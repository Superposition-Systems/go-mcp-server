// Package webhook provides a small HTTP router helper for registering
// signature-verified webhook endpoints against an existing net/http.ServeMux.
// See §4.9 of the v0.8.0 plan.
package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxBodyBytes bounds the size of a buffered webhook payload. Verifiers
// must see the full body (HMAC over a truncated body would produce a
// valid-looking signature), so requests larger than this are refused
// with 413 before the verifier runs.
const maxBodyBytes = 10 * 1024 * 1024 // 10 MB

// Verifier validates a webhook request. It returns nil on success; a
// non-nil error causes Router.Handle to respond 401 before invoking the
// underlying handler. Verifiers run after the body has been buffered (10
// MB cap) so both Verifier and handler observe the same bytes.
type Verifier func(r *http.Request, body []byte) error

// HMACSHA256 returns a Verifier that compares the `sha256=<hex>` value in
// r.Header.Get(headerName) against HMAC-SHA256(secret, body) using a
// constant-time comparison. It mirrors the GitHub x-hub-signature-256
// flow used by lib/pipeline/webhook-dispatch.js.
//
// The scheme prefix match is case-insensitive (`sha256=` or `SHA256=`).
// Empty, missing, or malformed headers return an error. An empty secret
// yields a Verifier that always errors (keys must be non-empty to be
// meaningful).
func HMACSHA256(secret, headerName string) Verifier {
	if secret == "" {
		return func(*http.Request, []byte) error {
			return errors.New("webhook: HMACSHA256 secret is empty")
		}
	}
	key := []byte(secret)
	return func(r *http.Request, body []byte) error {
		got := r.Header.Get(headerName)
		if got == "" {
			return errors.New("webhook: missing signature header")
		}
		// Case-insensitive "sha256=" prefix check.
		const prefix = "sha256="
		if len(got) < len(prefix) || !strings.EqualFold(got[:len(prefix)], prefix) {
			return errors.New("webhook: signature header missing sha256= prefix")
		}
		sigHex := got[len(prefix):]
		sig, err := hex.DecodeString(sigHex)
		if err != nil {
			return errors.New("webhook: signature is not valid hex")
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(body)
		expected := mac.Sum(nil)
		if !hmac.Equal(sig, expected) {
			return errors.New("webhook: signature mismatch")
		}
		return nil
	}
}

// BearerOrQuerySecret returns a Verifier that accepts either a Bearer
// token in the Authorization header or a ?<queryParam>=<value> query
// string value equal to secret. Comparisons are constant-time.
//
// Some Jira deployments double-encode the query-string secret; if the
// first compare on the raw query value fails, a single
// url.QueryUnescape is applied and the compare re-run. An empty secret
// yields a Verifier that always errors.
func BearerOrQuerySecret(secret, queryParam string) Verifier {
	if secret == "" {
		return func(*http.Request, []byte) error {
			return errors.New("webhook: BearerOrQuerySecret secret is empty")
		}
	}
	secretBytes := []byte(secret)
	return func(r *http.Request, _ []byte) error {
		// Authorization: Bearer <secret>
		if auth := r.Header.Get("Authorization"); auth != "" {
			const bearer = "bearer "
			if len(auth) > len(bearer) && strings.EqualFold(auth[:len(bearer)], bearer) {
				tok := auth[len(bearer):]
				if subtle.ConstantTimeCompare([]byte(tok), secretBytes) == 1 {
					return nil
				}
			}
		}
		// Raw query value (pre-decoded by net/url) — try direct, then a
		// single extra QueryUnescape pass to tolerate Jira double-encoding.
		if queryParam != "" {
			if vals, ok := r.URL.Query()[queryParam]; ok {
				for _, v := range vals {
					if subtle.ConstantTimeCompare([]byte(v), secretBytes) == 1 {
						return nil
					}
					if dec, err := url.QueryUnescape(v); err == nil && dec != v {
						if subtle.ConstantTimeCompare([]byte(dec), secretBytes) == 1 {
							return nil
						}
					}
				}
			}
		}
		return errors.New("webhook: bearer token or query secret missing or mismatched")
	}
}

// Router attaches signature-verified webhook endpoints to an existing
// http.ServeMux. Each path registers a Verifier that runs before the
// handler. The Router is stateless beyond its mux reference; instances
// are safe for concurrent use once all Handle calls have been made
// (Handle itself delegates to http.ServeMux, which is not safe to call
// concurrently with ServeHTTP — follow the standard library contract).
type Router struct {
	mux *http.ServeMux
}

// NewRouter wraps mux in a Router. Handlers registered via Handle are
// attached directly to mux at the given path.
func NewRouter(mux *http.ServeMux) *Router {
	return &Router{mux: mux}
}

// Handle registers path with the given Verifier and handler. The wrapper:
//   - reads up to 10 MB of request body; larger bodies yield 413 without
//     invoking the verifier or handler,
//   - runs the verifier against the buffered bytes; a non-nil error yields
//     401 "unauthorized" without invoking the handler,
//   - re-attaches the buffered bytes to r.Body (via io.NopCloser) so the
//     handler sees the identical sequence of bytes the verifier saw.
//
// If v is nil, verification is skipped — handy for tests and for paths
// that don't need per-request authentication.
func (rt *Router) Handle(path string, v Verifier, h http.Handler) {
	wrapper := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, tooLarge, err := readBody(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if tooLarge {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		if v != nil {
			if verr := v(r, body); verr != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		h.ServeHTTP(w, r)
	})
	rt.mux.Handle(path, wrapper)
}

// readBody reads up to maxBodyBytes+1 bytes from src. If more than
// maxBodyBytes are available, tooLarge is true and the returned body
// slice is the prefix (not used by the caller beyond the size decision).
// The extra byte is the standard "read one past the cap to detect
// overflow" pattern.
func readBody(src io.ReadCloser) (body []byte, tooLarge bool, err error) {
	defer src.Close()
	limited := io.LimitReader(src, maxBodyBytes+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, err
	}
	if len(buf) > maxBodyBytes {
		return buf[:maxBodyBytes], true, nil
	}
	return buf, false, nil
}
