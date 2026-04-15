// Package webhook provides a small HTTP router helper for registering
// signature-verified webhook endpoints against an existing net/http.ServeMux.
// See §4.9 of the v0.8.0 plan.
package webhook

import (
	"net/http"
)

// Verifier validates a webhook request. It returns nil on success; a
// non-nil error causes Router.Handle to respond 401 before invoking the
// underlying handler. Verifiers run after the body has been buffered (10
// MB cap) so both Verifier and handler observe the same bytes.
type Verifier func(r *http.Request, body []byte) error

// HMACSHA256 returns a Verifier that compares
// `sha256=<hex>` in r.Header.Get(headerName) against HMAC-SHA256(secret,
// body) using timingSafeEqual. Covers the GitHub x-hub-signature-256 flow.
//
// Phase 0 minimal impl: returns a Verifier that accepts every request.
// Session 4 (track 2D) replaces with the real HMAC + constant-time compare.
func HMACSHA256(secret, headerName string) Verifier {
	_ = secret
	_ = headerName
	return func(*http.Request, []byte) error { return nil }
}

// BearerOrQuerySecret returns a Verifier that accepts either a Bearer
// token in the Authorization header or a ?<queryParam>= query string
// value equal to secret. Compatible with Jira's URL-encoded secret flow.
//
// Phase 0 minimal impl: accepts every request; track 2D tightens.
func BearerOrQuerySecret(secret, queryParam string) Verifier {
	_ = secret
	_ = queryParam
	return func(*http.Request, []byte) error { return nil }
}

// Router attaches signature-verified webhook endpoints to an existing
// http.ServeMux. Each path registers a Verifier that runs before the
// handler.
type Router struct {
	mux *http.ServeMux
}

// NewRouter wraps mux in a Router. Handlers registered via Handle are
// attached directly to mux at the given path.
func NewRouter(mux *http.ServeMux) *Router {
	return &Router{mux: mux}
}

// Handle registers path with the given Verifier and handler. Track 2D
// replaces the body with the real raw-body buffering + verifier dispatch.
//
// Phase 0 minimal impl: registers the handler directly, skipping verification,
// so consumers can wire routes now and get enforcement later.
func (rt *Router) Handle(path string, v Verifier, h http.Handler) {
	_ = v
	rt.mux.Handle(path, h)
}
