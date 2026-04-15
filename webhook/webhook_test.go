package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// ghSig builds a GitHub-style `sha256=<hex>` signature over body.
func ghSig(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// newServer wires a single path through a Router and returns the test
// server plus a pointer to a "handler was called" flag.
func newServer(t *testing.T, path string, v Verifier, h http.Handler) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	mux := http.NewServeMux()
	rt := NewRouter(mux)
	var called atomic.Bool
	if h == nil {
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called.Store(true)
			w.WriteHeader(http.StatusOK)
			_, _ = io.Copy(io.Discard, r.Body)
		})
	} else {
		orig := h
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called.Store(true)
			orig.ServeHTTP(w, r)
		})
	}
	rt.Handle(path, v, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &called
}

func TestHMACSHA256_HappyPath(t *testing.T) {
	body := []byte(`{"action":"opened"}`)
	const header = "X-Hub-Signature-256"
	srv, called := newServer(t, "/gh", HMACSHA256("topsecret", header), nil)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/gh", bytes.NewReader(body))
	req.Header.Set(header, ghSig("topsecret", body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if !called.Load() {
		t.Fatal("handler not invoked")
	}
}

func TestHMACSHA256_BadPaths(t *testing.T) {
	body := []byte(`{"action":"opened"}`)
	const header = "X-Hub-Signature-256"

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"missing-header", "", http.StatusUnauthorized},
		{"wrong-scheme", "md5=" + hex.EncodeToString([]byte("nope")), http.StatusUnauthorized},
		{"not-hex", "sha256=zzzz", http.StatusUnauthorized},
		{"bad-signature", "sha256=" + strings.Repeat("00", 32), http.StatusUnauthorized},
		{"short-prefix", "sha256", http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, called := newServer(t, "/gh", HMACSHA256("topsecret", header), nil)
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/gh", bytes.NewReader(body))
			if tc.header != "" {
				req.Header.Set(header, tc.header)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("want %d, got %d", tc.want, resp.StatusCode)
			}
			if called.Load() {
				t.Fatal("handler should not have been invoked")
			}
		})
	}
}

func TestHMACSHA256_CaseInsensitivePrefix(t *testing.T) {
	body := []byte(`ok`)
	const header = "X-Hub-Signature-256"
	srv, called := newServer(t, "/gh", HMACSHA256("k", header), nil)

	// Build a signature then re-case the prefix.
	sig := ghSig("k", body)
	uppered := "SHA256=" + strings.TrimPrefix(sig, "sha256=")

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/gh", bytes.NewReader(body))
	req.Header.Set(header, uppered)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if !called.Load() {
		t.Fatal("handler not invoked")
	}
}

// TestHMACSHA256_RawBodyBytes is the §7 "production bug" edge case:
// the signature is computed over the exact bytes sent, including
// whitespace. A naive server that re-serialises via encoding/json and
// then signs that will fail this test.
func TestHMACSHA256_RawBodyBytes(t *testing.T) {
	// Valid JSON with extra whitespace embedded.
	body := []byte("{  \"action\"  :  \"opened\"  ,  \"n\"  :  1  }\n")
	const header = "X-Hub-Signature-256"
	srv, called := newServer(t, "/gh", HMACSHA256("k", header), nil)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/gh", bytes.NewReader(body))
	req.Header.Set(header, ghSig("k", body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if !called.Load() {
		t.Fatal("handler not invoked")
	}
}

func TestHMACSHA256_EmptySecret(t *testing.T) {
	// Empty secret must refuse at construction time (verifier always errors).
	v := HMACSHA256("", "X-Sig")
	req, _ := http.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Sig", "sha256=deadbeef")
	if err := v(req, []byte("x")); err == nil {
		t.Fatal("want error for empty secret")
	}
}

func TestBearerOrQuerySecret(t *testing.T) {
	const secret = "s3cr3t"
	const qp = "secret"

	// Double-encoded value: "s3cr3t" → "s3cr3t" (no special chars); use
	// a value with an encodable character so the double-encode test is
	// meaningful.
	const secretEnc = "needs encoding/+="
	once := url.QueryEscape(secretEnc)    // single-encoded (wire-ready)
	twice := url.QueryEscape(once)        // double-encoded (Jira quirk)

	cases := []struct {
		name   string
		setReq func(r *http.Request)
		sec    string
		want   int
	}{
		{
			name:   "bearer-ok",
			setReq: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+secret) },
			sec:    secret,
			want:   http.StatusOK,
		},
		{
			name:   "bearer-case-insensitive",
			setReq: func(r *http.Request) { r.Header.Set("Authorization", "bearer "+secret) },
			sec:    secret,
			want:   http.StatusOK,
		},
		{
			name:   "query-ok",
			setReq: func(r *http.Request) { r.URL.RawQuery = qp + "=" + url.QueryEscape(secret) },
			sec:    secret,
			want:   http.StatusOK,
		},
		{
			name:   "query-double-encoded",
			setReq: func(r *http.Request) { r.URL.RawQuery = qp + "=" + twice },
			sec:    secretEnc,
			want:   http.StatusOK,
		},
		{
			name:   "wrong-bearer",
			setReq: func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") },
			sec:    secret,
			want:   http.StatusUnauthorized,
		},
		{
			name:   "wrong-query",
			setReq: func(r *http.Request) { r.URL.RawQuery = qp + "=wrong" },
			sec:    secret,
			want:   http.StatusUnauthorized,
		},
		{
			name:   "nothing",
			setReq: func(r *http.Request) {},
			sec:    secret,
			want:   http.StatusUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, called := newServer(t, "/w", BearerOrQuerySecret(tc.sec, qp), nil)
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/w", bytes.NewReader([]byte("{}")))
			tc.setReq(req)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("want %d, got %d", tc.want, resp.StatusCode)
			}
			if tc.want == http.StatusOK && !called.Load() {
				t.Fatal("handler not invoked")
			}
			if tc.want != http.StatusOK && called.Load() {
				t.Fatal("handler should not have been invoked")
			}
		})
	}
}

func TestBearerOrQuerySecret_EmptySecret(t *testing.T) {
	v := BearerOrQuerySecret("", "secret")
	req, _ := http.NewRequest(http.MethodPost, "/?secret=x", nil)
	if err := v(req, nil); err == nil {
		t.Fatal("want error for empty secret")
	}
	// Also: does not panic.
}

func TestBodySizeLimit(t *testing.T) {
	var verifierCalled atomic.Bool
	v := func(r *http.Request, body []byte) error {
		verifierCalled.Store(true)
		return nil
	}
	srv, called := newServer(t, "/big", v, nil)

	// 10 MB + 1 byte.
	big := make([]byte, maxBodyBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/big", bytes.NewReader(big))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", resp.StatusCode)
	}
	if verifierCalled.Load() {
		t.Fatal("verifier should not have been invoked")
	}
	if called.Load() {
		t.Fatal("handler should not have been invoked")
	}
}

func TestBodySizeLimit_AtCap(t *testing.T) {
	// Exactly 10 MB must pass.
	srv, called := newServer(t, "/ok", nil, nil)
	body := make([]byte, maxBodyBytes)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/ok", bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if !called.Load() {
		t.Fatal("handler not invoked")
	}
}

// TestBytesEqual asserts that the bytes the verifier sees and the bytes
// the handler reads from r.Body are byte-identical. The verifier stashes
// its view in a closure and the handler drains r.Body into a second
// buffer; the test compares both.
func TestBytesEqual(t *testing.T) {
	body := []byte("raw\x00bytes\n{\"n\":1}   ")
	var seenByVerifier []byte
	v := func(r *http.Request, b []byte) error {
		seenByVerifier = append(seenByVerifier, b...)
		return nil
	}
	var seenByHandler []byte
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		seenByHandler = b
		w.WriteHeader(http.StatusOK)
	})
	srv, _ := newServer(t, "/eq", v, h)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/eq", bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if !bytes.Equal(seenByVerifier, body) {
		t.Fatalf("verifier got %q, want %q", seenByVerifier, body)
	}
	if !bytes.Equal(seenByHandler, body) {
		t.Fatalf("handler got %q, want %q", seenByHandler, body)
	}
}

func TestNilVerifier(t *testing.T) {
	srv, called := newServer(t, "/nop", nil, nil)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/nop", bytes.NewReader([]byte("x")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if !called.Load() {
		t.Fatal("handler not invoked")
	}
}

func TestConcurrentSafety(t *testing.T) {
	body := []byte(`{"event":"push"}`)
	const header = "X-Hub-Signature-256"
	srv, _ := newServer(t, "/gh", HMACSHA256("k", header), nil)

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/gh", bytes.NewReader(body))
			req.Header.Set(header, ghSig("k", body))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errs <- errFromStatus(resp.StatusCode)
				return
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

type statusErr int

func (s statusErr) Error() string { return http.StatusText(int(s)) }

func errFromStatus(code int) error { return statusErr(code) }
