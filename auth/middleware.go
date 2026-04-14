package auth

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter tracks attempts per IP with a sliding window.
type RateLimiter struct {
	mu          sync.Mutex
	attempts    map[string][]time.Time
	maxAttempts int
	window      time.Duration
	maxIPs      int // upper bound on tracked IPs to prevent memory exhaustion
}

// NewRateLimiter creates a rate limiter that allows maxAttempts within
// windowSeconds before blocking.
func NewRateLimiter(maxAttempts int, windowSeconds int) *RateLimiter {
	return &RateLimiter{
		attempts:    make(map[string][]time.Time),
		maxAttempts: maxAttempts,
		window:      time.Duration(windowSeconds) * time.Second,
		maxIPs:      100000,
	}
}

// IsRateLimited returns true if the IP has exceeded the limit.
func (rl *RateLimiter) IsRateLimited(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.prune(ip)
	return len(rl.attempts[ip]) >= rl.maxAttempts
}

// RecordFailure records an attempt for the given IP.
func (rl *RateLimiter) RecordFailure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.prune(ip)
	// Prevent unbounded memory growth from IP-spray attacks
	if len(rl.attempts) >= rl.maxIPs {
		return
	}
	rl.attempts[ip] = append(rl.attempts[ip], time.Now())
}

// Clear removes all attempts for the given IP (e.g. after successful auth).
func (rl *RateLimiter) Clear(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, ip)
}

func (rl *RateLimiter) prune(ip string) {
	cutoff := time.Now().Add(-rl.window)
	entries := rl.attempts[ip]
	n := 0
	for _, t := range entries {
		if t.After(cutoff) {
			entries[n] = t
			n++
		}
	}
	if n == 0 {
		delete(rl.attempts, ip)
	} else {
		rl.attempts[ip] = entries[:n]
	}
}

// parseBearer extracts the token from an RFC 6750-compliant Authorization
// header. The scheme match is case-insensitive; the token must be
// non-empty and must not itself contain whitespace — RFC 6750 §2.1
// mandates exactly one SP between the scheme and the token.
func parseBearer(header string) string {
	if len(header) < 8 {
		// Minimum is "Bearer X" — 7 bytes for "Bearer " + at least 1 char.
		return ""
	}
	if !strings.EqualFold(header[:6], "Bearer") || header[6] != ' ' {
		return ""
	}
	tok := header[7:]
	// Any embedded whitespace (including extra spaces, tabs, CR, LF) is
	// non-conforming and must not be silently normalized away: a second
	// space would turn "Bearer  X" into "X", which is not what the
	// client sent.
	if strings.ContainsAny(tok, " \t\r\n") {
		return ""
	}
	return tok
}

// writeUnauthorized emits an RFC 6750 §3-compliant 401 with the
// WWW-Authenticate challenge header that OAuth client libraries rely on
// to trigger re-authorization flows.
func writeUnauthorized(w http.ResponseWriter, description string) {
	challenge := `Bearer realm="mcp"`
	if description != "" {
		challenge += `, error="invalid_token", error_description="` + sanitizeChallenge(description) + `"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	// Keep the response body minimal; clients act on the header.
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}

// sanitizeChallenge strips characters that would break the quoted
// challenge description (the WWW-Authenticate grammar is unforgiving)
// and caps the result at 200 bytes so a future caller passing a
// user-controlled description cannot produce an unbounded header value.
func sanitizeChallenge(s string) string {
	out := strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 {
			return -1
		}
		return r
	}, s)
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

// BearerMiddleware creates HTTP middleware that requires a valid Bearer token
// on specified paths. It supports dual-mode auth: a static bearer token
// (for CLI tools like Claude Code) and OAuth access tokens (for claude.ai).
//
// For apps needing custom token validation (e.g. multiple tokens with
// different scopes), use WithTokenValidator instead of WithBearerToken.
//
// requiredScope is the OAuth scope that access tokens must carry (e.g.
// "mcp:tools"). Pass "" to skip scope enforcement.
//
// protectedPaths lists path prefixes that require authentication (e.g. "/mcp").
// All other paths pass through without auth — use your reverse proxy (e.g.
// Traefik with qa-gate) to protect those routes at the infrastructure layer.
func BearerMiddleware(bearerToken string, tokenValidator func(string) bool, store *OAuthStore, requiredScope string, protectedPaths ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// Check if this path requires bearer auth
			protected := false
			for _, prefix := range protectedPaths {
				if strings.HasPrefix(path, prefix) {
					protected = true
					break
				}
			}

			if !protected {
				next.ServeHTTP(w, r)
				return
			}

			token := parseBearer(r.Header.Get("Authorization"))
			if token == "" {
				writeUnauthorized(w, "missing or malformed bearer token")
				return
			}

			// On any successful auth path, stash a hash of the token on the
			// context so downstream handlers can identify this session without
			// ever touching the raw secret.
			passWithHash := func() {
				ctx := WithTokenHash(r.Context(), TokenHash(token))
				next.ServeHTTP(w, r.WithContext(ctx))
			}

			// Custom token validator (supports multi-token, scoped auth, etc.)
			if tokenValidator != nil && tokenValidator(token) {
				passWithHash()
				return
			}

			// Static bearer token (CLI tools)
			if bearerToken != "" && SafeEqual(token, bearerToken) {
				passWithHash()
				return
			}

			// OAuth access token (claude.ai)
			if store != nil && store.VerifyAccessToken(token, requiredScope) {
				passWithHash()
				return
			}

			writeUnauthorized(w, "invalid or expired bearer token")
		})
	}
}

// OriginAllowlistMiddleware rejects browser-initiated requests whose
// Origin is not on the provided allowlist. When allowedOrigins is empty
// the middleware is a pass-through — callers explicitly opt in to CORS
// enforcement, since MCP servers are often fronted by reverse proxies
// that already handle it.
//
// The check protects SSE endpoints against DNS-rebinding attacks: a
// malicious page that has caused a victim's browser to resolve the
// attacker's domain to 127.0.0.1 will still send the attacker's Origin
// header, which will not match the allowlist.
//
// For preflight (OPTIONS) requests with a permitted Origin, the
// middleware responds directly with the standard allow headers.
func OriginAllowlistMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	allow := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allow[o] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(allow) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			origin := r.Header.Get("Origin")
			if origin == "" {
				// Non-browser clients (curl, SDKs) omit Origin entirely.
				// No CSRF risk without a browser to drive the attack.
				next.ServeHTTP(w, r)
				return
			}
			if _, ok := allow[origin]; !ok {
				http.Error(w, `{"error":"origin not allowed"}`, http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
