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
}

// NewRateLimiter creates a rate limiter that allows maxAttempts within
// windowSeconds before blocking.
func NewRateLimiter(maxAttempts int, windowSeconds int) *RateLimiter {
	return &RateLimiter{
		attempts:    make(map[string][]time.Time),
		maxAttempts: maxAttempts,
		window:      time.Duration(windowSeconds) * time.Second,
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
	rl.attempts[ip] = entries[:n]
}

// BearerMiddleware creates HTTP middleware that requires a valid Bearer token
// on specified paths. It supports dual-mode auth: a static bearer token
// (for CLI tools like Claude Code) and OAuth access tokens (for claude.ai).
//
// protectedPaths lists path prefixes that require authentication (e.g. "/mcp").
// All other paths pass through without auth — use your reverse proxy (e.g.
// Traefik with qa-gate) to protect those routes at the infrastructure layer.
func BearerMiddleware(bearerToken string, store *OAuthStore, protectedPaths ...string) func(http.Handler) http.Handler {
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

			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error":"Missing or invalid Authorization header"}`, http.StatusUnauthorized)
				return
			}

			token := authHeader[7:]

			// Static bearer token (CLI tools)
			if bearerToken != "" && SafeEqual(token, bearerToken) {
				next.ServeHTTP(w, r)
				return
			}

			// OAuth access token (claude.ai)
			if store.VerifyAccessToken(token) {
				next.ServeHTTP(w, r)
				return
			}

			http.Error(w, `{"error":"Invalid token"}`, http.StatusUnauthorized)
		})
	}
}
