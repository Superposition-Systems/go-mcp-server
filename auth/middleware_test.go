package auth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// --- RateLimiter tests ---

func TestRateLimiterEnforcesLimit(t *testing.T) {
	rl := NewRateLimiter(3, 60)
	ip := "192.168.1.1"

	for i := 0; i < 3; i++ {
		if rl.IsRateLimited(ip) {
			t.Fatalf("should not be rate-limited after %d attempts", i)
		}
		rl.RecordFailure(ip)
	}

	if !rl.IsRateLimited(ip) {
		t.Error("should be rate-limited after 3 attempts")
	}
}

func TestRateLimiterDifferentIPs(t *testing.T) {
	rl := NewRateLimiter(2, 60)

	rl.RecordFailure("ip-a")
	rl.RecordFailure("ip-a")

	if !rl.IsRateLimited("ip-a") {
		t.Error("ip-a should be limited")
	}
	if rl.IsRateLimited("ip-b") {
		t.Error("ip-b should not be limited")
	}
}

func TestRateLimiterWindowExpiry(t *testing.T) {
	// Use a 1-second window so we can test expiry quickly
	rl := NewRateLimiter(2, 1)
	ip := "10.0.0.1"

	rl.RecordFailure(ip)
	rl.RecordFailure(ip)

	if !rl.IsRateLimited(ip) {
		t.Error("should be rate-limited")
	}

	// Wait for the window to expire
	time.Sleep(1100 * time.Millisecond)

	if rl.IsRateLimited(ip) {
		t.Error("should no longer be rate-limited after window expiry")
	}
}

func TestRateLimiterClear(t *testing.T) {
	rl := NewRateLimiter(2, 60)
	ip := "10.0.0.2"

	rl.RecordFailure(ip)
	rl.RecordFailure(ip)

	if !rl.IsRateLimited(ip) {
		t.Error("should be rate-limited")
	}

	rl.Clear(ip)

	if rl.IsRateLimited(ip) {
		t.Error("should not be rate-limited after Clear")
	}
}

// --- BearerMiddleware tests ---

func newTestStore(t *testing.T) *OAuthStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewOAuthStore(dbPath, "mcp:tools")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestBearerMiddlewareUnprotectedPassThrough(t *testing.T) {
	store := newTestStore(t)
	middleware := BearerMiddleware("secret-token", nil, store, "", "/mcp")

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	handler := middleware(inner)

	// Request to unprotected path (no auth needed)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for unprotected path, got %d", rec.Code)
	}
}

func TestBearerMiddlewareProtectedRequiresToken(t *testing.T) {
	store := newTestStore(t)
	middleware := BearerMiddleware("secret-token", nil, store, "", "/mcp")

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware(inner)

	// No Authorization header
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rec.Code)
	}
}

func TestBearerMiddlewareStaticToken(t *testing.T) {
	store := newTestStore(t)
	middleware := BearerMiddleware("my-secret", nil, store, "", "/mcp")

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authorized"))
	})

	handler := middleware(inner)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer my-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with valid static token, got %d", rec.Code)
	}
}

func TestBearerMiddlewareInvalidToken(t *testing.T) {
	store := newTestStore(t)
	middleware := BearerMiddleware("my-secret", nil, store, "", "/mcp")

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware(inner)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with invalid token, got %d", rec.Code)
	}
}

func TestBearerMiddlewareOAuthToken(t *testing.T) {
	store := newTestStore(t)
	middleware := BearerMiddleware("static-token", nil, store, "mcp:tools", "/mcp")

	// Store an OAuth access token
	now := time.Now().Unix()
	token := "oauth-access-token-123"
	err := store.StoreAccessToken(token, TokenData{
		ClientID:  "client-1",
		Scope:     "mcp:tools",
		ExpiresAt: now + 3600,
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("failed to store access token: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("oauth-ok"))
	})

	handler := middleware(inner)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with valid OAuth token, got %d", rec.Code)
	}
}

func TestBearerMiddlewareMultipleProtectedPaths(t *testing.T) {
	store := newTestStore(t)
	middleware := BearerMiddleware("tok", nil, store, "", "/mcp", "/api")

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware(inner)

	// /api/something should be protected
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for /api/data without token, got %d", rec.Code)
	}

	// /register should pass through
	req = httptest.NewRequest(http.MethodPost, "/register", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for unprotected /register, got %d", rec.Code)
	}
}
