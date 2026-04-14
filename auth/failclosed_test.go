package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestBearerMiddlewareFailsClosedOnStoreUnreachable verifies that when the
// OAuth token store is unreachable (here: closed DB handle, simulating a
// SQLite file that has become unavailable mid-request — disk full, perm
// error, etc.) the middleware denies access rather than falling through
// to the inner handler. This is the highest-leverage invariant in this
// library: every consumer service inherits this behavior.
func TestBearerMiddlewareFailsClosedOnStoreUnreachable(t *testing.T) {
	store := newTestStore(t)

	// Seed a valid OAuth access token so the path we exercise is
	// specifically "valid token presented, but store cannot be read."
	now := time.Now().Unix()
	token := "valid-oauth-token-xyz"
	if err := store.StoreAccessToken(token, TokenData{
		ClientID:  "c",
		Scope:     "mcp:tools",
		ExpiresAt: now + 3600,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	// Kill the store. All subsequent DB ops will error.
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	mw := BearerMiddleware("", nil, store, "mcp:tools", "/mcp")
	reached := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if reached {
		t.Fatal("SECURITY: inner handler was reached despite dead token store — fail-open bug")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on store failure, got %d", rec.Code)
	}
}
