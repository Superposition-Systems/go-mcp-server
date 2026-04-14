package auth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// --- SafeEqual tests ---

func TestSafeEqualIdentical(t *testing.T) {
	if !SafeEqual("hello", "hello") {
		t.Error("identical strings should be equal")
	}
}

func TestSafeEqualDifferent(t *testing.T) {
	if SafeEqual("hello", "world") {
		t.Error("different strings should not be equal")
	}
}

func TestSafeEqualDifferentLengths(t *testing.T) {
	if SafeEqual("short", "a much longer string") {
		t.Error("strings of different lengths should not be equal")
	}
}

func TestSafeEqualBothEmpty(t *testing.T) {
	if !SafeEqual("", "") {
		t.Error("two empty strings should be equal")
	}
}

func TestSafeEqualOneEmpty(t *testing.T) {
	if SafeEqual("", "notempty") {
		t.Error("empty vs non-empty should not be equal")
	}
	if SafeEqual("notempty", "") {
		t.Error("non-empty vs empty should not be equal")
	}
}

// --- OAuth store integration tests ---

func newOAuthTestStore(t *testing.T) *OAuthStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "oauth-test.db")
	store, err := NewOAuthStore(dbPath, "mcp:tools")
	if err != nil {
		t.Fatalf("failed to create OAuthStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestStoreRegisterAndGetClient(t *testing.T) {
	store := newOAuthTestStore(t)

	client, err := store.RegisterClient(map[string]any{
		"redirect_uris": []any{"http://localhost/callback"},
		"client_name":   "Test App",
	})
	if err != nil {
		t.Fatalf("RegisterClient failed: %v", err)
	}

	if client.ClientID == "" {
		t.Error("client_id should not be empty")
	}
	if client.ClientSecret == "" {
		t.Error("client_secret should not be empty")
	}
	if client.ClientName != "Test App" {
		t.Errorf("expected client_name 'Test App', got %q", client.ClientName)
	}

	// Get the client back
	got, err := store.GetClient(client.ClientID)
	if err != nil {
		t.Fatalf("GetClient failed: %v", err)
	}
	if got.ClientID != client.ClientID {
		t.Errorf("client_id mismatch: %q vs %q", got.ClientID, client.ClientID)
	}
	if got.ClientSecret != "" {
		t.Errorf("GetClient must not return the raw client_secret, got %q", got.ClientSecret)
	}
	// The secret is verified against its stored hash.
	if !store.VerifyClientSecret(client.ClientID, client.ClientSecret) {
		t.Errorf("VerifyClientSecret should accept the just-issued secret")
	}
	if store.VerifyClientSecret(client.ClientID, "wrong-secret") {
		t.Errorf("VerifyClientSecret must reject an incorrect secret")
	}
}

func TestStoreAuthCodeLifecycle(t *testing.T) {
	store := newOAuthTestStore(t)

	client, err := store.RegisterClient(map[string]any{
		"redirect_uris": []any{"http://localhost/callback"},
	})
	if err != nil {
		t.Fatalf("RegisterClient failed: %v", err)
	}

	code := "test-auth-code-123"
	err = store.StoreAuthCode(code, AuthCodeData{
		ClientID:  client.ClientID,
		CreatedAt: time.Now().Unix(),
		Scope:     "mcp:tools",
	})
	if err != nil {
		t.Fatalf("StoreAuthCode failed: %v", err)
	}

	// Consume the code
	data, err := store.ConsumeAuthCode(code)
	if err != nil {
		t.Fatalf("ConsumeAuthCode failed: %v", err)
	}
	if data.ClientID != client.ClientID {
		t.Errorf("client_id mismatch after consume")
	}

	// Second consume should fail (single-use)
	_, err = store.ConsumeAuthCode(code)
	if err == nil {
		t.Error("second ConsumeAuthCode should fail")
	}
}

func TestStoreTokenLifecycle(t *testing.T) {
	store := newOAuthTestStore(t)

	now := time.Now().Unix()
	accessToken := "access-token-xyz"
	err := store.StoreAccessToken(accessToken, TokenData{
		ClientID:  "client-1",
		Scope:     "mcp:tools",
		ExpiresAt: now + 3600,
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("StoreAccessToken failed: %v", err)
	}

	if !store.VerifyAccessToken(accessToken, "mcp:tools") {
		t.Error("valid access token should verify with matching scope")
	}

	if store.VerifyAccessToken(accessToken, "wrong:scope") {
		t.Error("access token with wrong scope should not verify")
	}

	if !store.VerifyAccessToken(accessToken, "") {
		t.Error("access token should verify when requiredScope is empty")
	}

	if store.VerifyAccessToken("nonexistent-token", "") {
		t.Error("nonexistent token should not verify")
	}

	// Refresh token
	refreshToken := "refresh-token-abc"
	err = store.StoreRefreshToken(refreshToken, TokenData{
		ClientID:  "client-1",
		Scope:     "mcp:tools",
		ExpiresAt: now + 86400,
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("StoreRefreshToken failed: %v", err)
	}

	// Client binding is enforced BEFORE deletion: a wrong client_id must
	// not burn the token.
	if _, err := store.ConsumeRefreshToken(refreshToken, "impostor"); err == nil {
		t.Error("ConsumeRefreshToken with wrong client_id should fail")
	}

	data, err := store.ConsumeRefreshToken(refreshToken, "client-1")
	if err != nil {
		t.Fatalf("ConsumeRefreshToken failed: %v", err)
	}
	if data.ClientID != "client-1" {
		t.Errorf("expected client-1, got %q", data.ClientID)
	}

	// Second consume should fail (rotation)
	_, err = store.ConsumeRefreshToken(refreshToken, "client-1")
	if err == nil {
		t.Error("second ConsumeRefreshToken should fail (rotation)")
	}
}

func TestRegLimiterReturns429AtHTTPLayer(t *testing.T) {
	store := newOAuthTestStore(t)
	h := NewOAuthHandler(store, OAuthConfig{Scope: "mcp:tools", ExternalURL: "https://x"})
	// Exhaust the registration limit for one IP (10/hr default).
	for i := 0; i < 11; i++ {
		req := httptest.NewRequest("POST", "/register", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		h.Register(rec, req)
		if i < 10 && rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d: unexpectedly rate-limited early (code %d)", i, rec.Code)
		}
	}
	// The 11th attempt must be 429.
	req := httptest.NewRequest("POST", "/register", nil)
	req.RemoteAddr = "10.0.0.1:5678"
	rec := httptest.NewRecorder()
	h.Register(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after exhausting RegLimiter, got %d", rec.Code)
	}
}

func TestAuthorizeLimiterReturns429AtHTTPLayer(t *testing.T) {
	store := newOAuthTestStore(t)
	h := NewOAuthHandler(store, OAuthConfig{Scope: "mcp:tools", ExternalURL: "https://x"})
	// AuthorizeLimiter allows 60/hr per IP. Send 61 malformed requests
	// from one IP; the limiter is incremented on every attempt, so the
	// 61st must return 429.
	for i := 0; i < 61; i++ {
		req := httptest.NewRequest("GET", "/authorize", nil)
		req.RemoteAddr = "10.0.0.2:1234"
		rec := httptest.NewRecorder()
		h.AuthorizeGET(rec, req)
	}
	req := httptest.NewRequest("GET", "/authorize", nil)
	req.RemoteAddr = "10.0.0.2:5678"
	rec := httptest.NewRecorder()
	h.AuthorizeGET(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after exhausting AuthorizeLimiter, got %d", rec.Code)
	}
}

func TestClientIPRejectsInvalidXForwardedFor(t *testing.T) {
	store := newOAuthTestStore(t)
	h := NewOAuthHandler(store, OAuthConfig{
		Scope:             "mcp:tools",
		ExternalURL:       "https://x",
		TrustedProxyCIDRs: []string{"10.0.0.0/8"},
	})

	// Garbage XFF from a trusted proxy falls back to RemoteAddr.
	req := httptest.NewRequest("GET", "/authorize", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	if got := h.clientIP(req); got != "10.0.0.1" {
		t.Errorf("invalid XFF should fall back to RemoteAddr host, got %q", got)
	}

	// Valid XFF with port is canonicalized.
	req.Header.Set("X-Forwarded-For", "203.0.113.7:9999")
	if got := h.clientIP(req); got != "203.0.113.7" {
		t.Errorf("IP:port XFF should yield bare IP, got %q", got)
	}

	// Left-most of a multi-entry XFF wins (if parseable).
	req.Header.Set("X-Forwarded-For", "garbage, 203.0.113.8")
	if got := h.clientIP(req); got != "203.0.113.8" {
		t.Errorf("multi-entry XFF should skip unparseable entries, got %q", got)
	}

	// Untrusted proxy: XFF is ignored entirely.
	req.RemoteAddr = "198.51.100.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	if got := h.clientIP(req); got != "198.51.100.1" {
		t.Errorf("untrusted proxy should ignore XFF, got %q", got)
	}
}

func TestDiscoveryRefusesWithoutExternalURLForNonLocalhost(t *testing.T) {
	store := newOAuthTestStore(t)
	h := NewOAuthHandler(store, OAuthConfig{Scope: "mcp:tools"})

	// Non-localhost Host, no ExternalURL -> must 500.
	req := httptest.NewRequest("GET", "http://prod.example.com/.well-known/oauth-authorization-server", nil)
	req.Host = "prod.example.com"
	rec := httptest.NewRecorder()
	h.Discovery(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("non-localhost without ExternalURL: expected 500, got %d", rec.Code)
	}

	// Localhost Host, no ExternalURL -> OK fallback.
	req = httptest.NewRequest("GET", "http://localhost:8080/.well-known/oauth-authorization-server", nil)
	req.Host = "localhost:8080"
	rec = httptest.NewRecorder()
	h.Discovery(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("localhost without ExternalURL: expected 200, got %d", rec.Code)
	}

	// Non-localhost WITH ExternalURL -> OK.
	h2 := NewOAuthHandler(store, OAuthConfig{Scope: "mcp:tools", ExternalURL: "https://prod.example.com"})
	req = httptest.NewRequest("GET", "http://prod.example.com/.well-known/oauth-authorization-server", nil)
	req.Host = "prod.example.com"
	rec = httptest.NewRecorder()
	h2.Discovery(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("non-localhost with ExternalURL: expected 200, got %d", rec.Code)
	}
}

func TestValidateRedirectURIRejectsDangerousForms(t *testing.T) {
	// These should all fail.
	bad := []string{
		"https://example.com/?",             // bare trailing ?
		"https://example.com/#frag",         // fragment
		"https://u:p@example.com/callback",  // userinfo
		"https://example.com/?foo=bar",      // query string
		"ftp://example.com/callback",        // wrong scheme
		"http://example.com/callback",       // http non-localhost
		"not-a-url",
	}
	for _, uri := range bad {
		if err := validateRedirectURI(uri); err == nil {
			t.Errorf("validateRedirectURI(%q) should have failed", uri)
		}
	}
	// These should pass.
	good := []string{
		"https://example.com/callback",
		"http://localhost:8080/callback",
		"http://127.0.0.1/cb",
	}
	for _, uri := range good {
		if err := validateRedirectURI(uri); err != nil {
			t.Errorf("validateRedirectURI(%q) should have succeeded: %v", uri, err)
		}
	}
}

func TestScopeContains(t *testing.T) {
	cases := []struct {
		granted, required string
		want              bool
	}{
		{"", "", true},
		{"mcp:tools", "", true},
		{"mcp:tools", "mcp:tools", true},
		{"mcp:tools mcp:read", "mcp:tools", true},
		{"mcp:tools mcp:read", "mcp:read mcp:tools", true},
		{"mcp:tools", "mcp:read", false},
		{"", "mcp:tools", false},
	}
	for _, c := range cases {
		if got := ScopeContains(c.granted, c.required); got != c.want {
			t.Errorf("ScopeContains(%q,%q)=%v want %v", c.granted, c.required, got, c.want)
		}
	}
}
