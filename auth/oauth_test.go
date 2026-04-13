package auth

import (
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
	if got.ClientSecret != client.ClientSecret {
		t.Errorf("client_secret mismatch")
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

	data, err := store.ConsumeRefreshToken(refreshToken)
	if err != nil {
		t.Fatalf("ConsumeRefreshToken failed: %v", err)
	}
	if data.ClientID != "client-1" {
		t.Errorf("expected client-1, got %q", data.ClientID)
	}

	// Second consume should fail (rotation)
	_, err = store.ConsumeRefreshToken(refreshToken)
	if err == nil {
		t.Error("second ConsumeRefreshToken should fail (rotation)")
	}
}
