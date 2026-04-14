package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRevokeAccessToken(t *testing.T) {
	store := newTestStore(t)
	h := NewOAuthHandler(store, OAuthConfig{Scope: "mcp:tools", ExternalURL: "https://x"})

	client, err := store.RegisterClient(map[string]any{
		"redirect_uris": []any{"https://c.example/cb"},
	})
	if err != nil {
		t.Fatal(err)
	}

	token := "access-to-revoke"
	now := time.Now().Unix()
	if err := store.StoreAccessToken(token, TokenData{
		ClientID: client.ClientID, Scope: "mcp:tools",
		ExpiresAt: now + 3600, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if !store.VerifyAccessToken(token, "mcp:tools") {
		t.Fatal("precondition: token should verify")
	}

	form := url.Values{
		"client_id":     {client.ClientID},
		"client_secret": {client.ClientSecret},
		"token":         {token},
	}
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Revoke(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if store.VerifyAccessToken(token, "mcp:tools") {
		t.Fatal("token should no longer verify after /revoke")
	}
}

func TestRevokeRejectsBadClientAuth(t *testing.T) {
	store := newTestStore(t)
	h := NewOAuthHandler(store, OAuthConfig{Scope: "mcp:tools", ExternalURL: "https://x"})

	client, err := store.RegisterClient(map[string]any{
		"redirect_uris": []any{"https://c.example/cb"},
	})
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"client_id":     {client.ClientID},
		"client_secret": {"WRONG"},
		"token":         {"anything"},
	}
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Revoke(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on bad client auth, got %d", rec.Code)
	}
}

func TestRevokeUnknownTokenReturns200(t *testing.T) {
	// RFC 7009 §2.2: unknown tokens must not be distinguishable from
	// successful revocations.
	store := newTestStore(t)
	h := NewOAuthHandler(store, OAuthConfig{Scope: "mcp:tools", ExternalURL: "https://x"})

	client, err := store.RegisterClient(map[string]any{
		"redirect_uris": []any{"https://c.example/cb"},
	})
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"client_id":     {client.ClientID},
		"client_secret": {client.ClientSecret},
		"token":         {"does-not-exist"},
	}
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Revoke(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for unknown token (RFC 7009), got %d", rec.Code)
	}
}

func TestRevokeCannotTouchOtherClientsTokens(t *testing.T) {
	store := newTestStore(t)
	h := NewOAuthHandler(store, OAuthConfig{Scope: "mcp:tools", ExternalURL: "https://x"})

	victim, err := store.RegisterClient(map[string]any{
		"redirect_uris": []any{"https://victim.example/cb"},
	})
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := store.RegisterClient(map[string]any{
		"redirect_uris": []any{"https://attacker.example/cb"},
	})
	if err != nil {
		t.Fatal(err)
	}

	victimToken := "victim-access-token"
	now := time.Now().Unix()
	if err := store.StoreAccessToken(victimToken, TokenData{
		ClientID: victim.ClientID, Scope: "mcp:tools",
		ExpiresAt: now + 3600, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Attacker authenticates as *themselves* and presents the victim's
	// token. Per the client-binding check, nothing should be deleted.
	form := url.Values{
		"client_id":     {attacker.ClientID},
		"client_secret": {attacker.ClientSecret},
		"token":         {victimToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Revoke(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (RFC requires indistinguishable response), got %d", rec.Code)
	}
	if !store.VerifyAccessToken(victimToken, "mcp:tools") {
		t.Fatal("SECURITY: attacker with valid client creds revoked another client's token")
	}
}
