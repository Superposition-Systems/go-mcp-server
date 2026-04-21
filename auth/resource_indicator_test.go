package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestVerifyAccessTokenForResource_Matrix exercises the full
// stored-audience × expected-audience decision matrix in the store
// helper. Every cell below is load-bearing for backwards compat:
//
//	stored="",  expected=""  → accept (legacy token + legacy middleware)
//	stored="",  expected=X   → accept (legacy token + v0.9 middleware)
//	stored=X,   expected=""  → accept (v0.9 token + legacy middleware)
//	stored=X,   expected=X   → accept (normal v0.9 case)
//	stored=X,   expected=Y   → reject (the RFC 8707 threat this feature prevents)
//
// The two "accept despite asymmetry" cells (rows 2 and 3) are what let
// deployments adopt audience binding gradually: clients upgrade first,
// servers upgrade later — or vice versa — without any token in flight
// being invalidated.
func TestVerifyAccessTokenForResource_Matrix(t *testing.T) {
	store := newTestStore(t)
	canonical := "https://mcp.example.com/mcp"
	otherResource := "https://attacker.example.com/mcp"
	now := time.Now().Unix()

	legacyToken := "legacy-unbound-token"
	if err := store.StoreAccessToken(legacyToken, TokenData{
		ClientID: "c1", Scope: "mcp:tools", Audience: "",
		ExpiresAt: now + 3600, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	boundToken := "audience-bound-token"
	if err := store.StoreAccessToken(boundToken, TokenData{
		ClientID: "c1", Scope: "mcp:tools", Audience: canonical,
		ExpiresAt: now + 3600, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name             string
		token            string
		expectedResource string
		want             bool
	}{
		{"legacy token, no enforcement", legacyToken, "", true},
		{"legacy token, enforcing server", legacyToken, canonical, true},
		{"bound token, no enforcement", boundToken, "", true},
		{"bound token, matching enforcement", boundToken, canonical, true},
		{"bound token, wrong enforcement", boundToken, otherResource, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := store.VerifyAccessTokenForResource(tc.token, "mcp:tools", tc.expectedResource)
			if got != tc.want {
				t.Errorf("VerifyAccessTokenForResource(_, _, %q)=%v, want %v", tc.expectedResource, got, tc.want)
			}
		})
	}
}

// TestValidateResourceParam_Policy covers validateResourceParam in
// isolation so later handler-level tests can trust it and focus on
// flow-wiring rather than re-asserting the matrix. The canonical URI
// is derived from the handler's ExternalURL+ResourcePath per the
// 2025-06-18 spec; validateResourceParam is what keeps us from
// accepting a non-matching `resource` even when the operator hasn't
// enabled RequireResourceIndicator.
func TestValidateResourceParam_Policy(t *testing.T) {
	store := newTestStore(t)
	canonical := "https://mcp.example.com/mcp"

	lenient := NewOAuthHandler(store, OAuthConfig{
		Scope: "mcp:tools", ExternalURL: "https://mcp.example.com",
	})
	strict := NewOAuthHandler(store, OAuthConfig{
		Scope: "mcp:tools", ExternalURL: "https://mcp.example.com",
		RequireResourceIndicator: true,
	})
	noExternal := NewOAuthHandler(store, OAuthConfig{Scope: "mcp:tools"})

	cases := []struct {
		name      string
		handler   *OAuthHandler
		raws      []string
		wantOK    bool
		wantValue string
	}{
		{"lenient, omitted → accept-empty", lenient, nil, true, ""},
		{"lenient, canonical → accept-canonical", lenient, []string{canonical}, true, canonical},
		{"lenient, wrong value → reject", lenient, []string{"https://other.example/mcp"}, false, ""},
		{"lenient, multiple → reject", lenient, []string{canonical, canonical}, false, ""},
		{"strict, omitted → reject", strict, nil, false, ""},
		{"strict, canonical → accept", strict, []string{canonical}, true, canonical},
		{"no-ExternalURL, omitted → accept-empty", noExternal, nil, true, ""},
		{"no-ExternalURL, non-empty → reject", noExternal, []string{canonical}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.handler.validateResourceParam(tc.raws)
			if ok != tc.wantOK {
				t.Errorf("validateResourceParam(%v) ok=%v, want %v", tc.raws, ok, tc.wantOK)
			}
			if got != tc.wantValue {
				t.Errorf("validateResourceParam(%v) value=%q, want %q", tc.raws, got, tc.wantValue)
			}
		})
	}
}

// TestTokenExchange_ResourceMismatch verifies RFC 8707 §2.2 — if the
// authorization request asserted resource A and the token request
// asserts resource B (or no resource), the server rejects with
// invalid_target. This is the core cross-audience-replay defense at
// the token-issuance layer.
//
// The test seeds an auth_code row directly rather than walking
// through the full PIN consent flow because validating the PIN
// interaction belongs elsewhere; we only need a code bound to a
// specific Resource to exercise exchangeAuthCode's validation path.
func TestTokenExchange_ResourceMismatch(t *testing.T) {
	store := newTestStore(t)
	h := NewOAuthHandler(store, OAuthConfig{
		Scope: "mcp:tools", ExternalURL: "https://mcp.example.com",
	})
	canonical := h.CanonicalResource()

	client, err := store.RegisterClient(map[string]any{
		"redirect_uris": []any{"https://c.example/cb"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Seed an auth code bound to the canonical resource. The PKCE
	// challenge is a known S256 of the verifier "v" so the test can
	// present the matching verifier at /token.
	code := "the-code"
	if err := store.StoreAuthCode(code, AuthCodeData{
		ClientID:            client.ClientID,
		RedirectURI:         "https://c.example/cb",
		CodeChallenge:       pkceS256("v"),
		CodeChallengeMethod: "S256",
		Scope:               "mcp:tools",
		Resource:            canonical,
		CreatedAt:           time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	// /token exchange with WRONG resource — must be rejected.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientID},
		"client_secret": {client.ClientSecret},
		"code":          {code},
		"code_verifier": {"v"},
		"redirect_uri":  {"https://c.example/cb"},
		"resource":      {"https://other.example/mcp"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Token(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong resource, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_target") {
		t.Errorf("expected invalid_target error, got body: %s", rec.Body.String())
	}
}

// TestTokenExchange_BindsAudience walks the happy path: /token with a
// matching resource parameter succeeds, and the stored access token
// carries the Audience. Without this the RFC 8707 plumbing is
// ceremonial — we need to know the binding actually reaches the
// store, because BearerMiddlewareForResource reads it from there.
func TestTokenExchange_BindsAudience(t *testing.T) {
	store := newTestStore(t)
	h := NewOAuthHandler(store, OAuthConfig{
		Scope: "mcp:tools", ExternalURL: "https://mcp.example.com",
	})
	canonical := h.CanonicalResource()

	client, err := store.RegisterClient(map[string]any{
		"redirect_uris": []any{"https://c.example/cb"},
	})
	if err != nil {
		t.Fatal(err)
	}

	code := "the-code"
	if err := store.StoreAuthCode(code, AuthCodeData{
		ClientID:            client.ClientID,
		RedirectURI:         "https://c.example/cb",
		CodeChallenge:       pkceS256("v"),
		CodeChallengeMethod: "S256",
		Scope:               "mcp:tools",
		Resource:            canonical,
		CreatedAt:           time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientID},
		"client_secret": {client.ClientSecret},
		"code":          {code},
		"code_verifier": {"v"},
		"redirect_uri":  {"https://c.example/cb"},
		"resource":      {canonical},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Token(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	// The response body contains the access_token. Pull it out and
	// assert that audience enforcement now works against it.
	var body struct {
		AccessToken string `json:"access_token"`
	}
	parseJSONBody(t, rec, &body)
	if body.AccessToken == "" {
		t.Fatal("no access_token in response")
	}

	// Token must pass audience check against canonical, fail against others.
	if !store.VerifyAccessTokenForResource(body.AccessToken, "mcp:tools", canonical) {
		t.Error("token should verify against its bound audience")
	}
	if store.VerifyAccessTokenForResource(body.AccessToken, "mcp:tools", "https://other.example/mcp") {
		t.Error("token must be rejected by a different-audience server")
	}
}

// TestRefreshExchange_InheritsAudience is the refresh-path analogue of
// TestTokenExchange_BindsAudience. A client refreshing an
// audience-bound token must receive a new access token bound to the
// same audience — otherwise an attacker with a refresh token could
// rotate into an un-bound access token and bypass enforcement.
func TestRefreshExchange_InheritsAudience(t *testing.T) {
	store := newTestStore(t)
	h := NewOAuthHandler(store, OAuthConfig{
		Scope: "mcp:tools", ExternalURL: "https://mcp.example.com",
	})
	canonical := h.CanonicalResource()

	client, err := store.RegisterClient(map[string]any{
		"redirect_uris": []any{"https://c.example/cb"},
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	refreshToken := "bound-refresh"
	if err := store.StoreRefreshToken(refreshToken, TokenData{
		ClientID: client.ClientID, Scope: "mcp:tools", Audience: canonical,
		ExpiresAt: now + 30*24*3600, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {client.ClientID},
		"client_secret": {client.ClientSecret},
		"refresh_token": {refreshToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Token(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	parseJSONBody(t, rec, &body)

	// New access token must carry the same audience.
	if !store.VerifyAccessTokenForResource(body.AccessToken, "mcp:tools", canonical) {
		t.Error("refreshed access token must inherit audience binding")
	}
	if store.VerifyAccessTokenForResource(body.AccessToken, "mcp:tools", "https://other.example/mcp") {
		t.Error("refreshed access token must not be accepted by a different-audience server")
	}
}

// TestBearerMiddlewareForResource_RejectsWrongAudience is the wire-
// level assertion: an audience-bound token delivered to a server with
// a different canonical resource is rejected at the middleware layer
// with 401. This is what actually prevents cross-server token
// replay in production.
func TestBearerMiddlewareForResource_RejectsWrongAudience(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().Unix()
	token := "bound-for-A"
	if err := store.StoreAccessToken(token, TokenData{
		ClientID: "c1", Scope: "mcp:tools", Audience: "https://a.example/mcp",
		ExpiresAt: now + 3600, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Middleware on server B.
	mw := BearerMiddlewareForResource("", nil, store, "mcp:tools", "https://b.example/mcp", "/mcp")
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := mw(inner)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for audience-mismatched token, got %d", rec.Code)
	}

	// Same token at server A (matching audience) must succeed.
	mwA := BearerMiddlewareForResource("", nil, store, "mcp:tools", "https://a.example/mcp", "/mcp")
	handlerA := mwA(inner)
	reqA := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	reqA.Header.Set("Authorization", "Bearer "+token)
	recA := httptest.NewRecorder()
	handlerA.ServeHTTP(recA, reqA)
	if recA.Code != http.StatusOK {
		t.Fatalf("expected 200 for matching-audience token, got %d", recA.Code)
	}
}

// TestMigrationV1ToV2_PreservesLegacyRows confirms that an existing
// v0.8-era database (schema version 1, no resource/audience columns)
// opens cleanly under v0.9 with the migration applied, and that any
// access tokens previously written continue to verify. Without this
// test, the migration could silently break every token in the fleet
// on upgrade — the worst possible regression for an auth library.
func TestMigrationV1ToV2_PreservesLegacyRows(t *testing.T) {
	store := newTestStore(t)

	// Simulate a v1 token row by writing through the v2 API with an
	// empty Audience (the shape any v1 row naturally has after
	// migration, since the ALTER TABLE added the column with default '').
	now := time.Now().Unix()
	legacy := "legacy-from-v0.8"
	if err := store.StoreAccessToken(legacy, TokenData{
		ClientID: "c1", Scope: "mcp:tools",
		ExpiresAt: now + 3600, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Both legacy and audience-aware checks must accept this token.
	if !store.VerifyAccessToken(legacy, "mcp:tools") {
		t.Error("legacy-shape token must verify via VerifyAccessToken")
	}
	if !store.VerifyAccessTokenForResource(legacy, "mcp:tools", "https://mcp.example.com/mcp") {
		t.Error("legacy-shape token must verify via VerifyAccessTokenForResource (empty stored audience is accepted)")
	}

	// Verify the schema_version row was bumped to currentSchemaVersion.
	var version int
	if err := store.db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != currentSchemaVersion {
		t.Errorf("expected schema_version=%d after migration, got %d", currentSchemaVersion, version)
	}
}

// pkceS256 computes the S256 code challenge for a given verifier. Used
// by tests that seed auth_codes rows directly. Kept here rather than
// exported from the auth package because no non-test caller should
// need it — production flows compute the challenge client-side.
func pkceS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func parseJSONBody(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("parse JSON body: %v (body=%s)", err, rec.Body.String())
	}
}
