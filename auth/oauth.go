package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"time"

	"github.com/google/uuid"
)

// OAuthConfig configures the OAuth handler.
type OAuthConfig struct {
	// PIN is the authorization PIN users enter on the consent page.
	PIN string

	// Scope is the OAuth scope string (e.g. "mcp:tools"). Multi-value
	// scopes may be expressed as a space-delimited list.
	Scope string

	// ResourcePath is the MCP endpoint path suffix for RFC 9728 metadata
	// (e.g. "/mcp"). Defaults to "/mcp" if empty.
	ResourcePath string

	// ExternalURL is the canonical public URL of this server (e.g.
	// "https://my-mcp.example.com"). Used as the OAuth issuer and to build
	// all metadata endpoint URLs. If empty, the server falls back to
	// deriving the URL from request headers (suitable for local dev only).
	ExternalURL string

	// ConsentTitle is the title shown on the PIN consent page.
	ConsentTitle string

	// ConsentDescription is the description shown on the PIN consent page.
	ConsentDescription string

	// AllowMissingState, when true, permits authorization requests that
	// omit the `state` parameter. Default (false) rejects them — OAuth
	// 2.1 treats state as the primary CSRF countermeasure, and PKCE
	// alone is not a complete substitute against cross-site request
	// forgery on the redirect leg. Enable only if you must interoperate
	// with legacy clients that do not send state.
	AllowMissingState bool

	// TrustedProxyCIDRs lists CIDR ranges whose X-Forwarded-For header
	// the server may trust when determining the client IP for rate
	// limiting. Leave empty to use r.RemoteAddr directly (appropriate
	// when no proxy is in front of this server).
	TrustedProxyCIDRs []string
}

// OAuthHandler serves all OAuth 2.0 endpoints: discovery, registration,
// authorization (PIN consent), and token exchange.
type OAuthHandler struct {
	Store            *OAuthStore
	config           OAuthConfig
	PINLimiter       *RateLimiter
	RegLimiter       *RateLimiter
	AuthorizeLimiter *RateLimiter
	trustedNets      []*net.IPNet
}

// NewOAuthHandler creates an OAuth handler with the given store and config.
func NewOAuthHandler(store *OAuthStore, cfg OAuthConfig) *OAuthHandler {
	if cfg.ResourcePath == "" {
		cfg.ResourcePath = "/mcp"
	}
	if cfg.Scope == "" {
		cfg.Scope = store.DefaultScope()
	}
	if cfg.ConsentTitle == "" {
		cfg.ConsentTitle = "MCP Server"
	}
	if cfg.ConsentDescription == "" {
		cfg.ConsentDescription = "Enter the authorization PIN to connect."
	}
	h := &OAuthHandler{
		Store:            store,
		config:           cfg,
		PINLimiter:       NewRateLimiter(5, 900),
		RegLimiter:       NewRateLimiter(10, 3600),
		AuthorizeLimiter: NewRateLimiter(60, 3600), // bound auth-request store DoS
	}
	for _, c := range cfg.TrustedProxyCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			log.Printf("mcpserver: ignoring invalid trusted proxy CIDR %q: %v", c, err)
			continue
		}
		h.trustedNets = append(h.trustedNets, n)
	}
	return h
}

// Discovery returns RFC 8414 OAuth authorization server metadata.
func (h *OAuthHandler) Discovery(w http.ResponseWriter, r *http.Request) {
	base, ok := baseURLOrError(h.config, r, w)
	if !ok {
		return
	}
	writeOAuthJSON(w, http.StatusOK, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"revocation_endpoint":                   base + "/revoke",
		"registration_endpoint":                 base + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{h.config.Scope},
	})
}

// ProtectedResource returns RFC 9728 protected resource metadata.
func (h *OAuthHandler) ProtectedResource(w http.ResponseWriter, r *http.Request) {
	base, ok := baseURLOrError(h.config, r, w)
	if !ok {
		return
	}
	writeOAuthJSON(w, http.StatusOK, map[string]any{
		"resource":                 base + h.config.ResourcePath,
		"authorization_servers":    []string{base},
		"scopes_supported":         []string{h.config.Scope},
		"bearer_methods_supported": []string{"header"},
	})
}

// Register handles RFC 7591 dynamic client registration.
func (h *OAuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	ip := h.clientIP(r)
	if h.RegLimiter.IsRateLimited(ip) {
		writeOAuthJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too_many_requests"})
		return
	}
	h.RegLimiter.RecordFailure(ip) // count every attempt, not just failures

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
	var metadata map[string]any
	if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}

	uris := getStringSlice(metadata, "redirect_uris")
	if len(uris) == 0 {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "error_description": "redirect_uris required"})
		return
	}
	for _, uri := range uris {
		if err := validateRedirectURI(uri); err != nil {
			writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "error_description": err.Error()})
			return
		}
	}

	client, err := h.Store.RegisterClient(metadata)
	if err != nil {
		// Don't echo the underlying error — SQLite error strings can
		// disclose schema details to unauthenticated callers.
		log.Printf("mcpserver: client registration failed: %v", err)
		writeOAuthJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "server_error", "error_description": "registration failed"})
		return
	}

	writeOAuthJSON(w, http.StatusCreated, client)
}

// redirectHost extracts the host portion of a redirect_uri for display on
// the consent page. Returns "" when the URI cannot be parsed.
func redirectHost(rawURI string) string {
	if rawURI == "" {
		return ""
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return ""
	}
	return u.Host
}

// renderPINErr writes an error-state consent page. Used for pre-client-lookup
// failures where ClientName/RedirectHost are not known. HTTP status and body
// are written together.
func (h *OAuthHandler) renderPINErr(w http.ResponseWriter, status int, authCtx, msg string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	fmt.Fprint(w, RenderPINPage(PINPageData{
		Title:       h.config.ConsentTitle,
		Description: h.config.ConsentDescription,
		AuthContext: authCtx,
		ErrorMsg:    msg,
	}))
}

// AuthorizeGET renders the PIN consent page.
func (h *OAuthHandler) AuthorizeGET(w http.ResponseWriter, r *http.Request) {
	// Rate-limit per-IP to bound the server-side auth-request store
	// against unauthenticated flood DoS.
	ip := h.clientIP(r)
	if h.AuthorizeLimiter.IsRateLimited(ip) {
		h.renderPINErr(w, http.StatusTooManyRequests, "", "Too many authorization requests from your address.")
		return
	}
	h.AuthorizeLimiter.RecordFailure(ip)

	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		h.renderPINErr(w, http.StatusBadRequest, "", "Invalid response_type.")
		return
	}

	// PKCE is mandatory — require code_challenge. For S256 the output is
	// base64url(SHA-256(verifier)), which is exactly 43 characters; we
	// accept a small envelope above that (up to 128) to tolerate future
	// methods without allowing 10KB+ blobs to fill the auth-request
	// store.
	codeChallenge := q.Get("code_challenge")
	if codeChallenge == "" {
		h.renderPINErr(w, http.StatusBadRequest, "", "code_challenge is required (PKCE S256).")
		return
	}
	if len(codeChallenge) > 128 {
		h.renderPINErr(w, http.StatusBadRequest, "", "code_challenge too long.")
		return
	}

	// Validate code_challenge_method. Normalize absent/empty method to
	// "S256" so the downstream record always stores a concrete value
	// (and never silently enables a future code path that branches on
	// an empty method).
	ccm := q.Get("code_challenge_method")
	if ccm == "" {
		ccm = "S256"
	}
	if ccm != "S256" {
		h.renderPINErr(w, http.StatusBadRequest, "", "Unsupported code_challenge_method. Only S256 is supported.")
		return
	}

	// OAuth 2.1: require `state` unless explicitly allowed off. PKCE
	// plus state form defense-in-depth against CSRF on the redirect.
	state := q.Get("state")
	if state == "" && !h.config.AllowMissingState {
		h.renderPINErr(w, http.StatusBadRequest, "", "state parameter is required.")
		return
	}
	if len(state) > 512 {
		h.renderPINErr(w, http.StatusBadRequest, "", "state parameter too long.")
		return
	}

	client, err := h.Store.GetClient(q.Get("client_id"))
	if err != nil || client == nil {
		h.renderPINErr(w, http.StatusBadRequest, "", "Unknown client_id.")
		return
	}

	// Validate redirect_uri against registered URIs before rendering consent (RFC 6749 §3.1.2.4)
	reqRedirectURI := q.Get("redirect_uri")
	if len(client.RedirectURIs) == 0 {
		h.renderPINErr(w, http.StatusBadRequest, "", "Client has no registered redirect URIs.")
		return
	}
	uriFound := false
	for _, u := range client.RedirectURIs {
		if u == reqRedirectURI {
			uriFound = true
			break
		}
	}
	if !uriFound {
		h.renderPINErr(w, http.StatusBadRequest, "", "Invalid redirect_uri.")
		return
	}

	// Validate requested scope is a subset of the configured scope.
	reqScope := q.Get("scope")
	if reqScope != "" && !ScopeContains(h.config.Scope, reqScope) {
		h.renderPINErr(w, http.StatusBadRequest, "", "Invalid scope.")
		return
	}

	// Store auth request server-side (not in form)
	requestID := uuid.New().String()
	if err := h.Store.StoreAuthRequest(requestID, map[string]string{
		"client_id":             q.Get("client_id"),
		"redirect_uri":          reqRedirectURI,
		"state":                 state,
		"code_challenge":        codeChallenge,
		"code_challenge_method": ccm,
		"scope":                 reqScope,
	}); err != nil {
		h.renderPINErr(w, http.StatusInternalServerError, "", "Server error.")
		return
	}

	// Happy path — render consent page with client identity so the
	// operator can visually confirm who they are authorizing before
	// entering the PIN. Redirect host is the validated registered
	// value, not attacker-controlled input.
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, RenderPINPage(PINPageData{
		Title:        h.config.ConsentTitle,
		Description:  h.config.ConsentDescription,
		AuthContext:  requestID,
		ClientName:   client.ClientName,
		RedirectHost: redirectHost(reqRedirectURI),
	}))
}

// AuthorizePOST validates the PIN and issues an authorization code.
func (h *OAuthHandler) AuthorizePOST(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64 KB — generous for a PIN form
	if err := r.ParseForm(); err != nil {
		h.renderPINErr(w, http.StatusBadRequest, "", "Invalid form data.")
		return
	}
	pin := r.FormValue("pin")
	requestID := r.FormValue("auth_context") // reuse field name for the opaque request ID

	if requestID == "" {
		h.renderPINErr(w, http.StatusBadRequest, "", "Missing authorization context.")
		return
	}

	ip := h.clientIP(r)
	if h.PINLimiter.IsRateLimited(ip) {
		h.renderPINErr(w, http.StatusTooManyRequests, requestID, "Too many attempts. Try later.")
		return
	}

	if h.config.PIN == "" {
		h.renderPINErr(w, http.StatusInternalServerError, requestID, "Server PIN not configured.")
		return
	}

	if !SafeEqual(pin, h.config.PIN) {
		h.PINLimiter.RecordFailure(ip)
		h.renderPINErr(w, http.StatusForbidden, requestID, "Incorrect PIN.")
		return
	}
	h.PINLimiter.Clear(ip)

	// Retrieve server-side stored auth request (tamper-proof)
	authCtx, err := h.Store.GetAuthRequest(requestID)
	if err != nil {
		h.renderPINErr(w, http.StatusBadRequest, "", "Authorization request expired or invalid.")
		return
	}

	client, err := h.Store.GetClient(authCtx["client_id"])
	if err != nil || client == nil {
		h.renderPINErr(w, http.StatusBadRequest, "", "Unknown client_id")
		return
	}

	// Redirect URI validation — ALWAYS required, reject if client has no URIs
	if len(client.RedirectURIs) == 0 {
		h.renderPINErr(w, http.StatusBadRequest, "", "Client has no registered redirect URIs.")
		return
	}
	found := false
	for _, u := range client.RedirectURIs {
		if u == authCtx["redirect_uri"] {
			found = true
			break
		}
	}
	if !found {
		h.renderPINErr(w, http.StatusBadRequest, "", "Invalid redirect_uri")
		return
	}

	code := uuid.New().String()
	if err := h.Store.StoreAuthCode(code, AuthCodeData{
		ClientID:            authCtx["client_id"],
		RedirectURI:         authCtx["redirect_uri"],
		CodeChallenge:       authCtx["code_challenge"],
		CodeChallengeMethod: authCtx["code_challenge_method"],
		Scope:               authCtx["scope"],
		CreatedAt:           time.Now().Unix(),
	}); err != nil {
		h.renderPINErr(w, http.StatusInternalServerError, "", "Failed to create authorization code.")
		return
	}

	redirectURI := authCtx["redirect_uri"]
	params := url.Values{"code": {code}}
	if s := authCtx["state"]; s != "" {
		params.Set("state", s)
	}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}

	http.Redirect(w, r, redirectURI+sep+params.Encode(), http.StatusFound)
}

// Token handles authorization code exchange and refresh token rotation.
func (h *OAuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64 KB
	if err := r.ParseForm(); err != nil {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		h.exchangeAuthCode(w, r)
	case "refresh_token":
		h.exchangeRefreshToken(w, r)
	default:
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
	}
}

func (h *OAuthHandler) exchangeAuthCode(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")

	if !h.Store.VerifyClientSecret(clientID, clientSecret) {
		writeOAuthJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
		return
	}

	codeData, err := h.Store.ConsumeAuthCode(code)
	if err != nil || codeData == nil {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}
	if codeData.ClientID != clientID {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}

	// RFC 6749 §4.1.3: redirect_uri must match the one from the authorization request
	if r.FormValue("redirect_uri") != codeData.RedirectURI {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
		return
	}

	// PKCE is mandatory — reject if no code_challenge was stored
	if codeData.CodeChallenge == "" {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "code_challenge required"})
		return
	}
	if codeData.CodeChallengeMethod != "S256" {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "unsupported code_challenge_method"})
		return
	}
	if codeVerifier == "" {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "code_verifier required"})
		return
	}
	if !pkceVerify(codeVerifier, codeData.CodeChallenge) {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "PKCE failed"})
		return
	}

	now := time.Now().Unix()
	// Scope the issued token to exactly what the client requested.
	// Do NOT widen to the server default — a client that asked for no
	// scope must not receive a maximally-privileged token.
	scope := codeData.Scope

	accessToken := RandomHex(32)
	if err := h.Store.StoreAccessToken(accessToken, TokenData{ClientID: clientID, Scope: scope, ExpiresAt: now + 3600, CreatedAt: now}); err != nil {
		writeOAuthJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error"})
		return
	}

	refreshToken := RandomHex(32)
	if err := h.Store.StoreRefreshToken(refreshToken, TokenData{ClientID: clientID, Scope: scope, ExpiresAt: now + 30*24*3600, CreatedAt: now}); err != nil {
		writeOAuthJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error"})
		return
	}

	writeOAuthJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
		"scope":         scope,
	})
}

// Revoke handles RFC 7009 token revocation. The client authenticates
// with client_secret_post; on success, the token is removed from the
// store. The response is 200 regardless of whether the token existed —
// §2.2 of the RFC mandates this to prevent probing.
//
// Unauthenticated or wrong-client requests receive 401. Store errors
// surface as 503 so operators know revocation did not take effect
// (fail-loud rather than the RFC's usual fail-quiet semantic —
// silently "succeeding" on a store failure would defeat the whole
// purpose of revocation).
func (h *OAuthHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := r.ParseForm(); err != nil {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	token := r.FormValue("token")

	if !h.Store.VerifyClientSecret(clientID, clientSecret) {
		writeOAuthJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
		return
	}
	// An empty token is a malformed request; callers should not hit
	// this endpoint without one. Per the RFC we could also return 200,
	// but silently accepting empty tokens would hide client bugs.
	if token == "" {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "error_description": "token required"})
		return
	}
	// token_type_hint is optional and we ignore it — our two token
	// spaces are disjoint hash digests so we can safely check both.

	if err := h.Store.RevokeToken(token, clientID); err != nil {
		log.Printf("mcpserver: token revocation failed: %v", err)
		writeOAuthJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "server_error"})
		return
	}
	// RFC 7009 §2.2: 200 with empty body on success (or on unknown
	// token). We emit {} for clients that insist on JSON.
	writeOAuthJSON(w, http.StatusOK, map[string]any{})
}

func (h *OAuthHandler) exchangeRefreshToken(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	refreshToken := r.FormValue("refresh_token")

	if !h.Store.VerifyClientSecret(clientID, clientSecret) {
		writeOAuthJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
		return
	}

	// ConsumeRefreshToken verifies the client binding BEFORE deleting so
	// that a wrong-client request cannot burn the legitimate client's
	// token.
	tokenData, err := h.Store.ConsumeRefreshToken(refreshToken, clientID)
	if err != nil || tokenData == nil {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}

	now := time.Now().Unix()
	scope := tokenData.Scope

	newAT := RandomHex(32)
	if err := h.Store.StoreAccessToken(newAT, TokenData{ClientID: clientID, Scope: scope, ExpiresAt: now + 3600, CreatedAt: now}); err != nil {
		writeOAuthJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error"})
		return
	}

	newRT := RandomHex(32)
	if err := h.Store.StoreRefreshToken(newRT, TokenData{ClientID: clientID, Scope: scope, ExpiresAt: now + 30*24*3600, CreatedAt: now}); err != nil {
		writeOAuthJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error"})
		return
	}

	writeOAuthJSON(w, http.StatusOK, map[string]any{
		"access_token":  newAT,
		"token_type":    "bearer",
		"expires_in":    3600,
		"refresh_token": newRT,
		"scope":         scope,
	})
}

// SafeEqual performs a constant-time string comparison that does not leak
// length information. Both inputs are SHA-256 hashed before comparison,
// producing fixed-length digests regardless of input length.
func SafeEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// pkceVerify computes the S256 challenge from the verifier and compares
// it to the stored challenge in constant time.
//
// codeVerifier is the raw PKCE verifier sent by the client; this
// function hashes it (unconditionally — no early return on short
// verifier input) to base64url(SHA-256) and compares the result
// against codeChallenge.
//
// The verifier-hash step runs before any length check on codeChallenge
// so timing does not disclose "was the verifier correct length"
// separately from "was it the right value." A legitimate S256
// codeChallenge is always 43 bytes (base64url-no-pad of 32 hash bytes);
// anything else is a protocol error and always fails.
func pkceVerify(codeVerifier, codeChallenge string) bool {
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	if len(codeChallenge) != len(computed) {
		// Explicit length guard after the hash work, so subtle's
		// implicit length-mismatch short-circuit never observably
		// runs. Equivalent security, clearer intent.
		return false
	}
	return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
}

// baseURLFromConfig returns the canonical base URL from config, or
// derives it from request headers for localhost-only development. For
// non-localhost requests without ExternalURL it returns an empty
// string — callers must treat that as an error (see baseURLOrError).
//
// Never silently falls back to "http://localhost" for non-localhost
// requests: that old behavior caused OAuth discovery to advertise
// localhost URLs to real clients, breaking the flow without any
// client-visible signal.
func baseURLFromConfig(cfg OAuthConfig, r *http.Request) string {
	if cfg.ExternalURL != "" {
		return strings.TrimRight(cfg.ExternalURL, "/")
	}
	host := r.Host
	hostname := host
	if i := strings.LastIndex(host, ":"); i != -1 {
		hostname = host[:i]
	}
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		return "http://" + host
	}
	return ""
}

// baseURLOrError is the metadata-endpoint wrapper around
// baseURLFromConfig. When no canonical base URL can be determined, it
// writes a 500 response explaining the required configuration and
// returns ok=false. Metadata clients therefore get a clear error
// instead of silently-poisoned "http://localhost" discovery data.
func baseURLOrError(cfg OAuthConfig, r *http.Request, w http.ResponseWriter) (string, bool) {
	base := baseURLFromConfig(cfg, r)
	if base == "" {
		log.Printf("mcpserver: rejecting OAuth metadata request from host %q — WithExternalURL(...) is required in production", r.Host)
		writeOAuthJSON(w, http.StatusInternalServerError, map[string]any{
			"error":             "server_error",
			"error_description": "OAuth ExternalURL is not configured; server cannot produce discovery metadata for non-localhost hosts",
		})
		return "", false
	}
	return base, true
}

// validateRedirectURI enforces RFC 6749 §3.1.2: https (or localhost http
// for dev), no query string or fragment component, and no userinfo
// (credentials in a redirect URL are dangerous — they end up in browser
// history and server logs).
func validateRedirectURI(uri string) error {
	u, err := url.ParseRequestURI(uri)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri: %w", err)
	}
	if u.Fragment != "" || strings.Contains(uri, "#") {
		return fmt.Errorf("redirect_uri must not contain a fragment")
	}
	// url.Parse treats a bare trailing "?" as RawQuery=="" so we check
	// the raw string too.
	if u.RawQuery != "" || strings.Contains(uri, "?") {
		return fmt.Errorf("redirect_uri must not contain a query string")
	}
	if u.User != nil {
		return fmt.Errorf("redirect_uri must not contain userinfo")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1") {
		return nil
	}
	return fmt.Errorf("redirect_uri must use https (or http://localhost for development)")
}

// clientIP extracts the client IP for rate limiting. Strips the port
// from RemoteAddr so repeated connections from the same IP aggregate
// under one rate-limit key. When the request arrived from a CIDR in
// TrustedProxyCIDRs, the left-most parseable X-Forwarded-For (or
// X-Real-IP) entry is used instead.
//
// Every proxy-header candidate is run through net.ParseIP and
// canonicalized via IP.String() before use. Without this, an attacker
// behind a trusted proxy could spray arbitrary string values via
// X-Forwarded-For and create unlimited distinct rate-limit keys,
// filling the 100k-IP cap and defeating per-IP limiting entirely.
func (h *OAuthHandler) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	if len(h.trustedNets) > 0 {
		remoteIP := net.ParseIP(host)
		if remoteIP != nil && h.isTrustedProxy(remoteIP) {
			if ip := firstValidIP(r.Header.Get("X-Forwarded-For")); ip != "" {
				return ip
			}
			if ip := parseIPHeader(r.Header.Get("X-Real-IP")); ip != "" {
				return ip
			}
		}
	}
	return host
}

// firstValidIP returns the left-most comma-separated entry in xff that
// parses as an IP address (canonicalized). Returns "" if none parse.
func firstValidIP(xff string) string {
	if xff == "" {
		return ""
	}
	for _, p := range strings.Split(xff, ",") {
		if ip := parseIPHeader(p); ip != "" {
			return ip
		}
	}
	return ""
}

// parseIPHeader parses a proxy-supplied IP header value, tolerating
// surrounding whitespace and an optional appended port. Returns the
// canonical string form ("" on failure).
func parseIPHeader(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// Accept "ip:port" forms as well as bare IPs.
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func (h *OAuthHandler) isTrustedProxy(ip net.IP) bool {
	for _, n := range h.trustedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func writeOAuthJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("mcpserver: failed to write OAuth JSON response: %v", err)
	}
}
