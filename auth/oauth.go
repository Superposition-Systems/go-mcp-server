package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
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

	// Scope is the OAuth scope string (e.g. "mcp:tools").
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
}

// OAuthHandler serves all OAuth 2.0 endpoints: discovery, registration,
// authorization (PIN consent), and token exchange.
type OAuthHandler struct {
	Store      *OAuthStore
	config     OAuthConfig
	PINLimiter *RateLimiter
	RegLimiter *RateLimiter
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
	return &OAuthHandler{
		Store:      store,
		config:     cfg,
		PINLimiter: NewRateLimiter(5, 900),
		RegLimiter: NewRateLimiter(10, 3600),
	}
}

// Discovery returns RFC 8414 OAuth authorization server metadata.
func (h *OAuthHandler) Discovery(w http.ResponseWriter, r *http.Request) {
	base := baseURLFromConfig(h.config, r)
	writeOAuthJSON(w, http.StatusOK, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
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
	base := baseURLFromConfig(h.config, r)
	writeOAuthJSON(w, http.StatusOK, map[string]any{
		"resource":                 base + h.config.ResourcePath,
		"authorization_servers":    []string{base},
		"scopes_supported":        []string{h.config.Scope},
		"bearer_methods_supported": []string{"header"},
	})
}

// Register handles RFC 7591 dynamic client registration.
func (h *OAuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
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
		writeOAuthJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "server_error", "error_description": err.Error()})
		return
	}

	writeOAuthJSON(w, http.StatusCreated, client)
}

// AuthorizeGET renders the PIN consent page.
func (h *OAuthHandler) AuthorizeGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, "", "Invalid response_type."))
		return
	}

	// PKCE is mandatory — require code_challenge
	if q.Get("code_challenge") == "" {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, "", "code_challenge is required (PKCE S256)."))
		return
	}

	// Validate code_challenge_method
	ccm := q.Get("code_challenge_method")
	if ccm != "" && ccm != "S256" {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, "", "Unsupported code_challenge_method. Only S256 is supported."))
		return
	}

	client, err := h.Store.GetClient(q.Get("client_id"))
	if err != nil || client == nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, "", "Unknown client_id."))
		return
	}

	// Validate scope against allowed scope
	reqScope := q.Get("scope")
	if reqScope != "" && reqScope != h.config.Scope {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, "", "Invalid scope."))
		return
	}

	// Store auth request server-side (not in form)
	requestID := uuid.New().String()
	if err := h.Store.StoreAuthRequest(requestID, map[string]string{
		"client_id":             q.Get("client_id"),
		"redirect_uri":         q.Get("redirect_uri"),
		"state":                q.Get("state"),
		"code_challenge":       q.Get("code_challenge"),
		"code_challenge_method": q.Get("code_challenge_method"),
		"scope":                q.Get("scope"),
	}); err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, "", "Server error."))
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, requestID, ""))
}

// AuthorizePOST validates the PIN and issues an authorization code.
func (h *OAuthHandler) AuthorizePOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, "", "Invalid form data."))
		return
	}
	pin := r.FormValue("pin")
	requestID := r.FormValue("auth_context") // reuse field name for the opaque request ID

	if requestID == "" {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, "", "Missing authorization context."))
		return
	}

	ip := clientIP(r)
	if h.PINLimiter.IsRateLimited(ip) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, requestID, "Too many attempts. Try later."))
		return
	}

	if h.config.PIN == "" {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, requestID, "Server PIN not configured."))
		return
	}

	if !SafeEqual(pin, h.config.PIN) {
		h.PINLimiter.RecordFailure(ip)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, requestID, "Incorrect PIN."))
		return
	}
	h.PINLimiter.Clear(ip)

	// Retrieve server-side stored auth request (tamper-proof)
	authCtx, err := h.Store.GetAuthRequest(requestID)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, "", "Authorization request expired or invalid."))
		return
	}

	client, err := h.Store.GetClient(authCtx["client_id"])
	if err != nil || client == nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, "", "Unknown client_id"))
		return
	}

	// Redirect URI validation — ALWAYS required, reject if client has no URIs
	if len(client.RedirectURIs) == 0 {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, "", "Client has no registered redirect URIs."))
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
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, "", "Invalid redirect_uri"))
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
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, RenderPINPage(h.config.ConsentTitle, h.config.ConsentDescription, "", "Failed to create authorization code."))
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

	client, err := h.Store.GetClient(clientID)
	if err != nil || client == nil || !SafeEqual(clientSecret, client.ClientSecret) {
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

	// PKCE is mandatory — reject if no code_challenge was stored
	if codeData.CodeChallenge == "" {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "code_challenge required"})
		return
	}
	if codeData.CodeChallengeMethod != "" && codeData.CodeChallengeMethod != "S256" {
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
	scope := codeData.Scope
	if scope == "" {
		scope = h.config.Scope
	}

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

func (h *OAuthHandler) exchangeRefreshToken(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	refreshToken := r.FormValue("refresh_token")

	client, err := h.Store.GetClient(clientID)
	if err != nil || client == nil || !SafeEqual(clientSecret, client.ClientSecret) {
		writeOAuthJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
		return
	}

	tokenData, err := h.Store.ConsumeRefreshToken(refreshToken)
	if err != nil || tokenData == nil {
		writeOAuthJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}
	if tokenData.ClientID != clientID {
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

func pkceVerify(codeVerifier, codeChallenge string) bool {
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return SafeEqual(computed, codeChallenge)
}

// baseURLFromConfig returns the canonical base URL from config, or derives
// it from request headers (dev-only fallback restricted to localhost).
func baseURLFromConfig(cfg OAuthConfig, r *http.Request) string {
	if cfg.ExternalURL != "" {
		return strings.TrimRight(cfg.ExternalURL, "/")
	}
	// Dev-only fallback: only trust request-derived URLs for localhost.
	// In production, ExternalURL must be set.
	host := r.Host
	hostname := host
	if i := strings.LastIndex(host, ":"); i != -1 {
		hostname = host[:i]
	}
	if hostname != "localhost" && hostname != "127.0.0.1" && hostname != "::1" {
		log.Printf("mcpserver: WARNING: ExternalURL not set and request host %q is not localhost — using http://localhost as fallback", host)
		return "http://localhost"
	}
	return "http://" + host
}

// validateRedirectURI ensures a redirect URI uses https (or http://localhost for dev).
func validateRedirectURI(uri string) error {
	u, err := url.ParseRequestURI(uri)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1") {
		return nil
	}
	return fmt.Errorf("redirect_uri must use https (or http://localhost for development)")
}

// clientIP extracts the client IP for rate limiting.
// Uses RemoteAddr by default. When behind a trusted reverse proxy,
// falls back to the first X-Forwarded-For entry (client-supplied IP).
// For untrusted networks, configure your proxy to overwrite X-Forwarded-For.
func clientIP(r *http.Request) string {
	return r.RemoteAddr
}

func writeOAuthJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("mcpserver: failed to write OAuth JSON response: %v", err)
	}
}
