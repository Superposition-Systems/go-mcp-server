package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// validScope matches safe scope strings (alphanumeric, colon, dot, underscore, hyphen, space).
var validScope = regexp.MustCompile(`^[a-zA-Z0-9:._\- ]+$`)

// OAuthStore persists OAuth 2.0 clients, auth codes, and tokens in SQLite.
// Uses pure-Go SQLite (modernc.org/sqlite) for CGO-free builds compatible
// with distroless container images.
//
// Secrets (client secrets, access tokens, refresh tokens, auth codes) are
// stored as SHA-256 hashes, never plaintext. A database dump therefore
// does not disclose live credentials, and lookups occur against the hash
// (making SQL-level equality checks safe from timing disclosure of the
// raw secret).
type OAuthStore struct {
	db         *sql.DB
	mu         sync.Mutex
	maxClients int
	scope      string
}

// ClientData represents a registered OAuth client.
//
// Note: ClientSecret is populated only on the RegisterClient return value
// (once, at issuance). GetClient never returns the secret — use
// VerifyClientSecret to authenticate a client.
type ClientData struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	ClientName              string   `json:"client_name,omitempty"`
}

// AuthCodeData represents an issued authorization code.
type AuthCodeData struct {
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	CreatedAt           int64
}

// TokenData represents an access or refresh token.
type TokenData struct {
	ClientID  string
	Scope     string
	ExpiresAt int64
	CreatedAt int64
}

// hashSecret returns the hex-encoded SHA-256 of a secret (token, code, or
// client secret). Used as the primary lookup key for all persisted
// secrets so the raw values never touch the database.
func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// NewOAuthStore opens (or creates) a SQLite database at dbPath for OAuth state.
// The scope parameter sets the default OAuth scope (e.g. "mcp:tools").
func NewOAuthStore(dbPath string, scope string) (*OAuthStore, error) {
	if scope != "" && !validScope.MatchString(scope) {
		return nil, fmt.Errorf("invalid scope: contains disallowed characters")
	}

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	// SQLite supports only one writer at a time. Pinning to a single connection
	// ensures db.BeginTx transactions are not split across pool connections.
	db.SetMaxOpenConns(1)

	store := &OAuthStore{db: db, maxClients: 1000, scope: scope}
	if err := store.createTables(); err != nil {
		db.Close()
		return nil, err
	}

	return store, nil
}

// Close closes the underlying SQLite database.
func (s *OAuthStore) Close() error {
	return s.db.Close()
}

// DefaultScope returns the configured default scope.
func (s *OAuthStore) DefaultScope() string {
	return s.scope
}

func (s *OAuthStore) createTables() error {
	// Column names retained for backward compat with existing databases,
	// but semantically all "*_secret"/"token"/"code" columns now store
	// hex-SHA-256 digests rather than the raw secret.
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS clients (
			client_id TEXT PRIMARY KEY,
			client_secret TEXT NOT NULL,
			client_id_issued_at INTEGER NOT NULL,
			redirect_uris TEXT NOT NULL DEFAULT '[]',
			token_endpoint_auth_method TEXT DEFAULT 'client_secret_post',
			grant_types TEXT DEFAULT '["authorization_code","refresh_token"]',
			response_types TEXT DEFAULT '["code"]',
			scope TEXT DEFAULT '',
			client_name TEXT
		);
		CREATE TABLE IF NOT EXISTS auth_codes (
			code TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL DEFAULT '',
			code_challenge TEXT NOT NULL DEFAULT '',
			code_challenge_method TEXT DEFAULT 'S256',
			scope TEXT DEFAULT '',
			created_at INTEGER NOT NULL,
			FOREIGN KEY (client_id) REFERENCES clients(client_id)
		);
		CREATE TABLE IF NOT EXISTS access_tokens (
			token TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			scope TEXT DEFAULT '',
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS refresh_tokens (
			token TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			scope TEXT DEFAULT '',
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS auth_requests (
			request_id TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL DEFAULT '',
			state TEXT NOT NULL DEFAULT '',
			code_challenge TEXT NOT NULL DEFAULT '',
			code_challenge_method TEXT DEFAULT 'S256',
			scope TEXT DEFAULT '',
			created_at INTEGER NOT NULL
		);
	`)
	return err
}

// RegisterClient performs RFC 7591 dynamic client registration. The
// returned ClientData carries the raw ClientSecret — this is the only
// time it is accessible. The secret is stored as a SHA-256 hash; all
// subsequent authentications must go through VerifyClientSecret.
func (s *OAuthStore) RegisterClient(metadata map[string]any) (*ClientData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM clients").Scan(&count); err != nil {
		return nil, fmt.Errorf("count clients: %w", err)
	}
	if count >= s.maxClients {
		return nil, fmt.Errorf("max clients reached")
	}

	clientID := uuid.New().String()
	clientSecret := RandomHex(32)
	now := time.Now().Unix()

	redirectURIs, _ := json.Marshal(getStringSlice(metadata, "redirect_uris"))
	grantTypes, _ := json.Marshal(getStringSliceDefault(metadata, "grant_types", []string{"authorization_code", "refresh_token"}))
	responseTypes, _ := json.Marshal(getStringSliceDefault(metadata, "response_types", []string{"code"}))
	scope := getStringDefault(metadata, "scope", s.scope)
	authMethod := getStringDefault(metadata, "token_endpoint_auth_method", "client_secret_post")
	clientName := getStringDefault(metadata, "client_name", "")

	_, err := s.db.Exec(
		`INSERT INTO clients (client_id, client_secret, client_id_issued_at,
			redirect_uris, token_endpoint_auth_method, grant_types, response_types, scope, client_name)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		clientID, hashSecret(clientSecret), now, string(redirectURIs), authMethod,
		string(grantTypes), string(responseTypes), scope, clientName,
	)
	if err != nil {
		return nil, err
	}

	return &ClientData{
		ClientID:                clientID,
		ClientSecret:            clientSecret, // returned once, only here
		ClientIDIssuedAt:        now,
		RedirectURIs:            getStringSlice(metadata, "redirect_uris"),
		TokenEndpointAuthMethod: authMethod,
		GrantTypes:              getStringSliceDefault(metadata, "grant_types", []string{"authorization_code", "refresh_token"}),
		ResponseTypes:           getStringSliceDefault(metadata, "response_types", []string{"code"}),
		Scope:                   scope,
		ClientName:              clientName,
	}, nil
}

// GetClient retrieves a client by ID. The returned ClientData never
// carries ClientSecret — use VerifyClientSecret to authenticate a
// client's credentials.
func (s *OAuthStore) GetClient(clientID string) (*ClientData, error) {
	row := s.db.QueryRow("SELECT * FROM clients WHERE client_id = ?", clientID)
	var c ClientData
	var redirectURIs, grantTypes, responseTypes string
	var storedHash string
	err := row.Scan(&c.ClientID, &storedHash, &c.ClientIDIssuedAt,
		&redirectURIs, &c.TokenEndpointAuthMethod, &grantTypes, &responseTypes, &c.Scope, &c.ClientName)
	if err != nil {
		return nil, err
	}
	c.ClientSecret = "" // never expose the (hashed) secret to callers
	if err := json.Unmarshal([]byte(redirectURIs), &c.RedirectURIs); err != nil {
		return nil, fmt.Errorf("unmarshal redirect_uris: %w", err)
	}
	if err := json.Unmarshal([]byte(grantTypes), &c.GrantTypes); err != nil {
		return nil, fmt.Errorf("unmarshal grant_types: %w", err)
	}
	if err := json.Unmarshal([]byte(responseTypes), &c.ResponseTypes); err != nil {
		return nil, fmt.Errorf("unmarshal response_types: %w", err)
	}
	return &c, nil
}

// VerifyClientSecret returns true if the presented secret matches the
// hash stored for clientID. Comparison is constant-time against the
// stored hash (SQL equality on a fixed-length digest leaks no length
// information about the raw secret).
func (s *OAuthStore) VerifyClientSecret(clientID, secret string) bool {
	var storedHash string
	err := s.db.QueryRow("SELECT client_secret FROM clients WHERE client_id = ?", clientID).Scan(&storedHash)
	if err != nil {
		return false
	}
	return SafeEqual(hashSecret(secret), storedHash)
}

// StoreAuthCode persists an authorization code. The code is stored as a
// SHA-256 hash; callers retain the raw value to hand to the client.
func (s *OAuthStore) StoreAuthCode(code string, data AuthCodeData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge,
			code_challenge_method, scope, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		hashSecret(code), data.ClientID, data.RedirectURI, data.CodeChallenge,
		data.CodeChallengeMethod, data.Scope, data.CreatedAt,
	)
	return err
}

// ConsumeAuthCode atomically reads and deletes an auth code. Returns nil
// if the code doesn't exist or has expired (300-second TTL).
func (s *OAuthStore) ConsumeAuthCode(code string) (*AuthCodeData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	hashed := hashSecret(code)

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback() // no-op after Commit

	row := tx.QueryRow("SELECT client_id, redirect_uri, code_challenge, code_challenge_method, scope, created_at FROM auth_codes WHERE code = ?", hashed)
	var d AuthCodeData
	if err := row.Scan(&d.ClientID, &d.RedirectURI, &d.CodeChallenge, &d.CodeChallengeMethod, &d.Scope, &d.CreatedAt); err != nil {
		return nil, err
	}

	expired := now-d.CreatedAt > 300
	if _, err := tx.Exec("DELETE FROM auth_codes WHERE code = ?", hashed); err != nil {
		return nil, fmt.Errorf("delete auth code: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	if expired {
		return nil, fmt.Errorf("auth code expired")
	}
	return &d, nil
}

// StoreAccessToken persists an access token as a SHA-256 hash.
// Caps total access tokens at 50,000 to prevent unbounded growth.
func (s *OAuthStore) StoreAccessToken(token string, data TokenData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM access_tokens").Scan(&count); err != nil {
		return fmt.Errorf("count access tokens: %w", err)
	}
	if count >= 50000 {
		return fmt.Errorf("too many active access tokens")
	}

	_, err := s.db.Exec(
		"INSERT INTO access_tokens (token, client_id, scope, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
		hashSecret(token), data.ClientID, data.Scope, data.ExpiresAt, data.CreatedAt,
	)
	return err
}

// VerifyAccessToken checks whether a token is valid, not expired, and
// carries the required scope. Scope is interpreted as a space-delimited
// list (RFC 6749 §3.3): the token is considered to carry requiredScope
// if every space-separated token in requiredScope is present in the
// granted scope. Pass "" to skip scope enforcement entirely.
// Expired tokens are lazily deleted on verification.
func (s *OAuthStore) VerifyAccessToken(token string, requiredScope string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	hashed := hashSecret(token)
	var expiresAt int64
	var scope string
	err := s.db.QueryRow("SELECT expires_at, scope FROM access_tokens WHERE token = ?", hashed).Scan(&expiresAt, &scope)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("mcpserver: failed to verify access token: %v", err)
		}
		return false
	}
	if time.Now().Unix() > expiresAt {
		if _, err := s.db.Exec("DELETE FROM access_tokens WHERE token = ?", hashed); err != nil {
			log.Printf("mcpserver: failed to delete expired token: %v", err)
		}
		return false
	}
	return ScopeContains(scope, requiredScope)
}

// ScopeContains reports whether granted (space-delimited) covers every
// entry in required (also space-delimited). An empty required always
// passes; an empty granted satisfies only an empty required.
func ScopeContains(granted, required string) bool {
	if required == "" {
		return true
	}
	have := make(map[string]struct{})
	for _, s := range splitScope(granted) {
		have[s] = struct{}{}
	}
	for _, s := range splitScope(required) {
		if _, ok := have[s]; !ok {
			return false
		}
	}
	return true
}

func splitScope(s string) []string {
	if s == "" {
		return nil
	}
	out := make([]string, 0, 4)
	for _, f := range regexpSpace.Split(s, -1) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

var regexpSpace = regexp.MustCompile(`\s+`)

// StoreRefreshToken persists a refresh token as a SHA-256 hash.
// Caps total refresh tokens at 50,000 to prevent unbounded growth.
func (s *OAuthStore) StoreRefreshToken(token string, data TokenData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM refresh_tokens").Scan(&count); err != nil {
		return fmt.Errorf("count refresh tokens: %w", err)
	}
	if count >= 50000 {
		return fmt.Errorf("too many active refresh tokens")
	}

	_, err := s.db.Exec(
		"INSERT INTO refresh_tokens (token, client_id, scope, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
		hashSecret(token), data.ClientID, data.Scope, data.ExpiresAt, data.CreatedAt,
	)
	return err
}

// ConsumeRefreshToken atomically reads, verifies client binding, and
// deletes a refresh token (rotate-on-use). If expectedClientID is
// non-empty and does not match the token's recorded clientID, the token
// is left in place and an error is returned — this preserves the
// legitimate client's ability to refresh when a second party presents
// the same token with a wrong client_id.
func (s *OAuthStore) ConsumeRefreshToken(token, expectedClientID string) (*TokenData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	hashed := hashSecret(token)

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback() // no-op after Commit

	row := tx.QueryRow("SELECT client_id, scope, expires_at, created_at FROM refresh_tokens WHERE token = ?", hashed)
	var d TokenData
	if err := row.Scan(&d.ClientID, &d.Scope, &d.ExpiresAt, &d.CreatedAt); err != nil {
		return nil, err
	}
	// Verify client binding BEFORE deleting. A mismatched client_id
	// must not consume the legitimate client's refresh token.
	if expectedClientID != "" && d.ClientID != expectedClientID {
		return nil, fmt.Errorf("refresh token client_id mismatch")
	}
	// Always delete (expired or not) to prevent reuse.
	if _, err := tx.Exec("DELETE FROM refresh_tokens WHERE token = ?", hashed); err != nil {
		return nil, fmt.Errorf("delete refresh token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	if time.Now().Unix() > d.ExpiresAt {
		return nil, fmt.Errorf("refresh token expired")
	}
	return &d, nil
}

// StoreAuthRequest stores authorization request parameters server-side.
// Limits the total number of pending auth requests to prevent DoS via
// unbounded row insertion from unauthenticated callers.
func (s *OAuthStore) StoreAuthRequest(requestID string, data map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM auth_requests").Scan(&count); err != nil {
		return fmt.Errorf("count auth requests: %w", err)
	}
	if count >= 10000 {
		return fmt.Errorf("too many pending auth requests")
	}

	_, err := s.db.Exec(
		`INSERT INTO auth_requests (request_id, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		requestID, data["client_id"], data["redirect_uri"], data["state"],
		data["code_challenge"], data["code_challenge_method"], data["scope"], time.Now().Unix(),
	)
	return err
}

// GetAuthRequest retrieves and deletes an authorization request (single-use).
func (s *OAuthStore) GetAuthRequest(requestID string) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Capture `now` before the transaction so the expiry decision is
	// made against the same clock reading the row was fetched at.
	now := time.Now().Unix()

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback() // no-op after Commit

	var clientID, redirectURI, state, codeChallenge, codeChallengeMethod, scope string
	var createdAt int64
	err = tx.QueryRow(
		"SELECT client_id, redirect_uri, state, code_challenge, code_challenge_method, scope, created_at FROM auth_requests WHERE request_id = ?",
		requestID,
	).Scan(&clientID, &redirectURI, &state, &codeChallenge, &codeChallengeMethod, &scope, &createdAt)
	if err != nil {
		return nil, err
	}

	// Always delete (expired or not) to prevent reuse
	if _, err := tx.Exec("DELETE FROM auth_requests WHERE request_id = ?", requestID); err != nil {
		return nil, fmt.Errorf("delete auth request: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	if now-createdAt > 600 {
		return nil, fmt.Errorf("auth request expired")
	}
	return map[string]string{
		"client_id":             clientID,
		"redirect_uri":          redirectURI,
		"state":                 state,
		"code_challenge":        codeChallenge,
		"code_challenge_method": codeChallengeMethod,
		"scope":                 scope,
	}, nil
}

// Cleanup removes expired auth codes, access tokens, refresh tokens, and auth requests.
// Call this periodically (e.g. every 5 minutes) from a background goroutine.
func (s *OAuthStore) Cleanup() error {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec("DELETE FROM auth_codes WHERE created_at < ?", now-300); err != nil {
		return fmt.Errorf("cleanup auth codes: %w", err)
	}
	if _, err := s.db.Exec("DELETE FROM access_tokens WHERE expires_at < ?", now); err != nil {
		return fmt.Errorf("cleanup access tokens: %w", err)
	}
	if _, err := s.db.Exec("DELETE FROM refresh_tokens WHERE expires_at < ?", now); err != nil {
		return fmt.Errorf("cleanup refresh tokens: %w", err)
	}
	if _, err := s.db.Exec("DELETE FROM auth_requests WHERE created_at < ?", now-600); err != nil {
		return fmt.Errorf("cleanup auth requests: %w", err)
	}
	return nil
}

// RandomHex generates n random bytes and returns them as a hex string.
func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Helpers for extracting values from map[string]any (JSON-decoded metadata).

func getStringSlice(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

func getStringSliceDefault(m map[string]any, key string, def []string) []string {
	if v := getStringSlice(m, key); v != nil {
		return v
	}
	return def
}

func getStringDefault(m map[string]any, key, def string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return def
}
