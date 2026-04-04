package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// OAuthStore persists OAuth 2.0 clients, auth codes, and tokens in SQLite.
// Uses pure-Go SQLite (modernc.org/sqlite) for CGO-free builds compatible
// with distroless container images.
type OAuthStore struct {
	db         *sql.DB
	mu         sync.Mutex
	maxClients int
	scope      string
}

// ClientData represents a registered OAuth client.
type ClientData struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
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

// NewOAuthStore opens (or creates) a SQLite database at dbPath for OAuth state.
// The scope parameter sets the default OAuth scope (e.g. "mcp:tools").
func NewOAuthStore(dbPath string, scope string) (*OAuthStore, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA foreign_keys=ON")

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
	scope := s.scope
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS clients (
			client_id TEXT PRIMARY KEY,
			client_secret TEXT NOT NULL,
			client_id_issued_at INTEGER NOT NULL,
			redirect_uris TEXT NOT NULL DEFAULT '[]',
			token_endpoint_auth_method TEXT DEFAULT 'client_secret_post',
			grant_types TEXT DEFAULT '["authorization_code","refresh_token"]',
			response_types TEXT DEFAULT '["code"]',
			scope TEXT DEFAULT '` + scope + `',
			client_name TEXT
		);
		CREATE TABLE IF NOT EXISTS auth_codes (
			code TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL DEFAULT '',
			code_challenge TEXT NOT NULL DEFAULT '',
			code_challenge_method TEXT DEFAULT 'S256',
			scope TEXT DEFAULT '` + scope + `',
			created_at INTEGER NOT NULL,
			FOREIGN KEY (client_id) REFERENCES clients(client_id)
		);
		CREATE TABLE IF NOT EXISTS access_tokens (
			token TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			scope TEXT DEFAULT '` + scope + `',
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS refresh_tokens (
			token TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			scope TEXT DEFAULT '` + scope + `',
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		);
	`)
	return err
}

// RegisterClient performs RFC 7591 dynamic client registration.
func (s *OAuthStore) RegisterClient(metadata map[string]any) (*ClientData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM clients").Scan(&count)
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
		clientID, clientSecret, now, string(redirectURIs), authMethod,
		string(grantTypes), string(responseTypes), scope, clientName,
	)
	if err != nil {
		return nil, err
	}

	return &ClientData{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        now,
		RedirectURIs:            getStringSlice(metadata, "redirect_uris"),
		TokenEndpointAuthMethod: authMethod,
		GrantTypes:              getStringSliceDefault(metadata, "grant_types", []string{"authorization_code", "refresh_token"}),
		ResponseTypes:           getStringSliceDefault(metadata, "response_types", []string{"code"}),
		Scope:                   scope,
		ClientName:              clientName,
	}, nil
}

// GetClient retrieves a client by ID.
func (s *OAuthStore) GetClient(clientID string) (*ClientData, error) {
	row := s.db.QueryRow("SELECT * FROM clients WHERE client_id = ?", clientID)
	var c ClientData
	var redirectURIs, grantTypes, responseTypes string
	err := row.Scan(&c.ClientID, &c.ClientSecret, &c.ClientIDIssuedAt,
		&redirectURIs, &c.TokenEndpointAuthMethod, &grantTypes, &responseTypes, &c.Scope, &c.ClientName)
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(redirectURIs), &c.RedirectURIs)
	json.Unmarshal([]byte(grantTypes), &c.GrantTypes)
	json.Unmarshal([]byte(responseTypes), &c.ResponseTypes)
	return &c, nil
}

// StoreAuthCode persists an authorization code.
func (s *OAuthStore) StoreAuthCode(code string, data AuthCodeData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge,
			code_challenge_method, scope, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		code, data.ClientID, data.RedirectURI, data.CodeChallenge,
		data.CodeChallengeMethod, data.Scope, data.CreatedAt,
	)
	return err
}

// ConsumeAuthCode atomically reads and deletes an auth code. Returns nil
// if the code doesn't exist or has expired (300-second TTL).
func (s *OAuthStore) ConsumeAuthCode(code string) (*AuthCodeData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	row := s.db.QueryRow("SELECT client_id, redirect_uri, code_challenge, code_challenge_method, scope, created_at FROM auth_codes WHERE code = ?", code)
	var d AuthCodeData
	if err := row.Scan(&d.ClientID, &d.RedirectURI, &d.CodeChallenge, &d.CodeChallengeMethod, &d.Scope, &d.CreatedAt); err != nil {
		return nil, err
	}
	s.db.Exec("DELETE FROM auth_codes WHERE code = ?", code)

	if time.Now().Unix()-d.CreatedAt > 300 {
		return nil, fmt.Errorf("auth code expired")
	}
	return &d, nil
}

// StoreAccessToken persists an access token.
func (s *OAuthStore) StoreAccessToken(token string, data TokenData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		"INSERT INTO access_tokens (token, client_id, scope, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
		token, data.ClientID, data.Scope, data.ExpiresAt, data.CreatedAt,
	)
	return err
}

// VerifyAccessToken checks whether a token is valid and not expired.
// Expired tokens are lazily deleted on verification.
func (s *OAuthStore) VerifyAccessToken(token string) bool {
	var expiresAt int64
	err := s.db.QueryRow("SELECT expires_at FROM access_tokens WHERE token = ?", token).Scan(&expiresAt)
	if err != nil {
		return false
	}
	if time.Now().Unix() > expiresAt {
		s.db.Exec("DELETE FROM access_tokens WHERE token = ?", token)
		return false
	}
	return true
}

// StoreRefreshToken persists a refresh token.
func (s *OAuthStore) StoreRefreshToken(token string, data TokenData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		"INSERT INTO refresh_tokens (token, client_id, scope, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
		token, data.ClientID, data.Scope, data.ExpiresAt, data.CreatedAt,
	)
	return err
}

// ConsumeRefreshToken atomically reads and deletes a refresh token (rotate-on-use).
func (s *OAuthStore) ConsumeRefreshToken(token string) (*TokenData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	row := s.db.QueryRow("SELECT client_id, scope, expires_at, created_at FROM refresh_tokens WHERE token = ?", token)
	var d TokenData
	if err := row.Scan(&d.ClientID, &d.Scope, &d.ExpiresAt, &d.CreatedAt); err != nil {
		return nil, err
	}
	s.db.Exec("DELETE FROM refresh_tokens WHERE token = ?", token)

	if time.Now().Unix() > d.ExpiresAt {
		return nil, fmt.Errorf("refresh token expired")
	}
	return &d, nil
}

// Cleanup removes expired auth codes, access tokens, and refresh tokens.
// Call this periodically (e.g. every 5 minutes) from a background goroutine.
func (s *OAuthStore) Cleanup() {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("DELETE FROM auth_codes WHERE created_at < ?", now-300)
	s.db.Exec("DELETE FROM access_tokens WHERE expires_at < ?", now)
	s.db.Exec("DELETE FROM refresh_tokens WHERE expires_at < ?", now)
}

// RandomHex generates n random bytes and returns them as a hex string.
func RandomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
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
