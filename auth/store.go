package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	// 0700 on the parent directory is the primary protection: without
	// execute-bit access, no other UID can stat the DB or its WAL/SHM
	// sidecars regardless of what mode SQLite ends up creating them
	// with. The 0600 on the main file below is defense-in-depth for
	// bind-mount / volume-copy scenarios where only the file (not the
	// directory mode) is preserved.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}
	// Re-apply the mode in case the directory already existed with a
	// looser permission (e.g., MkdirAll is a no-op on existing dirs).
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("chmod db directory: %w", err)
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

	// Tighten the DB file mode AFTER the first write (createTables) —
	// SQLite creates the file lazily, and writes the WAL/SHM sidecars
	// on the journal_mode PRAGMA. Chmod'ing earlier fails on a file
	// that doesn't exist yet. 0644 is the typical default under a
	// container umask; a world-readable DB leaks metadata (client_ids,
	// issuance timestamps) even though the secrets themselves are
	// SHA-256 hashed. Sidecar chmods are best-effort; the 0700 on the
	// parent directory is the primary access barrier.
	if err := os.Chmod(dbPath, 0600); err != nil {
		db.Close()
		return nil, fmt.Errorf("chmod db file: %w", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Chmod(dbPath+suffix, 0600) // may not exist yet; ignore
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
		-- Indexes on the columns Cleanup scans, so the periodic
		-- DELETE-WHERE does not degrade to a full table scan at cap.
		CREATE INDEX IF NOT EXISTS idx_auth_codes_created_at     ON auth_codes(created_at);
		CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at  ON access_tokens(expires_at);
		CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
		CREATE INDEX IF NOT EXISTS idx_auth_requests_created_at  ON auth_requests(created_at);
		-- Schema version checkpoint. Carries a single row. Future
		-- library versions that change the schema will read this
		-- value, run migrations up to currentSchemaVersion, and write
		-- the new version back. This release does no migrations — it
		-- only establishes the checkpoint.
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER NOT NULL
		);
	`)
	if err != nil {
		return err
	}
	return s.initSchemaVersion()
}

// currentSchemaVersion is the schema revision written into schema_version
// on fresh databases. Bump in lockstep with any change to createTables.
const currentSchemaVersion = 1

// initSchemaVersion ensures schema_version has exactly one row. An
// empty table (fresh DB, or DB created before this table existed) gets
// seeded with currentSchemaVersion. A populated table is left alone —
// we do not downgrade or overwrite a version that a future release may
// have already bumped.
func (s *OAuthStore) initSchemaVersion() error {
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM schema_version").Scan(&count); err != nil {
		return fmt.Errorf("read schema_version: %w", err)
	}
	if count == 0 {
		if _, err := s.db.Exec("INSERT INTO schema_version (version) VALUES (?)", currentSchemaVersion); err != nil {
			return fmt.Errorf("seed schema_version: %w", err)
		}
	}
	return nil
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
//
// The SELECT names every column explicitly rather than SELECT * so the
// column order is bound to this source file, not to whatever order the
// schema happens to have on a given deployment. Without this, adding
// or reordering columns in createTables (or any future migration) would
// misalign the positional Scan and surface as a spurious "scan failed"
// error that callers already map to "Unknown client_id."
func (s *OAuthStore) GetClient(clientID string) (*ClientData, error) {
	row := s.db.QueryRow(
		`SELECT client_id, client_secret, client_id_issued_at,
			redirect_uris, token_endpoint_auth_method, grant_types,
			response_types, scope, client_name
		 FROM clients WHERE client_id = ?`, clientID)
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

// dummyClientSecretHash is a 64-character hex string generated fresh
// at package-init time, used as the comparand on the unknown-client
// branch of VerifyClientSecret. A distinct, random, real-looking dummy
// (rather than a self-compare or a recognizable constant like all
// zeros) prevents any compiler or CPU short-path from folding the
// compare to a constant result.
var dummyClientSecretHash = RandomHex(32)

// VerifyClientSecret returns true if the presented secret matches the
// hash stored for clientID.
//
// CPU-level work is equalized across the known-vs-unknown-client_id
// branches: hashSecret runs unconditionally, and the constant-time
// compare runs in both branches against a value of the same length. A
// small timing gap remains from the DB SELECT itself (index hit vs miss
// on an indexed PRIMARY KEY is microseconds) — that is a property of
// SQLite, not of this code, and is orders of magnitude smaller than the
// hashSecret work it now follows. For fully uniform timing a
// full-register approach (always select + always ignore) would be
// needed; we have judged the remaining gap acceptable.
func (s *OAuthStore) VerifyClientSecret(clientID, secret string) bool {
	// Hash unconditionally so both branches pay the hash cost.
	presented := hashSecret(secret)

	var storedHash string
	err := s.db.QueryRow("SELECT client_secret FROM clients WHERE client_id = ?", clientID).Scan(&storedHash)
	if err != nil {
		// Burn the same constant-time compare against a distinct
		// dummy so the compiler cannot fold self-compares to true.
		_ = subtle.ConstantTimeCompare([]byte(presented), []byte(dummyClientSecretHash))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(storedHash)) == 1
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

// ConsumeAuthCode atomically reads and deletes an auth code. Returns
// (nil, err) if the code doesn't exist (err will be sql.ErrNoRows) or
// has expired (300-second TTL). A successful consume returns the
// decoded AuthCodeData with a nil error. Callers must check err, not
// just the pointer.
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

// RevokeToken deletes the given token (access or refresh) from the
// store if it is bound to expectedClientID. Returns nil if a row was
// deleted OR if no matching row existed — per RFC 7009 §2.2, the
// response to /revoke is indistinguishable between "unknown token"
// and "revoked successfully." A returned error therefore always
// represents a store-level failure, not a token-not-found condition.
//
// The client binding check prevents one DCR'd client from revoking
// another client's tokens by guessing or replaying values.
func (s *OAuthStore) RevokeToken(token, expectedClientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hashed := hashSecret(token)
	// Delete from both tables; at most one will match because the two
	// key spaces are independent hex-SHA-256 digests of unrelated
	// random secrets. The client_id predicate is the authorization
	// check — a mismatched client silently deletes nothing.
	if _, err := s.db.Exec(
		"DELETE FROM access_tokens WHERE token = ? AND client_id = ?",
		hashed, expectedClientID,
	); err != nil {
		return fmt.Errorf("revoke access token: %w", err)
	}
	if _, err := s.db.Exec(
		"DELETE FROM refresh_tokens WHERE token = ? AND client_id = ?",
		hashed, expectedClientID,
	); err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	return nil
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

// cleanupBatchSize caps how many rows a single DELETE statement removes
// so the per-batch lock hold on s.mu stays bounded regardless of how
// many rows are expired. Cleanup releases and re-acquires s.mu between
// batches so auth requests are not blocked for seconds on large sweeps.
const cleanupBatchSize = 1000

// Cleanup removes expired auth codes, access tokens, refresh tokens,
// and auth requests in small batches, releasing the store mutex
// between batches. Call periodically (e.g. every 5 minutes) from a
// background goroutine.
func (s *OAuthStore) Cleanup() error {
	now := time.Now().Unix()
	if err := s.cleanupBatched(
		"DELETE FROM auth_codes WHERE rowid IN (SELECT rowid FROM auth_codes WHERE created_at < ? LIMIT ?)",
		now-300,
	); err != nil {
		return fmt.Errorf("cleanup auth codes: %w", err)
	}
	if err := s.cleanupBatched(
		"DELETE FROM access_tokens WHERE rowid IN (SELECT rowid FROM access_tokens WHERE expires_at < ? LIMIT ?)",
		now,
	); err != nil {
		return fmt.Errorf("cleanup access tokens: %w", err)
	}
	if err := s.cleanupBatched(
		"DELETE FROM refresh_tokens WHERE rowid IN (SELECT rowid FROM refresh_tokens WHERE expires_at < ? LIMIT ?)",
		now,
	); err != nil {
		return fmt.Errorf("cleanup refresh tokens: %w", err)
	}
	if err := s.cleanupBatched(
		"DELETE FROM auth_requests WHERE rowid IN (SELECT rowid FROM auth_requests WHERE created_at < ? LIMIT ?)",
		now-600,
	); err != nil {
		return fmt.Errorf("cleanup auth requests: %w", err)
	}
	return nil
}

func (s *OAuthStore) cleanupBatched(query string, threshold int64) error {
	for {
		s.mu.Lock()
		res, err := s.db.Exec(query, threshold, cleanupBatchSize)
		s.mu.Unlock()
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n < cleanupBatchSize {
			return nil
		}
	}
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
