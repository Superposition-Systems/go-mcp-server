// Package config provides a SQLite-backed key-value store with a precedence
// chain (SQLite → credentials file → env) and write-through to an optional
// credentials file, plus auto-registered config tools. See §4.8 + §3.8 of
// docs/plans/v0.8.0-middleware-and-registry.md.
//
// Precedence on Get:
//  1. SQLite (source of truth)
//  2. CredentialsFile on disk (re-read each call; file may be edited
//     out-of-band by operators)
//  3. os.Getenv (only when Options.EnvFallback is true; values read from
//     env are not copied into SQLite)
//
// On Open, any SQLite row whose key maps to an empty env var backfills
// os.Setenv(key, value). This mirrors the Node `lib/config-db.js:seedConfig`
// behaviour so app code that reads config via os.Getenv (rather than through
// this package) still sees the SQLite-resolved values.
//
// Set and Delete write through to CredentialsFile (when configured) by
// atomically rewriting the whole file from the current SQLite table:
// write to "<path>.tmp" then os.Rename, which is atomic on POSIX filesystems.
// SQLite is the source of truth — a SQLite write error aborts the operation
// and the credentials file is left untouched.
//
// SECURITY NOTE: The auto-registered tools (config_get / config_set /
// config_list / config_delete) are deliberately un-gated. Track 3 (diag
// tools) handles elevation for its own tools; config tools are part of
// the server-config surface and are typically exposed only to operators.
// Consumers that want to require step-up authentication should wrap these
// tools with their own elevation middleware (see the auth.Elevation helpers).
// config_list returns keys only (never values) so that the tool's output
// is safe to surface in LLM-visible chat logs even when values are secrets.
package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	mcp "github.com/Superposition-Systems/go-mcp-server"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, CGO-free
)

// Options configures a Store. DBPath is required; pass ":memory:" for
// ephemeral tests. CredentialsFile enables write-through to a KEY=VALUE
// text file. EnvFallback enables os.Getenv as the last-resort resolver
// on Get; it does not control the env-backfill behaviour on Open (that
// always runs).
type Options struct {
	// DBPath is the SQLite database path. Required. ":memory:" is supported.
	DBPath string
	// CredentialsFile is an optional KEY=VALUE text file that Open seeds
	// from and Set / Delete write through to. Empty disables the file
	// integration.
	CredentialsFile string
	// EnvFallback, when true, consults os.Getenv on Get when SQLite and
	// the credentials file both miss. Env values are never copied into
	// SQLite. The "mirror SQLite to env on Open" behaviour is independent
	// and always runs.
	EnvFallback bool
}

// Store is the configuration key-value handle backed by SQLite with
// optional credentials-file write-through and env fallback on Get.
//
// All methods are safe for concurrent use.
type Store struct {
	mu     sync.Mutex
	db     *sql.DB
	opts   Options
	closed bool
}

// credLine is one parsed line of a CredentialsFile. Used internally to
// preserve insertion order when rewriting the file.
type credLine struct {
	key   string
	value string
}

// Open opens (or creates) a SQLite database at opts.DBPath and returns a
// ready-to-use Store. If opts.CredentialsFile is set and the file exists,
// any keys in the file that are NOT already in SQLite are seeded into
// SQLite. Existing SQLite rows take precedence and are never overwritten
// by file contents.
//
// After seeding, Open mirrors every SQLite row into the process
// environment via os.Setenv — but only for keys whose env var is
// currently empty, so caller-provided env vars are never clobbered.
//
// Returns an error if DBPath is empty, if SQLite cannot be opened, if
// the schema cannot be created, or if the credentials file exists but
// is malformed in a way that prevents parsing the entire file.
func Open(opts Options) (*Store, error) {
	if opts.DBPath == "" {
		return nil, errors.New("config.Open: DBPath is required")
	}

	// sql.Open is lazy; it does not actually touch the file until the
	// first query. A later Exec will surface I/O errors.
	db, err := sql.Open("sqlite", opts.DBPath)
	if err != nil {
		return nil, fmt.Errorf("config.Open: open sqlite: %w", err)
	}

	// SQLite supports a single writer at a time; pinning to one
	// connection avoids lock contention from the database/sql pool and
	// matches the pattern used by the auth.OAuthStore.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS config (
			key        TEXT PRIMARY KEY,
			value      TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		);
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("config.Open: create table: %w", err)
	}

	s := &Store{db: db, opts: opts}

	// Seed from credentials file (if configured and present). Missing
	// file is not an error — it may simply not exist yet on first boot.
	if opts.CredentialsFile != "" {
		if err := s.seedFromFile(); err != nil {
			db.Close()
			return nil, err
		}
	}

	// Env-backfill: mirror SQLite rows to os.Setenv for keys whose env
	// var is currently empty.
	if err := s.backfillEnv(); err != nil {
		db.Close()
		return nil, err
	}

	return s, nil
}

// seedFromFile parses CredentialsFile and inserts any keys that are NOT
// already present in SQLite. A missing file is not an error.
func (s *Store) seedFromFile() error {
	entries, err := readCredentialsFile(s.opts.CredentialsFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("config.Open: read credentials file: %w", err)
	}

	now := time.Now().Unix()
	for _, e := range entries {
		// INSERT OR IGNORE preserves existing SQLite rows — file values
		// only seed missing keys, never overwrite.
		if _, err := s.db.Exec(
			"INSERT OR IGNORE INTO config (key, value, updated_at) VALUES (?, ?, ?)",
			e.key, e.value, now,
		); err != nil {
			return fmt.Errorf("config.Open: seed %q: %w", e.key, err)
		}
	}
	return nil
}

// backfillEnv mirrors every SQLite row into os.Setenv when the
// corresponding env var is currently empty. This is the
// "SQLite wins but env mirrors it" behaviour app code relies on.
func (s *Store) backfillEnv() error {
	rows, err := s.db.Query("SELECT key, value FROM config")
	if err != nil {
		return fmt.Errorf("config.Open: backfill env query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return fmt.Errorf("config.Open: backfill env scan: %w", err)
		}
		if os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("config.Open: backfill env iter: %w", err)
	}
	return nil
}

// Get returns the value for key and whether it was found. Precedence:
// SQLite, then (if CredentialsFile is set) the file on disk re-read
// fresh, then (if EnvFallback) os.Getenv. Returns ("", false) on miss
// across every source.
func (s *Store) Get(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. SQLite.
	if v, ok, _ := s.getFromDB(key); ok {
		return v, true
	}

	// 2. Credentials file (re-read fresh each call — an operator may
	// have edited the file out-of-band since the last call).
	if s.opts.CredentialsFile != "" {
		if v, ok := getFromFile(s.opts.CredentialsFile, key); ok {
			return v, true
		}
	}

	// 3. Env var.
	if s.opts.EnvFallback {
		if v := os.Getenv(key); v != "" {
			return v, true
		}
	}

	return "", false
}

// getFromDB reads a key from SQLite. The bool is false on sql.ErrNoRows;
// the error is returned for any other DB-level failure (corruption,
// closed DB, etc.) but Get treats it as a miss.
func (s *Store) getFromDB(key string) (string, bool, error) {
	var v string
	err := s.db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&v)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	return v, true, nil
}

// Set stores key=value in SQLite (UPSERT with updated_at = now) and, if
// CredentialsFile is configured, atomically rewrites the file to reflect
// the full current SQLite table. SQLite is the source of truth: a SQLite
// write error aborts and the file is left unchanged.
func (s *Store) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	if _, err := s.db.Exec(
		`INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, now,
	); err != nil {
		return fmt.Errorf("config.Set: %w", err)
	}

	if s.opts.CredentialsFile != "" {
		if err := s.rewriteCredentialsFile(); err != nil {
			return fmt.Errorf("config.Set: rewrite credentials file: %w", err)
		}
	}
	return nil
}

// Delete removes key from SQLite (idempotent — absence is not an error)
// and, if CredentialsFile is configured, atomically rewrites the file.
func (s *Store) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.db.Exec("DELETE FROM config WHERE key = ?", key); err != nil {
		return fmt.Errorf("config.Delete: %w", err)
	}

	if s.opts.CredentialsFile != "" {
		if err := s.rewriteCredentialsFile(); err != nil {
			return fmt.Errorf("config.Delete: rewrite credentials file: %w", err)
		}
	}
	return nil
}

// List returns a copy of the SQLite table as a map. Does NOT merge
// the credentials file or environment — callers that want the merged
// view call Get per key.
func (s *Store) List() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := map[string]string{}
	rows, err := s.db.Query("SELECT key, value FROM config")
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		out[k] = v
	}
	return out
}

// rewriteCredentialsFile atomically writes CredentialsFile from the
// current SQLite table. Content is sorted by key so repeated writes are
// deterministic. Writes go to "<path>.tmp" then os.Rename — on POSIX
// the rename is atomic, so a crash mid-write leaves either the previous
// complete file or the new complete file, never a partial blob.
//
// Caller must hold s.mu.
func (s *Store) rewriteCredentialsFile() error {
	rows, err := s.db.Query("SELECT key, value FROM config ORDER BY key")
	if err != nil {
		return fmt.Errorf("read all rows: %w", err)
	}
	var buf strings.Builder
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return fmt.Errorf("scan row: %w", err)
		}
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(v)
		buf.WriteByte('\n')
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate rows: %w", err)
	}

	path := s.opts.CredentialsFile
	tmp := path + ".tmp"

	// Ensure the parent directory exists. 0700 mirrors the auth store
	// convention — credentials files should never be world-readable.
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("mkdir parent: %w", err)
		}
	}

	// 0600: credentials file is readable only by the owning UID.
	if err := os.WriteFile(tmp, []byte(buf.String()), 0600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		// Best-effort cleanup so a stale .tmp does not accumulate.
		_ = os.Remove(tmp)
		return fmt.Errorf("rename tmp: %w", err)
	}
	return nil
}

// readCredentialsFile parses a KEY=VALUE text file. Comments start with
// '#' and are ignored; blank lines are ignored; malformed lines
// (no '=') are silently skipped. Returns an ordered slice so callers
// can preserve insertion order when useful.
func readCredentialsFile(path string) ([]credLine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []credLine
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			// No '=' or empty key — skip.
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := line[idx+1:]
		if key == "" {
			continue
		}
		out = append(out, credLine{key: key, value: value})
	}
	return out, nil
}

// getFromFile reads path and returns the value for key, if present.
// Returns ("", false) for missing file or missing key.
func getFromFile(path, key string) (string, bool) {
	entries, err := readCredentialsFile(path)
	if err != nil {
		return "", false
	}
	// Later entries override earlier ones (match shell-dotenv semantics).
	var hit string
	var found bool
	for _, e := range entries {
		if e.key == key {
			hit = e.value
			found = true
		}
	}
	return hit, found
}

// RegisterTools registers config_get / config_set / config_list /
// config_delete on the given Registry. The tools are un-gated — see the
// package doc comment for the rationale and for the recommended
// elevation wrapping.
func (s *Store) RegisterTools(r *mcp.Registry) error {
	if r == nil {
		return errors.New("config.RegisterTools: nil registry")
	}

	tools := []mcp.Tool{
		{
			Name:        "config_get",
			Description: "Read a configuration value. Returns the resolved value and the source it was resolved from (sqlite, file, env, or missing).",
			Category:    "config",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"key": {"type": "string", "description": "config key to look up"}
				},
				"required": ["key"],
				"additionalProperties": false
			}`),
			Handler: s.handleGet,
		},
		{
			Name:        "config_set",
			Description: "Write a configuration value. Persists to SQLite and (if configured) the credentials file.",
			Category:    "config",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"key":   {"type": "string", "description": "config key to write"},
					"value": {"type": "string", "description": "config value to store"}
				},
				"required": ["key", "value"],
				"additionalProperties": false
			}`),
			Handler: s.handleSet,
		},
		{
			Name:        "config_list",
			Description: "List every configured key. Values are NOT returned — they may be secrets.",
			Category:    "config",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {},
				"additionalProperties": false
			}`),
			Handler: s.handleList,
		},
		{
			Name:        "config_delete",
			Description: "Delete a configuration value. Idempotent — absent keys succeed silently.",
			Category:    "config",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"key": {"type": "string", "description": "config key to delete"}
				},
				"required": ["key"],
				"additionalProperties": false
			}`),
			Handler: s.handleDelete,
		},
	}

	for _, t := range tools {
		if err := r.Register(t); err != nil {
			return fmt.Errorf("config.RegisterTools: register %q: %w", t.Name, err)
		}
	}
	return nil
}

// handleGet implements the config_get tool. Returns a map with "value"
// and "source" (one of "sqlite", "file", "env", "missing").
func (s *Store) handleGet(_ context.Context, args map[string]any) (any, error) {
	key, _ := args["key"].(string)
	if key == "" {
		return nil, errors.New("config_get: missing or empty 'key'")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if v, ok, _ := s.getFromDB(key); ok {
		return map[string]any{"value": v, "source": "sqlite"}, nil
	}
	if s.opts.CredentialsFile != "" {
		if v, ok := getFromFile(s.opts.CredentialsFile, key); ok {
			return map[string]any{"value": v, "source": "file"}, nil
		}
	}
	if s.opts.EnvFallback {
		if v := os.Getenv(key); v != "" {
			return map[string]any{"value": v, "source": "env"}, nil
		}
	}
	return map[string]any{"value": "", "source": "missing"}, nil
}

// handleSet implements the config_set tool.
func (s *Store) handleSet(_ context.Context, args map[string]any) (any, error) {
	key, _ := args["key"].(string)
	value, _ := args["value"].(string)
	if key == "" {
		return nil, errors.New("config_set: missing or empty 'key'")
	}
	if err := s.Set(key, value); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

// handleList implements the config_list tool. Returns keys only (never
// values) so the tool's output is safe to log even when values are
// secrets.
func (s *Store) handleList(_ context.Context, _ map[string]any) (any, error) {
	m := s.List()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return map[string]any{"keys": keys}, nil
}

// handleDelete implements the config_delete tool.
func (s *Store) handleDelete(_ context.Context, args map[string]any) (any, error) {
	key, _ := args["key"].(string)
	if key == "" {
		return nil, errors.New("config_delete: missing or empty 'key'")
	}
	if err := s.Delete(key); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

// Close releases the SQLite connection. Idempotent — a second Close on
// an already-closed Store returns nil.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}
