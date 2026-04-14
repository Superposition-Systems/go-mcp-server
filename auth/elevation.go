package auth

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// -----------------------------------------------------------------------------
// GrantStore: in-memory TTL-keyed permission slips.
//
// Kept in memory deliberately — a restart is a security event that should
// revoke all elevations. Keys are arbitrary strings, typically the hex
// SHA-256 of a bearer token (see TokenHash).
// -----------------------------------------------------------------------------

// GrantStore holds time-bounded "this key is currently elevated" grants.
type GrantStore struct {
	mu     sync.Mutex
	grants map[string]time.Time
}

// NewGrantStore returns an empty in-memory grant store.
func NewGrantStore() *GrantStore {
	return &GrantStore{grants: make(map[string]time.Time)}
}

// Grant marks key as elevated until now+ttl. A second Grant for the same
// key refreshes the expiry.
func (g *GrantStore) Grant(key string, ttl time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.grants[key] = time.Now().Add(ttl)
}

// Has returns true if the key has an unexpired grant. Expired grants are
// cleaned opportunistically on access.
func (g *GrantStore) Has(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	exp, ok := g.grants[key]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(g.grants, key)
		return false
	}
	return true
}

// ExpiresAt returns the expiry time and true if the key is elevated.
// Returns zero time and false otherwise.
func (g *GrantStore) ExpiresAt(key string) (time.Time, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	exp, ok := g.grants[key]
	if !ok || time.Now().After(exp) {
		if ok {
			delete(g.grants, key)
		}
		return time.Time{}, false
	}
	return exp, true
}

// Revoke removes the grant for a single key.
func (g *GrantStore) Revoke(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.grants, key)
}

// RevokeAll clears every active grant. Called on password rotation.
func (g *GrantStore) RevokeAll() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.grants = make(map[string]time.Time)
}

// ActiveCount returns the number of currently-active grants, pruning
// expired entries as a side effect.
func (g *GrantStore) ActiveCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for k, exp := range g.grants {
		if now.After(exp) {
			delete(g.grants, k)
		}
	}
	return len(g.grants)
}

// -----------------------------------------------------------------------------
// PasswordStore: on-disk hashed elevation password with bootstrap semantics.
//
// Bootstrap rule: if no password is stored and no env-var override is set,
// IsSet() returns false and callers should treat the session as elevated by
// default. The first SetInitial call establishes a password and closes the
// bootstrap window.
//
// Hashing: PBKDF2-SHA256 with 600k iterations (matches modern browser
// defaults for password storage). Uses stdlib crypto/pbkdf2 (Go 1.24+).
// -----------------------------------------------------------------------------

const (
	pbkdf2Iterations = 600_000
	pbkdf2KeyLen     = 32
	pbkdf2SaltLen    = 16
)

// ErrPasswordAlreadySet is returned by SetInitial when a password exists.
var ErrPasswordAlreadySet = errors.New("elevation password already set; use Rotate to change it")

// ErrPasswordNotSet is returned by Rotate when no password has been set yet.
var ErrPasswordNotSet = errors.New("no elevation password set; use SetInitial")

// ErrIncorrectPassword is returned by Verify and Rotate on mismatch.
var ErrIncorrectPassword = errors.New("incorrect elevation password")

// ErrEmptyPassword is returned when a caller tries to set an empty password.
var ErrEmptyPassword = errors.New("elevation password cannot be empty")

// PasswordStore persists the elevation password hash (and set/rotation
// timestamps) in SQLite. A non-empty envPassword overrides the stored
// password for the lifetime of this process — useful for strict-mode
// deployments that want to bypass the bootstrap window entirely.
type PasswordStore struct {
	db          *sql.DB
	mu          sync.Mutex
	envPassword string // if non-empty, used instead of stored hash
}

// NewPasswordStore opens (or creates) the SQLite database at dbPath and
// prepares the elevation_password table. If envPassword is non-empty, it
// takes precedence over any stored password for this process — IsSet will
// return true, Verify will compare against envPassword, and SetInitial /
// Rotate will return an error (rotation in strict-mode deployments is an
// infrastructure operation, not a runtime one).
func NewPasswordStore(dbPath, envPassword string) (*PasswordStore, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create elevation db directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open elevation sqlite: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	db.SetMaxOpenConns(1)

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS elevation_password (
			id             INTEGER PRIMARY KEY CHECK (id = 1),
			hash           BLOB NOT NULL,
			salt           BLOB NOT NULL,
			iterations     INTEGER NOT NULL,
			set_at         INTEGER NOT NULL,
			last_rotated_at INTEGER NOT NULL
		);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create elevation_password table: %w", err)
	}

	return &PasswordStore{db: db, envPassword: envPassword}, nil
}

// Close closes the underlying SQLite handle.
func (p *PasswordStore) Close() error {
	return p.db.Close()
}

// IsSet returns true if a password is configured — either via the env
// override or a previously-stored hash. When false, the server is in
// bootstrap mode and callers should treat sessions as elevated by default.
func (p *PasswordStore) IsSet() bool {
	if p.envPassword != "" {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var count int
	_ = p.db.QueryRow("SELECT COUNT(*) FROM elevation_password").Scan(&count)
	return count > 0
}

// SetInitial stores a password only if none has been set. Fails with
// ErrPasswordAlreadySet if one already exists or the env override is in use.
func (p *PasswordStore) SetInitial(newPassword string) error {
	if newPassword == "" {
		return ErrEmptyPassword
	}
	if p.envPassword != "" {
		return ErrPasswordAlreadySet
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	var count int
	if err := p.db.QueryRow("SELECT COUNT(*) FROM elevation_password").Scan(&count); err != nil {
		return fmt.Errorf("count elevation rows: %w", err)
	}
	if count > 0 {
		return ErrPasswordAlreadySet
	}

	salt, hash, err := derivePassword(newPassword)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = p.db.Exec(
		`INSERT INTO elevation_password (id, hash, salt, iterations, set_at, last_rotated_at)
		 VALUES (1, ?, ?, ?, ?, ?)`,
		hash, salt, pbkdf2Iterations, now, now,
	)
	return err
}

// Rotate replaces the stored password. Requires the correct current
// password. Returns ErrPasswordNotSet if called in bootstrap mode (use
// SetInitial), ErrIncorrectPassword if current doesn't match, and
// ErrPasswordAlreadySet if the env override is in use.
func (p *PasswordStore) Rotate(currentPassword, newPassword string) error {
	if newPassword == "" {
		return ErrEmptyPassword
	}
	if p.envPassword != "" {
		// Strict-mode deployments rotate via infrastructure, not runtime.
		return ErrPasswordAlreadySet
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	hash, salt, iter, err := p.loadLocked()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPasswordNotSet
		}
		return err
	}
	if !verifyPassword(currentPassword, salt, hash, iter) {
		return ErrIncorrectPassword
	}

	newSalt, newHash, err := derivePassword(newPassword)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = p.db.Exec(
		`UPDATE elevation_password
		    SET hash = ?, salt = ?, iterations = ?, last_rotated_at = ?
		  WHERE id = 1`,
		newHash, newSalt, pbkdf2Iterations, now,
	)
	return err
}

// Verify returns true if password matches the configured secret. Returns
// false in bootstrap mode (no password means nothing to verify against).
func (p *PasswordStore) Verify(password string) bool {
	if p.envPassword != "" {
		return SafeEqual(password, p.envPassword)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	hash, salt, iter, err := p.loadLocked()
	if err != nil {
		return false
	}
	return verifyPassword(password, salt, hash, iter)
}

// ElevationStatus is the timestamp snapshot returned by Status.
type ElevationStatus struct {
	PasswordSetAt time.Time
	LastRotatedAt time.Time
	ViaEnvOverride bool
}

// Status returns timestamps for when the password was first set and most
// recently rotated. Returns nil in bootstrap mode so callers can decide
// whether to surface anything.
func (p *PasswordStore) Status() *ElevationStatus {
	if p.envPassword != "" {
		// The env override has no persistent timestamps; report "now" as
		// a reasonable proxy for "since this process started."
		return &ElevationStatus{
			PasswordSetAt:  time.Time{},
			LastRotatedAt:  time.Time{},
			ViaEnvOverride: true,
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var setAt, rotAt int64
	err := p.db.QueryRow("SELECT set_at, last_rotated_at FROM elevation_password WHERE id = 1").
		Scan(&setAt, &rotAt)
	if err != nil {
		return nil
	}
	return &ElevationStatus{
		PasswordSetAt: time.Unix(setAt, 0).UTC(),
		LastRotatedAt: time.Unix(rotAt, 0).UTC(),
	}
}

// loadLocked reads the single row. Caller must hold p.mu.
func (p *PasswordStore) loadLocked() (hash, salt []byte, iter int, err error) {
	err = p.db.QueryRow(
		"SELECT hash, salt, iterations FROM elevation_password WHERE id = 1",
	).Scan(&hash, &salt, &iter)
	return
}

// -----------------------------------------------------------------------------
// Hashing helpers
// -----------------------------------------------------------------------------

func derivePassword(password string) (salt, hash []byte, err error) {
	salt = make([]byte, pbkdf2SaltLen)
	if _, err = rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("read salt: %w", err)
	}
	hash, err = pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("derive key: %w", err)
	}
	return salt, hash, nil
}

func verifyPassword(password string, salt, expected []byte, iter int) bool {
	if iter <= 0 {
		iter = pbkdf2Iterations
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(expected))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, expected) == 1
}

// HashToHex returns a hex representation of a salt or hash for logging
// (never log full secrets — this is for developer inspection of the DB).
func HashToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// -----------------------------------------------------------------------------
// Elevation: the composed interface the server exposes to apps.
//
// Apps query this to decide whether a request counts as elevated. The
// server wires the two stores together and hands this handle out via
// Server.Elevation().
// -----------------------------------------------------------------------------

// Elevation composes the password and grant stores with the configured TTL
// and exposes the high-level checks the server and apps need. Safe to call
// before ListenAndServe — Status() and HasCurrentSession() return
// sensible zero values until the stores are opened.
type Elevation struct {
	password *PasswordStore
	grants   *GrantStore
	ttl      time.Duration
}

// NewElevation composes the two stores. The password store may be nil to
// indicate the stores haven't been opened yet (see lazy init in server.go).
func NewElevation(password *PasswordStore, grants *GrantStore, ttl time.Duration) *Elevation {
	if grants == nil {
		grants = NewGrantStore()
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Elevation{password: password, grants: grants, ttl: ttl}
}

// PasswordStore returns the underlying password store (may be nil if not
// yet initialized). Exposed so tests and advanced callers can inspect it.
func (e *Elevation) PasswordStore() *PasswordStore { return e.password }

// GrantStore returns the underlying grant store.
func (e *Elevation) GrantStore() *GrantStore { return e.grants }

// TTL returns the configured grant duration.
func (e *Elevation) TTL() time.Duration { return e.ttl }

// IsBootstrap reports whether the server is in bootstrap mode (no password
// configured anywhere). Returns false if the Elevation is nil or the
// password store hasn't been opened yet — safer to treat "unknown" as
// "not bootstrap" so the caller doesn't accidentally grant free access.
func (e *Elevation) IsBootstrap() bool {
	if e == nil || e.password == nil {
		return false
	}
	return !e.password.IsSet()
}

// HasCurrentSession returns true if the context represents an elevated
// session. In bootstrap mode, every authenticated session is elevated. In
// normal mode, the context's token hash must have an active grant.
func (e *Elevation) HasCurrentSession(ctx context.Context) bool {
	if e == nil || e.password == nil {
		return false
	}
	if !e.password.IsSet() {
		return true // bootstrap — everyone authenticated is elevated
	}
	hash := GetTokenHash(ctx)
	if hash == "" {
		return false
	}
	return e.grants.Has(hash)
}

// Elevate verifies the password and, on success, grants elevation to the
// token hash from ctx for the configured TTL. Returns the expiry on
// success, ErrIncorrectPassword on wrong password, and a descriptive
// error in bootstrap mode (where Elevate is a no-op — already elevated).
func (e *Elevation) Elevate(ctx context.Context, password string) (time.Time, error) {
	if e == nil || e.password == nil {
		return time.Time{}, errors.New("elevation not initialized")
	}
	if !e.password.IsSet() {
		// Already elevated by bootstrap rule; no grant needed.
		return time.Time{}, errBootstrapAlreadyElevated
	}
	if !e.password.Verify(password) {
		return time.Time{}, ErrIncorrectPassword
	}
	hash := GetTokenHash(ctx)
	if hash == "" {
		return time.Time{}, errors.New("no session identity on context")
	}
	e.grants.Grant(hash, e.ttl)
	exp, _ := e.grants.ExpiresAt(hash)
	return exp, nil
}

// errBootstrapAlreadyElevated is a sentinel used by Elevate; callers can
// check it with errors.Is to give a friendly "no password set" response.
var errBootstrapAlreadyElevated = errors.New("bootstrap mode: elevation granted by default")

// ErrBootstrapAlreadyElevated is the public sentinel for the Elevate-in-
// bootstrap-mode case.
var ErrBootstrapAlreadyElevated = errBootstrapAlreadyElevated
