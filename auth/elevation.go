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
	"log"
	"net/http"
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

// defaultMaxGrants is the ceiling for concurrent elevated sessions. At
// SHA-256-per-token costs it bounds memory at roughly a few megabytes.
const defaultMaxGrants = 10_000

// ErrGrantStoreFull is returned by Grant when the active-grant cap has
// been hit. Consistent with the defensive caps used elsewhere in the
// codebase (auth-request store, token tables).
var ErrGrantStoreFull = errors.New("grant store at capacity")

// GrantStore holds time-bounded "this key is currently elevated" grants.
type GrantStore struct {
	mu        sync.Mutex
	grants    map[string]time.Time
	maxGrants int
}

// NewGrantStore returns an empty in-memory grant store with the default
// cap on concurrent active grants.
func NewGrantStore() *GrantStore {
	return &GrantStore{grants: make(map[string]time.Time), maxGrants: defaultMaxGrants}
}

// SetMaxGrants overrides the cap (primarily for tests).
func (g *GrantStore) SetMaxGrants(n int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.maxGrants = n
}

// Grant marks key as elevated until now+ttl. A second Grant for the same
// key refreshes the expiry. Returns ErrGrantStoreFull if the cap is hit
// and the key is not already present (refreshing an existing grant is
// always allowed).
func (g *GrantStore) Grant(key string, ttl time.Duration) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.grants[key]; !exists {
		// Prune expired entries opportunistically before enforcing cap.
		now := time.Now()
		for k, exp := range g.grants {
			if now.After(exp) {
				delete(g.grants, k)
			}
		}
		if g.maxGrants > 0 && len(g.grants) >= g.maxGrants {
			return ErrGrantStoreFull
		}
	}
	g.grants[key] = time.Now().Add(ttl)
	return nil
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
// IsSet() returns false and the server runs with a one-time bootstrap
// token. The operator passes that token to set_elevation_password to
// establish a password and close the bootstrap window. Clients that do
// not know the token cannot call set_elevation_password.
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

// ErrInvalidBootstrapToken is returned when SetInitial is called without
// the bootstrap token (or with a wrong value) while bootstrap mode is
// active.
var ErrInvalidBootstrapToken = errors.New("invalid or missing bootstrap token")

// PasswordStore persists the elevation password hash (and set/rotation
// timestamps) in SQLite. A non-empty envPassword overrides the stored
// password for the lifetime of this process — useful for strict-mode
// deployments that want to bypass the bootstrap window entirely.
//
// Note: if the DB already contains a stored password from a previous
// run and envPassword is also set for the current run, the stored
// password is ignored (never consulted and never deleted). Removing the
// env var on a subsequent run will restore the stored password. This
// is intentional — strict mode wins cleanly while it is in effect.
type PasswordStore struct {
	db             *sql.DB
	mu             sync.Mutex
	envPassword    string // if non-empty, used instead of stored hash
	bootstrapToken string // one-time token for initial password setup (when applicable)
}

// NewPasswordStore opens (or creates) the SQLite database at dbPath and
// prepares the elevation_password table. If envPassword is non-empty, it
// takes precedence over any stored password for this process.
//
// If the store opens in bootstrap mode (no password, no env override) a
// random bootstrap token is generated. The caller is responsible for
// surfacing it to the operator (typically via server logs) — it is
// required by SetInitial to close the bootstrap window and guards
// against a compromised OAuth client racing to seize the elevation
// password.
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

	ps := &PasswordStore{db: db, envPassword: envPassword}

	// Generate a bootstrap token if we are entering bootstrap mode.
	if envPassword == "" {
		var count int
		_ = db.QueryRow("SELECT COUNT(*) FROM elevation_password").Scan(&count)
		if count == 0 {
			ps.bootstrapToken = RandomHex(24)
		}
	}

	return ps, nil
}

// Close closes the underlying SQLite handle.
func (p *PasswordStore) Close() error {
	return p.db.Close()
}

// BootstrapToken returns the one-time token required to close the
// bootstrap window via SetInitial. Empty when bootstrap mode is not
// active (a password is already set, or the env override is in use).
func (p *PasswordStore) BootstrapToken() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bootstrapToken
}

// IsSet returns true if a password is configured — either via the env
// override or a previously-stored hash. When false, the server is in
// bootstrap mode.
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

// SetInitial stores a password only if none has been set AND the caller
// presents the correct bootstrap token. Fails with ErrPasswordAlreadySet
// if a password is already set, ErrInvalidBootstrapToken if the token is
// wrong, and ErrEmptyPassword if newPassword is empty.
func (p *PasswordStore) SetInitial(bootstrapToken, newPassword string) error {
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

	// Bootstrap token must match the one generated at construction.
	if p.bootstrapToken == "" || !SafeEqual(bootstrapToken, p.bootstrapToken) {
		return ErrInvalidBootstrapToken
	}

	salt, hash, err := derivePassword(newPassword)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	if _, err := p.db.Exec(
		`INSERT INTO elevation_password (id, hash, salt, iterations, set_at, last_rotated_at)
		 VALUES (1, ?, ?, ?, ?, ?)`,
		hash, salt, pbkdf2Iterations, now, now,
	); err != nil {
		return err
	}
	// Bootstrap is closed; the token is no longer useful and should be
	// cleared so any lingering reference in logs cannot be replayed.
	p.bootstrapToken = ""
	return nil
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
//
// Callers should gate with IsSet() before calling Verify — the
// row-absent branch short-circuits before running PBKDF2, which makes
// the "no password set" case much faster than a wrong-password case.
// If a caller uses Verify to probe whether a password is configured,
// the timing gap would leak bootstrap status. All in-tree callers
// front with IsSet(), so this is a latent hazard, not an active one.
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
	PasswordSetAt  time.Time
	LastRotatedAt  time.Time
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
	// Defense-in-depth: a zero-length or short `expected` should never
	// reach here (derivePassword always emits pbkdf2KeyLen bytes), but
	// if a DB row is ever corrupted or tampered to contain an empty
	// hash, pbkdf2.Key(..., 0) returns an empty slice and
	// subtle.ConstantTimeCompare([]byte{}, []byte{}) returns 1 — any
	// password would be accepted. Refuse.
	if len(expected) < pbkdf2KeyLen {
		return false
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
	password       *PasswordStore
	grants         *GrantStore
	ttl            time.Duration
	attemptLimiter *RateLimiter // per-token-hash brute-force guard on Elevate
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
	return &Elevation{
		password:       password,
		grants:         grants,
		ttl:            ttl,
		attemptLimiter: NewRateLimiter(5, 900), // 5 bad passwords per 15 minutes per session
	}
}

// PasswordStore returns the underlying password store (may be nil if not
// yet initialized). Exposed so tests and advanced callers can inspect it.
func (e *Elevation) PasswordStore() *PasswordStore { return e.password }

// PruneAttemptLimiter drops fully-expired entries from the
// per-session elevation attempt limiter. Safe to call periodically.
func (e *Elevation) PruneAttemptLimiter() {
	if e != nil && e.attemptLimiter != nil {
		e.attemptLimiter.PruneAll()
	}
}

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

// ErrElevationRateLimited is returned by Elevate when the caller has
// exceeded the attempt limit on this session.
var ErrElevationRateLimited = errors.New("too many elevation attempts; try again later")

// Elevate verifies the password and, on success, grants elevation to the
// token hash from ctx for the configured TTL. Returns the expiry on
// success, ErrIncorrectPassword on wrong password, ErrElevationRateLimited
// when the attempt limit is exceeded, and a descriptive error in
// bootstrap mode (where Elevate is a no-op — already elevated).
func (e *Elevation) Elevate(ctx context.Context, password string) (time.Time, error) {
	if e == nil || e.password == nil {
		return time.Time{}, errors.New("elevation not initialized")
	}
	if !e.password.IsSet() {
		// Already elevated by bootstrap rule; no grant needed.
		return time.Time{}, ErrBootstrapAlreadyElevated
	}
	hash := GetTokenHash(ctx)
	if hash == "" {
		return time.Time{}, errors.New("no session identity on context")
	}
	if e.attemptLimiter != nil && e.attemptLimiter.IsRateLimited(hash) {
		return time.Time{}, ErrElevationRateLimited
	}
	if !e.password.Verify(password) {
		if e.attemptLimiter != nil {
			e.attemptLimiter.RecordFailure(hash)
		}
		return time.Time{}, ErrIncorrectPassword
	}
	if e.attemptLimiter != nil {
		e.attemptLimiter.Clear(hash)
	}
	if err := e.grants.Grant(hash, e.ttl); err != nil {
		return time.Time{}, err
	}
	exp, _ := e.grants.ExpiresAt(hash)
	return exp, nil
}

// Middleware returns an http.Handler wrapper that stamps each request's
// context with the result of HasCurrentSession, so downstream handlers
// can call IsElevated(ctx) as the canonical check. This must be wired
// AFTER BearerMiddleware (which puts the token hash on the context).
//
// The elevation state is snapshotted ONCE at middleware entry. A tool
// handler that runs for up to WithTimeout will retain that snapshot
// even if the operator rotates the password mid-call (RevokeAll clears
// grants immediately but the in-flight ctx value is immutable). For
// long-running operations that must honor emergency revocation, re-check
// e.HasCurrentSession(ctx) periodically inside the tool. The maximum
// lag between RevokeAll and a stamped ctx becoming stale equals the
// server's request timeout.
//
// Callers must not invoke this on a nil *Elevation — guard at the call
// site (server.go does this). The nil check is intentionally absent
// here so a programming error fails loudly rather than silently
// letting requests through without elevation stamping.
func (e *Elevation) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := WithElevated(r.Context(), e.HasCurrentSession(r.Context()))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// LogBootstrapBanner emits a highly-visible log message announcing the
// bootstrap token if bootstrap mode is active. Called by the server at
// startup. No-op when not in bootstrap mode.
func (e *Elevation) LogBootstrapBanner() {
	if e == nil || e.password == nil {
		return
	}
	token := e.password.BootstrapToken()
	if token == "" {
		return
	}
	log.Printf("mcpserver: ======================================================================")
	log.Printf("mcpserver: ELEVATION BOOTSTRAP — no password set")
	log.Printf("mcpserver: Pass bootstrap_token=%q to set_elevation_password to", token)
	log.Printf("mcpserver: establish the initial elevation password. This token is single-use")
	log.Printf("mcpserver: and is regenerated on every restart while bootstrap mode is active.")
	log.Printf("mcpserver: ======================================================================")
}

// ErrBootstrapAlreadyElevated is the sentinel returned by Elevate when
// the server is in bootstrap mode (no password configured). Callers can
// check it with errors.Is to give a friendly "no password set" response.
var ErrBootstrapAlreadyElevated = errors.New("bootstrap mode: elevation granted by default")
