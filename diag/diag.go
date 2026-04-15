// Package diag provides a diagnostic logger with a SQLite ring-buffer
// backend and an slog.Handler adapter, plus a tool-call middleware and
// auto-registered log-query tools. See §4.7 of the v0.8.0 plan.
//
// The diagnostic log database is separate from the OAuth database (see
// §3.5 of the plan): log volume is orders of magnitude higher than auth
// writes, and mixing them would contend for the single-writer SQLite
// connection the auth module enforces.
//
// All log writes are best-effort. Errors on the write path are
// swallowed (with a throttled warning to the standard logger) so a
// storage failure cannot fail an in-flight tool call.
package diag

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mcp "github.com/Superposition-Systems/go-mcp-server"

	_ "modernc.org/sqlite"
)

// Config configures a diagnostic Logger.
type Config struct {
	// DBPath is the SQLite file path for diagnostic logs.
	// Default "/data/server-logs.db". The special value ":memory:" uses
	// an in-memory database (useful for tests and ephemeral servers).
	DBPath string

	// RingSize is the maximum number of rows retained in the logs table.
	// After each insert, the oldest rows are deleted until the count is
	// at most RingSize. Default 50_000 when zero.
	RingSize int

	// Categories is the set of known log categories. Kept for
	// documentation; the logger does not refuse writes with other
	// category names. Default: request, tool, auth, api, lifecycle, error.
	Categories []string

	// AutoRegisterTools, when true, causes RegisterTools to install
	// server_get_logs, server_get_stats, and server_clear_logs on the
	// supplied Registry.
	//
	// Note: Go's zero value for bool is false. The plan documents the
	// default as "true" to match the Node precedent, but this library
	// cannot distinguish "unset" from "explicit false". Callers who want
	// the Node default must set AutoRegisterTools: true explicitly. If
	// this field is false, RegisterTools is a no-op.
	AutoRegisterTools bool

	// ElevationRequired is reserved for a future convention (plan §9
	// item 2). In v0.8.0 the server does not enforce elevation on the
	// log tools; consumers who need to restrict log access must gate the
	// tools externally (e.g. install an elevation-checking middleware in
	// front of the registry). The field is preserved for forward
	// compatibility so configuration files that already set it keep
	// compiling.
	ElevationRequired bool
}

// Logger is the diagnostic logger handle. A Logger owns one SQLite
// database file, one slog.Handler adapter, and one tool-call middleware
// factory. All methods are safe for concurrent use except Close, which
// must not race with an in-flight operation.
type Logger struct {
	cfg Config

	db       *sql.DB
	mu       sync.Mutex // serialises writer access and eviction
	levelVar *slog.LevelVar

	closeOnce sync.Once
	closeErr  error

	// lastErrNs records the unix-nano timestamp of the most recent
	// write-path failure that was reported via log.Printf. Further
	// failures within 60 seconds are silently dropped so a broken disk
	// does not flood the standard log. atomic.Int64 for lock-free
	// reads on the hot path.
	lastErrNs atomic.Int64
}

// defaultCategories is the plan-mandated category set (plan §8.2.3 item 2).
var defaultCategories = []string{"request", "tool", "auth", "api", "lifecycle", "error"}

// New opens (or creates) a SQLite database at cfg.DBPath and returns a
// Logger. Unset Config fields are filled with defaults. The database
// file's parent directory is created with 0700 permissions, matching
// the convention established by auth/store.go.
func New(cfg Config) (*Logger, error) {
	if cfg.DBPath == "" {
		cfg.DBPath = "/data/server-logs.db"
	}
	if cfg.RingSize <= 0 {
		cfg.RingSize = 50_000
	}
	if len(cfg.Categories) == 0 {
		cfg.Categories = append([]string(nil), defaultCategories...)
	}

	// Only create the parent directory for on-disk paths. The special
	// ":memory:" path and Go-SQLite's file: URIs may not have a real
	// filesystem directory.
	if cfg.DBPath != ":memory:" && !strings.HasPrefix(cfg.DBPath, "file:") {
		if dir := filepath.Dir(cfg.DBPath); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("create db directory: %w", err)
			}
		}
	}

	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// PRAGMAs match the project's existing auth/store.go pattern
	// (journal_mode=WAL, foreign_keys=ON) plus the two requested in the
	// charter (synchronous=NORMAL, busy_timeout=5000).
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}

	// SQLite is a single-writer store. Pinning to a single connection
	// mirrors auth/store.go and prevents writer contention across the
	// Go-level connection pool.
	db.SetMaxOpenConns(1)

	l := &Logger{
		cfg:      cfg,
		db:       db,
		levelVar: new(slog.LevelVar), // defaults to slog.LevelInfo
	}
	if err := l.createTables(); err != nil {
		db.Close()
		return nil, fmt.Errorf("create tables: %w", err)
	}
	return l, nil
}

func (l *Logger) createTables() error {
	_, err := l.db.Exec(`
		CREATE TABLE IF NOT EXISTS logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts INTEGER NOT NULL,
			level TEXT NOT NULL,
			category TEXT NOT NULL,
			message TEXT NOT NULL,
			attrs TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
		CREATE INDEX IF NOT EXISTS idx_logs_cat_ts ON logs(category, ts);
	`)
	return err
}

// LevelVar exposes the underlying slog level variable so consumers can
// raise or lower verbosity at runtime. Returns a pointer to the live
// LevelVar; callers may invoke Set on it.
func (l *Logger) LevelVar() *slog.LevelVar { return l.levelVar }

// Slog returns an *slog.Logger that persists every record to the
// diagnostic database.
func (l *Logger) Slog() *slog.Logger {
	return slog.New(&handler{l: l})
}

// Close closes the underlying SQLite database. Safe to call multiple
// times; subsequent calls return the error from the first Close.
//
// Close takes l.mu so it observes a consistent state with in-flight
// writers (write / handleGetLogs / handleGetStats / handleClearLogs),
// and nil-clears l.db under the same lock so the (l.db == nil) guards
// in those methods actually fire after Close returns. Without this the
// guards are dead code — l.db becomes non-nil-but-closed, and callers
// get sql.ErrConnDone leaking out as a query error.
func (l *Logger) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.db != nil {
			l.closeErr = l.db.Close()
			l.db = nil
		}
	})
	return l.closeErr
}

// noteWriteError reports a write-path failure to the standard logger,
// throttled to at most once per 60 seconds. It never returns an error.
func (l *Logger) noteWriteError(err error) {
	if err == nil {
		return
	}
	now := time.Now().UnixNano()
	last := l.lastErrNs.Load()
	// 60-second throttle. If a race lets two callers pass the gate we
	// log twice — acceptable.
	if now-last < int64(60*time.Second) {
		return
	}
	if !l.lastErrNs.CompareAndSwap(last, now) {
		return
	}
	log.Printf("diag: log write failed: %v", err)
}

// write inserts a single log row and evicts over-cap rows. All errors
// are swallowed; the caller's request must not be failed by a log
// write failure.
func (l *Logger) write(ts int64, level, category, message string, attrsJSON string) {
	defer func() {
		if r := recover(); r != nil {
			l.noteWriteError(fmt.Errorf("panic: %v", r))
		}
	}()

	l.mu.Lock()
	defer l.mu.Unlock()

	// db may be nil if Close was called concurrently. Skip the insert.
	if l.db == nil {
		return
	}

	var attrs any
	if attrsJSON == "" {
		attrs = nil
	} else {
		attrs = attrsJSON
	}
	if _, err := l.db.Exec(
		`INSERT INTO logs (ts, level, category, message, attrs) VALUES (?, ?, ?, ?, ?)`,
		ts, level, category, message, attrs,
	); err != nil {
		l.noteWriteError(err)
		return
	}
	l.evictLocked()
}

// evictLocked deletes the oldest rows until count <= RingSize. Must be
// called with l.mu held.
func (l *Logger) evictLocked() {
	var count int
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM logs`).Scan(&count); err != nil {
		l.noteWriteError(err)
		return
	}
	if count <= l.cfg.RingSize {
		return
	}
	excess := count - l.cfg.RingSize
	if _, err := l.db.Exec(
		`DELETE FROM logs WHERE id IN (SELECT id FROM logs ORDER BY id ASC LIMIT ?)`,
		excess,
	); err != nil {
		l.noteWriteError(err)
	}
}

// ---------------- slog adapter ----------------

// handler is an slog.Handler that writes each record to the logs
// table. Groups are flattened: WithGroup(name) applies name as a prefix
// on subsequent keys using "name.key" dotted notation. This is
// consistent with the rest of the project's logging conventions and
// avoids nested JSON that would be awkward to query in SQL.
type handler struct {
	l      *Logger
	attrs  []slog.Attr
	groups []string
}

// Enabled reports whether records at lvl should be emitted. Defers to
// the Logger's LevelVar so consumers can tune verbosity at runtime.
func (h *handler) Enabled(_ context.Context, lvl slog.Level) bool {
	return lvl >= h.l.levelVar.Level()
}

// Handle serialises the record and inserts it.
func (h *handler) Handle(_ context.Context, r slog.Record) error {
	// Merge pre-applied attrs with record attrs. Derive category from
	// the attr named "category" if present; otherwise "lifecycle".
	// The "category" key is treated as special and is scanned for in
	// BOTH the pre-applied attrs (from WithAttrs) and the record's own
	// attrs BEFORE any group-flattening. This makes `logger.With(
	// "category", "foo")` and `logger.WithGroup("g").With("category",
	// "foo")` both work.
	category := "lifecycle"
	takeCategory := func(a slog.Attr) bool {
		if a.Key == "category" {
			if s, ok := a.Value.Resolve().Any().(string); ok && s != "" {
				category = s
			}
			return true
		}
		return false
	}

	merged := make(map[string]any, len(h.attrs)+r.NumAttrs())
	for _, a := range h.attrs {
		if takeCategory(a) {
			continue
		}
		h.addAttr(merged, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		if takeCategory(a) {
			return true
		}
		h.addAttr(merged, a)
		return true
	})

	var attrsJSON string
	if len(merged) > 0 {
		b, err := json.Marshal(merged)
		if err == nil {
			attrsJSON = string(b)
		}
	}

	ts := r.Time.UnixNano()
	if r.Time.IsZero() {
		ts = time.Now().UnixNano()
	}
	h.l.write(ts, r.Level.String(), category, r.Message, attrsJSON)
	return nil
}

// addAttr flattens a slog.Attr into dst. Groups become dotted key
// prefixes; leaf values are JSON-serialisable Go values.
func (h *handler) addAttr(dst map[string]any, a slog.Attr) {
	key := a.Key
	if len(h.groups) > 0 && key != "" {
		key = strings.Join(h.groups, ".") + "." + key
	}
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		for _, ga := range v.Group() {
			gk := ga.Key
			full := key
			if full != "" && gk != "" {
				full = full + "." + gk
			} else if gk != "" {
				full = gk
			}
			// recurse with a temp handler whose groups include `full`
			// is more work than needed; we just inline the group expansion.
			h.addAttrAt(dst, full, ga.Value)
		}
		return
	}
	dst[key] = v.Any()
}

func (h *handler) addAttrAt(dst map[string]any, key string, v slog.Value) {
	v = v.Resolve()
	if v.Kind() == slog.KindGroup {
		for _, ga := range v.Group() {
			sub := key
			if sub != "" && ga.Key != "" {
				sub = sub + "." + ga.Key
			} else if ga.Key != "" {
				sub = ga.Key
			}
			h.addAttrAt(dst, sub, ga.Value)
		}
		return
	}
	dst[key] = v.Any()
}

// WithAttrs returns a new handler with attrs pre-applied to every
// emitted record.
func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := &handler{l: h.l, groups: h.groups}
	out.attrs = append(out.attrs, h.attrs...)
	out.attrs = append(out.attrs, attrs...)
	return out
}

// WithGroup returns a new handler whose subsequent attrs are prefixed
// with name. Groups are flattened into dotted keys at serialisation
// time. If name is empty the receiver is returned unchanged, per the
// slog.Handler contract.
func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	out := &handler{l: h.l, attrs: h.attrs}
	out.groups = append(out.groups, h.groups...)
	out.groups = append(out.groups, name)
	return out
}

// ---------------- middleware ----------------

// maxErrTextLen caps the size of err_text stored per log row so a
// pathological error message cannot bloat the log DB.
const maxErrTextLen = 500

// Middleware returns a ToolMiddleware that records one log row per
// tool call. The log row uses category "tool" and includes the tool
// name, duration, isError flag, error-flag, sorted argument keys
// (not values — avoids credential leakage), a truncated error text,
// and the byte size of the result. Neither full args nor full
// results are persisted.
func (l *Logger) Middleware() mcp.ToolMiddleware {
	return func(next mcp.ToolCallFunc) mcp.ToolCallFunc {
		return func(ctx context.Context, name string, args map[string]any) (any, bool, error) {
			start := time.Now()
			result, isError, err := next(ctx, name, args)
			dur := time.Since(start)

			// Collect sorted argument keys for lightweight analytics.
			keys := make([]string, 0, len(args))
			for k := range args {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			attrs := map[string]any{
				"tool":        name,
				"duration_ms": dur.Milliseconds(),
				"isError":     isError,
				"hasError":    err != nil,
				"arg_keys":    keys,
			}
			if err != nil {
				s := err.Error()
				if len(s) > maxErrTextLen {
					s = s[:maxErrTextLen]
				}
				attrs["err_text"] = s
			}
			if result != nil {
				if b, mErr := json.Marshal(result); mErr == nil {
					attrs["result_size_bytes"] = len(b)
				}
			}

			// Best-effort; write swallows its own errors.
			if b, mErr := json.Marshal(attrs); mErr == nil {
				l.write(time.Now().UnixNano(), slog.LevelInfo.String(), "tool", "tool.call", string(b))
			}
			return result, isError, err
		}
	}
}

// ---------------- registered tools ----------------

// RegisterTools installs server_get_logs, server_get_stats, and
// server_clear_logs on r when cfg.AutoRegisterTools is true. When
// false, RegisterTools is a no-op.
//
// Elevation gating is deferred to a future convention (plan §9 item
// 2). Consumers who need to restrict these tools to elevated sessions
// must wrap the registry externally.
func (l *Logger) RegisterTools(r *mcp.Registry) error {
	if !l.cfg.AutoRegisterTools {
		return nil
	}
	if r == nil {
		return errors.New("diag: RegisterTools: nil registry")
	}

	if err := r.Register(mcp.Tool{
		Name:        "server_get_logs",
		Description: "Return recent diagnostic log rows, newest first.",
		InputSchema: json.RawMessage(`{
			"type":"object",
			"properties":{
				"limit":{"type":"integer","minimum":1,"maximum":10000,"default":100},
				"category":{"type":"string"},
				"level":{"type":"string"},
				"since_ns":{"type":"integer"}
			}
		}`),
		Category: "diagnostics",
		Handler:  l.handleGetLogs,
	}); err != nil {
		return err
	}
	if err := r.Register(mcp.Tool{
		Name:        "server_get_stats",
		Description: "Return diagnostic log statistics: totals by category and level.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Category:    "diagnostics",
		Handler:     l.handleGetStats,
	}); err != nil {
		return err
	}
	if err := r.Register(mcp.Tool{
		Name:        "server_clear_logs",
		Description: "Delete all diagnostic log rows. Returns the count cleared.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Category:    "diagnostics",
		Handler:     l.handleClearLogs,
	}); err != nil {
		return err
	}
	return nil
}

// LogRow is the shape of a row returned from server_get_logs.
type LogRow struct {
	ID       int64  `json:"id"`
	TS       int64  `json:"ts"`
	Level    string `json:"level"`
	Category string `json:"category"`
	Message  string `json:"message"`
	Attrs    any    `json:"attrs,omitempty"`
}

func (l *Logger) handleGetLogs(_ context.Context, args map[string]any) (any, error) {
	limit := 100
	if v, ok := args["limit"]; ok {
		switch n := v.(type) {
		case int:
			limit = n
		case int64:
			limit = int(n)
		case float64:
			limit = int(n)
		}
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 10000 {
		limit = 10000
	}

	var (
		where []string
		qargs []any
	)
	if s, ok := args["category"].(string); ok && s != "" {
		where = append(where, "category = ?")
		qargs = append(qargs, s)
	}
	if s, ok := args["level"].(string); ok && s != "" {
		where = append(where, "level = ?")
		qargs = append(qargs, s)
	}
	if v, ok := args["since_ns"]; ok {
		var since int64
		switch n := v.(type) {
		case int64:
			since = n
		case int:
			since = int64(n)
		case float64:
			since = int64(n)
		}
		if since > 0 {
			where = append(where, "ts >= ?")
			qargs = append(qargs, since)
		}
	}
	q := `SELECT id, ts, level, category, message, attrs FROM logs`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	qargs = append(qargs, limit)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.db == nil {
		return map[string]any{"logs": []LogRow{}, "count": 0}, nil
	}
	rows, err := l.db.Query(q, qargs...)
	if err != nil {
		return nil, fmt.Errorf("query logs: %w", err)
	}
	defer rows.Close()

	out := []LogRow{}
	for rows.Next() {
		var lr LogRow
		var attrs sql.NullString
		if err := rows.Scan(&lr.ID, &lr.TS, &lr.Level, &lr.Category, &lr.Message, &attrs); err != nil {
			return nil, fmt.Errorf("scan log row: %w", err)
		}
		if attrs.Valid && attrs.String != "" {
			var a any
			if err := json.Unmarshal([]byte(attrs.String), &a); err == nil {
				lr.Attrs = a
			} else {
				lr.Attrs = attrs.String
			}
		}
		out = append(out, lr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate logs: %w", err)
	}
	return map[string]any{"logs": out, "count": len(out)}, nil
}

func (l *Logger) handleGetStats(_ context.Context, _ map[string]any) (any, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.db == nil {
		return map[string]any{
			"total":       0,
			"by_category": map[string]int64{},
			"by_level":    map[string]int64{},
			"oldest_ts":   int64(0),
			"newest_ts":   int64(0),
		}, nil
	}

	var total int64
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM logs`).Scan(&total); err != nil {
		return nil, fmt.Errorf("count logs: %w", err)
	}

	byCategory, err := scanGroupCounts(l.db, `SELECT category, COUNT(*) FROM logs GROUP BY category`)
	if err != nil {
		return nil, err
	}
	byLevel, err := scanGroupCounts(l.db, `SELECT level, COUNT(*) FROM logs GROUP BY level`)
	if err != nil {
		return nil, err
	}

	var oldestTS, newestTS sql.NullInt64
	if err := l.db.QueryRow(`SELECT MIN(ts), MAX(ts) FROM logs`).Scan(&oldestTS, &newestTS); err != nil {
		return nil, fmt.Errorf("bounds logs: %w", err)
	}

	return map[string]any{
		"total":       total,
		"by_category": byCategory,
		"by_level":    byLevel,
		"oldest_ts":   oldestTS.Int64,
		"newest_ts":   newestTS.Int64,
	}, nil
}

func scanGroupCounts(db *sql.DB, q string) (map[string]int64, error) {
	rows, err := db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("group query: %w", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var v int64
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		out[k] = v
	}
	return out, rows.Err()
}

func (l *Logger) handleClearLogs(_ context.Context, _ map[string]any) (any, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.db == nil {
		return map[string]any{"cleared": int64(0)}, nil
	}
	var before int64
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM logs`).Scan(&before); err != nil {
		return nil, fmt.Errorf("count before clear: %w", err)
	}
	if _, err := l.db.Exec(`DELETE FROM logs`); err != nil {
		return nil, fmt.Errorf("delete logs: %w", err)
	}
	return map[string]any{"cleared": before}, nil
}
