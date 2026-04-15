// Package diag provides a diagnostic logger with a SQLite ring-buffer
// backend and an slog.Handler adapter, plus a tool-call middleware and
// auto-registered log-query tools. See §4.7 of the v0.8.0 plan.
package diag

import (
	"log/slog"

	mcp "github.com/Superposition-Systems/go-mcp-server"
)

// Config configures a diagnostic Logger.
type Config struct {
	DBPath            string   // default "/data/server-logs.db"
	RingSize          int      // default 50_000
	Categories        []string // default: request, tool, auth, api, lifecycle, error
	AutoRegisterTools bool     // default true; registers server_get_logs etc.
	ElevationRequired bool     // default true; log-query tools need elevation
}

// Logger is the diagnostic logger handle.
//
// Phase 0 minimal impl: holds the config and returns trivial values from
// its methods. Session 3 (track 2F) replaces the body with the production
// SQLite ring-buffer + slog adapter + tool-call middleware.
type Logger struct {
	cfg Config
}

// New opens a Logger. Phase 0: returns a handle with no SQLite attached.
func New(cfg Config) (*Logger, error) {
	return &Logger{cfg: cfg}, nil
}

// Slog returns an slog.Logger backed by the diagnostic store.
//
// Phase 0: returns slog.Default() so callers can use the logger interface
// without waiting for track 2F.
func (l *Logger) Slog() *slog.Logger {
	return slog.Default()
}

// Middleware returns a ToolMiddleware that logs every tool call with
// duration, tool name, success/error, and (truncated) arguments.
//
// Phase 0: returns an identity middleware. Track 2F fills in.
func (l *Logger) Middleware() mcp.ToolMiddleware {
	return func(next mcp.ToolCallFunc) mcp.ToolCallFunc { return next }
}

// RegisterTools adds server_get_logs / server_get_stats / server_clear_logs
// to the given registry (elevation-gated when Config.ElevationRequired).
//
// Phase 0: no-op. Track 2F registers the real tools.
func (l *Logger) RegisterTools(r *mcp.Registry) error {
	_ = r
	return nil
}

// Close flushes pending writes and closes the underlying SQLite handle.
//
// Phase 0: no-op.
func (l *Logger) Close() error { return nil }
