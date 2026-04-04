package mcpserver

import (
	"time"

	"github.com/Superposition-Systems/go-mcp-server/auth"
)

// Option configures a Server.
type Option func(*Server)

// WithName sets the MCP server name reported during initialization.
func WithName(name string) Option {
	return func(s *Server) { s.info.Name = name }
}

// WithVersion sets the MCP server version reported during initialization.
func WithVersion(version string) Option {
	return func(s *Server) { s.info.Version = version }
}

// WithInstructions sets the human-readable server description.
func WithInstructions(instructions string) Option {
	return func(s *Server) { s.info.Instructions = instructions }
}

// WithPort sets the listen port (default "8080").
func WithPort(port string) Option {
	return func(s *Server) {
		if port != "" {
			s.port = port
		}
	}
}

// WithTimeout sets the per-request timeout (default 120s).
func WithTimeout(d time.Duration) Option {
	return func(s *Server) { s.timeout = d }
}

// WithDrainTime sets the graceful shutdown drain window (default 30s).
func WithDrainTime(d time.Duration) Option {
	return func(s *Server) { s.drainTime = d }
}

// WithBearerToken sets the static bearer token for CLI authentication.
// If not set, reads from BEARER_TOKEN environment variable.
func WithBearerToken(token string) Option {
	return func(s *Server) { s.bearerToken = token }
}

// WithMCPPath sets the MCP endpoint path (default "/mcp").
// ResourcePath is resolved lazily in ListenAndServe from mcpPath,
// so this option can be used in any order with WithAuth.
func WithMCPPath(path string) Option {
	return func(s *Server) {
		s.mcpPath = path
	}
}

// WithAuth configures OAuth authentication.
func WithAuth(cfg auth.OAuthConfig) Option {
	return func(s *Server) {
		s.oauthConfig = cfg
		// ResourcePath is resolved lazily in ListenAndServe from s.mcpPath
	}
}

// WithOAuthDBPath sets the SQLite database path for OAuth state
// (default reads from OAUTH_DB_PATH env, fallback "/data/oauth.db").
func WithOAuthDBPath(path string) Option {
	return func(s *Server) { s.oauthDBPath = path }
}

// WithScope sets the OAuth scope (default "mcp:tools").
func WithScope(scope string) Option {
	return func(s *Server) { s.oauthConfig.Scope = scope }
}

// WithPIN sets the OAuth consent PIN. If not set, reads from AUTH_PIN
// environment variable.
func WithPIN(pin string) Option {
	return func(s *Server) { s.oauthConfig.PIN = pin }
}

// WithConsent sets the title and description for the OAuth PIN consent page.
func WithConsent(title, description string) Option {
	return func(s *Server) {
		s.oauthConfig.ConsentTitle = title
		s.oauthConfig.ConsentDescription = description
	}
}
