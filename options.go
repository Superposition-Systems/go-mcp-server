package mcpserver

import (
	"net/http"
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

// WithTokenValidator sets a custom function to validate bearer tokens.
// The function receives the raw token (after stripping "Bearer ") and
// returns true if the token should be accepted.
//
// This is checked before the static bearer token and OAuth, so it can
// be used to accept multiple tokens, implement scoped auth, or delegate
// to an external auth service. Combine with WithMiddleware to tag the
// request context with scope metadata before validation runs.
func WithTokenValidator(fn func(token string) bool) Option {
	return func(s *Server) { s.tokenValidator = fn }
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
//
// For distroless or other read-only container filesystems, ensure the
// target directory exists and is writable (mount a volume at /data, or
// set OAUTH_DB_PATH to a tmpfs location such as /tmp/oauth.db).
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

// WithExternalURL sets the canonical public URL of this server (e.g.
// "https://my-mcp.example.com"). Used as the OAuth issuer and for all
// metadata endpoint URLs. Required for production deployments.
func WithExternalURL(url string) Option {
	return func(s *Server) { s.oauthConfig.ExternalURL = url }
}

// WithConsent sets the title and description for the OAuth PIN consent page.
func WithConsent(title, description string) Option {
	return func(s *Server) {
		s.oauthConfig.ConsentTitle = title
		s.oauthConfig.ConsentDescription = description
	}
}

// WithAllowedOrigins enables browser-origin enforcement. When set, any
// request carrying an Origin header that is not in the allowlist is
// rejected with 403, and matching requests receive standard CORS headers.
// Non-browser clients (which omit Origin) pass through unchanged.
//
// Recommended for public deployments where the MCP endpoint is reachable
// from a browser and DNS-rebinding against a local MCP server is a risk.
func WithAllowedOrigins(origins ...string) Option {
	return func(s *Server) { s.allowedOrigins = append(s.allowedOrigins, origins...) }
}

// WithTrustedProxyCIDRs configures the OAuth handler to trust
// X-Forwarded-For (or X-Real-IP) from requests arriving via the given
// CIDR ranges. Without this, rate limiters key on the reverse-proxy IP,
// which makes per-attacker bucketing impossible. Configure your proxy
// to set X-Forwarded-For with the original client IP.
func WithTrustedProxyCIDRs(cidrs ...string) Option {
	return func(s *Server) {
		s.oauthConfig.TrustedProxyCIDRs = append(s.oauthConfig.TrustedProxyCIDRs, cidrs...)
	}
}

// WithAllowMissingState relaxes OAuth 2.1 state enforcement to
// accommodate legacy clients. Not recommended for new deployments —
// PKCE alone does not fully substitute for state on the redirect leg.
func WithAllowMissingState() Option {
	return func(s *Server) { s.oauthConfig.AllowMissingState = true }
}

// WithMiddleware sets an outer middleware that wraps the entire handler chain
// (including bearer auth). This runs before any auth check, so it can inspect
// the raw Authorization header to tag the request context with application-
// specific metadata (e.g. auth scope levels).
func WithMiddleware(mw func(http.Handler) http.Handler) Option {
	return func(s *Server) {
		s.outerMiddleware = mw
	}
}

// ElevationConfig configures the built-in step-up authentication feature.
// When a server is constructed WithElevation, the library:
//
//   - Opens a SQLite store at DBPath for the hashed password
//   - Registers two tools: <ToolNamePrefix>_elevate and
//     <ToolNamePrefix>_set_elevation_password
//   - Exposes Server.Elevation() so apps can check session state and
//     fold elevation info into their health responses
//
// In bootstrap mode (no password configured, no env override), every
// authenticated session is treated as elevated — this is the one-time
// window in which an operator calls set_elevation_password to close it.
//
// If EnvPasswordVar is set and that env var is non-empty at startup, the
// server runs in strict mode: the env password is the source of truth,
// bootstrap mode is disabled, and runtime rotation is refused.
type ElevationConfig struct {
	// DBPath is the SQLite path for the password store. Required.
	DBPath string

	// GrantTTL is how long an elevation lasts after a successful call to
	// elevate (default 10 minutes).
	GrantTTL time.Duration

	// EnvPasswordVar is the env var consulted for a strict-mode password
	// override (e.g. "MCP_ELEVATION_PASSWORD"). Leave empty to disable.
	EnvPasswordVar string

	// ToolNamePrefix is prepended to the two registered tool names. If
	// empty, the server name is used (with hyphens replaced by underscores).
	ToolNamePrefix string
}

// WithElevation enables the step-up-auth elevation feature. See
// ElevationConfig for details. When this option is not set, none of the
// elevation machinery is constructed and Server.Elevation() returns nil.
func WithElevation(cfg ElevationConfig) Option {
	return func(s *Server) {
		c := cfg
		s.elevationConfig = &c
	}
}
