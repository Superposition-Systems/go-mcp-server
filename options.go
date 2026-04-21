package mcpserver

import (
	"net/http"
	"time"

	"github.com/Superposition-Systems/go-mcp-server/auth"
	"github.com/Superposition-Systems/go-mcp-server/suggest"
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

// WithRequireResourceIndicator requires every /authorize and /token
// request to include an RFC 8707 `resource` parameter matching the
// server's canonical resource URI (ExternalURL + /mcp path). The
// 2025-06-18 MCP spec says clients MUST send it; this option makes
// the server side symmetric and rejects legacy clients that omit it.
//
// Leave unset (the default) during the transition: the server still
// validates the parameter when present and binds the token to the
// audience, so audience enforcement kicks in automatically as clients
// upgrade. Opt in once every client in a deployment is known to send
// `resource` (check deployment logs for any `invalid_target` responses
// before flipping the flag).
//
// Has no effect if WithExternalURL is unset — the server has no
// canonical URI to validate against in that mode, and
// validateResourceParam already rejects any non-empty resource.
func WithRequireResourceIndicator() Option {
	return func(s *Server) { s.oauthConfig.RequireResourceIndicator = true }
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

// ─────────────────────────────────────────────────────────────────────────────
// v0.8.0 options — tool-call middleware, registry extensions, telemetry.
//
// These options are declared here as the central "contract" file for the
// Phase 0 scaffold. Session tracks implement the behaviour the options wire
// into (middleware chain, transformer, aliases, validator, suggestion hook)
// but do not re-declare the option signatures. See
// docs/plans/v0.8.0-middleware-and-registry.md §8.1 + §8.3.
// ─────────────────────────────────────────────────────────────────────────────

// WithToolMiddleware installs one or more ToolMiddleware wrappers. They run
// outermost-first; the innermost wraps the registry's dispatch. Safe to call
// multiple times — middlewares accumulate. See §4.2.
func WithToolMiddleware(mw ...ToolMiddleware) Option {
	return func(s *Server) { s.toolMiddleware = append(s.toolMiddleware, mw...) }
}

// WithResponseTransformer installs a transformer that runs on successful
// tool-call results (isError=false, err=nil). Internally this is appended
// as a tail-end ToolMiddleware. See §4.3.
func WithResponseTransformer(t ResponseTransformer) Option {
	return func(s *Server) { s.responseTransformer = t }
}

// WithParamAliases installs middleware that rewrites parameter names in the
// args map before downstream middleware or the handler runs. Per-tool
// aliases (Tool.ParamAliases) override the global map. Collisions (both
// alias and canonical present) drop the alias and fire
// suggest.EventAliasCollision. See §4.10.
func WithParamAliases(global map[string]string) Option {
	return func(s *Server) { s.paramAliases = global }
}

// WithInputValidation installs middleware that validates each tool's args
// against its InputSchema before calling the handler. Tools without an
// InputSchema pass through unchanged. See §4.6.
func WithInputValidation(opts ...ValidationOption) Option {
	return func(s *Server) { s.validationOptions = append(s.validationOptions, opts...) }
}

// WithSuggestionHook wires a suggest.Hook so that every unknown tool name
// (mux dispatch), every unknown parameter name (validator / alias
// middleware), and every alias collision produces a suggestion event. See
// §4.11.
func WithSuggestionHook(h suggest.Hook) Option {
	return func(s *Server) { s.suggestionHook = h }
}
