package mcpserver

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Superposition-Systems/go-mcp-server/auth"
	"github.com/Superposition-Systems/go-mcp-server/suggest"
)

// Server is an opinionated MCP server that combines the JSON-RPC transport,
// OAuth 2.0 auth, and an stdlib ServeMux into a single runnable binary.
//
// The typical usage pattern is API-first:
//  1. Create a Server with New()
//  2. Mount your REST API routes on Server.Mux()
//  3. Call Server.RegisterTools() to add the MCP layer
//  4. Call Server.ListenAndServe() to start
type Server struct {
	mux             *http.ServeMux
	info            ServerInfo
	port            string
	timeout         time.Duration
	drainTime       time.Duration
	oauthStore      *auth.OAuthStore
	oauthConfig     auth.OAuthConfig
	bearerToken     string
	tokenValidator  func(string) bool
	mcpPath         string
	tools           ToolHandler
	healthFunc      http.HandlerFunc
	oauthDBPath     string
	routeOnce       sync.Once
	outerMiddleware func(http.Handler) http.Handler // applied outside bearer auth
	allowedOrigins  []string                        // CORS allowlist (optional)

	// Elevation (optional). Configured via WithElevation. The stores open
	// lazily on first Elevation() call so apps can fetch the handle during
	// tool construction, before ListenAndServe runs.
	elevationConfig *ElevationConfig
	elevationOnce   sync.Once
	elevationErr    error
	elevation       *auth.Elevation
	elevationPwd    *auth.PasswordStore

	// v0.8.0 (optional) — tool-call middleware chain and associated knobs.
	// Phase 0 holds the configuration; Session 2 (track 1B) wires the chain
	// into transport.go's tools/call path.
	toolMiddleware      []ToolMiddleware
	responseTransformer ResponseTransformer
	paramAliases        map[string]string
	validationOptions   []ValidationOption
	suggestionHook      suggest.Hook
}

// New creates a new MCP server with the given options.
func New(opts ...Option) *Server {
	s := &Server{
		mux:       http.NewServeMux(),
		port:      "8080",
		timeout:   120 * time.Second,
		drainTime: 30 * time.Second,
		mcpPath:   "/mcp",
		info: ServerInfo{
			Name:    "mcp-server",
			Version: "1.0.0",
		},
		oauthConfig: auth.OAuthConfig{
			Scope:        "mcp:tools",
			ResourcePath: "/mcp",
		},
		oauthDBPath: envDefault("OAUTH_DB_PATH", "/data/oauth.db"),
		bearerToken: os.Getenv("BEARER_TOKEN"),
	}
	// Read PIN from env as default (can be overridden by WithPIN)
	s.oauthConfig.PIN = os.Getenv("AUTH_PIN")

	for _, opt := range opts {
		opt(s)
	}
	return s
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Mux returns the underlying http.ServeMux for mounting application routes.
// Call this before ListenAndServe to add your REST API endpoints:
//
//	srv := mcpserver.New(...)
//	srv.Mux().HandleFunc("GET /api/v1/users", usersHandler)
//	srv.Mux().HandleFunc("GET /api/v1/items/{id}", itemHandler)
//	srv.RegisterTools(myTools)
//	srv.ListenAndServe()
func (s *Server) Mux() *http.ServeMux {
	return s.mux
}

// RegisterTools sets the ToolHandler for MCP tool dispatch.
func (s *Server) RegisterTools(tools ToolHandler) {
	s.tools = tools
}

// SetHealthCheck sets a custom health check handler. If not set, a default
// handler returning 200 OK is used.
func (s *Server) SetHealthCheck(handler http.HandlerFunc) {
	s.healthFunc = handler
}

// ListenAndServe starts the HTTP server with all routes mounted:
//   - Health endpoints (/health, /healthz)
//   - MCP transport (default: /mcp)
//   - OAuth endpoints (/.well-known/*, /register, /authorize, /token)
//   - Any user-mounted routes via Mux()
//
// It blocks until the server shuts down (SIGINT/SIGTERM).
func (s *Server) ListenAndServe() error {
	if s.tools == nil {
		return fmt.Errorf("mcpserver: no ToolHandler registered — call RegisterTools() before ListenAndServe()")
	}

	// Refuse to start with a dangerously short OAuth PIN. Rate limit is
	// 5 attempts per 15 minutes per IP; at six characters (≈60 bits if
	// mixed-case alpha, ≈20 bits if numeric) a single-IP attacker needs
	// years — acceptable. Below that, even single-IP brute force is
	// feasible in days and distributed attacks in minutes.
	//
	// Empty PIN is allowed (static-bearer-only deployments) — the
	// existing startup warning covers that case.
	if s.oauthConfig.PIN != "" && len(s.oauthConfig.PIN) < 6 {
		return fmt.Errorf("mcpserver: AUTH_PIN is shorter than 6 characters; refusing to start. Set a longer PIN or unset AUTH_PIN for static-bearer-only mode")
	}

	// Refuse to start with a non-https ExternalURL unless the host is
	// loopback. The issuer claim in discovery metadata must match the
	// scheme clients will see at runtime — advertising http:// while
	// Traefik terminates TLS produces spec-violating metadata and can
	// fool downstream audience validation that expects https://.
	if s.oauthConfig.ExternalURL != "" {
		u, err := url.Parse(s.oauthConfig.ExternalURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("mcpserver: ExternalURL %q is not a valid absolute URL", s.oauthConfig.ExternalURL)
		}
		host := u.Hostname()
		isLoopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
		if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback) {
			return fmt.Errorf("mcpserver: ExternalURL must be https:// (or http://localhost for dev), got %q", s.oauthConfig.ExternalURL)
		}
	}

	// Resolve ResourcePath from mcpPath if not explicitly set via WithAuth
	if s.oauthConfig.ResourcePath == "" {
		s.oauthConfig.ResourcePath = s.mcpPath
	}

	// Initialize elevation (no-op if WithElevation was not set). The lazy
	// accessor may have already run this during app-side tool construction,
	// in which case the once.Do is a no-op here.
	if s.elevationConfig != nil {
		s.Elevation()
		if s.elevationErr != nil {
			return fmt.Errorf("mcpserver: %w", s.elevationErr)
		}
		if s.elevationPwd != nil {
			defer s.elevationPwd.Close()
		}
		// Wrap the user's tool handler to add library-level elevation tools.
		s.tools = s.wrapToolsWithElevation(s.tools)
	}

	// OAuth store
	oauthStore, err := auth.NewOAuthStore(s.oauthDBPath, s.oauthConfig.Scope)
	if err != nil {
		return fmt.Errorf("mcpserver: oauth store: %w", err)
	}
	defer oauthStore.Close()
	s.oauthStore = oauthStore

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Capture whether a PIN was configured before zeroing it — used
	// below for the startup warning banner.
	pinAtHandlerBuild := s.oauthConfig.PIN
	oauthHandler := auth.NewOAuthHandler(oauthStore, s.oauthConfig)
	// The OAuth handler holds its own copy of the PIN; clear it from
	// the Server struct so panics/log dumps of the Server don't expose it.
	s.oauthConfig.PIN = ""

	// Cleanup goroutine: prunes expired DB rows and sweeps the
	// in-memory rate-limiter maps so they cannot stay at capacity under
	// sustained adversarial traffic. Wrapped in panic recovery so a
	// SQLite driver panic cannot kill the server process.
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("mcpserver: cleanup goroutine panicked: %v", rec)
			}
		}()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := oauthStore.Cleanup(); err != nil {
					log.Printf("mcpserver: cleanup error: %v", err)
				}
				oauthHandler.PINLimiter.PruneAll()
				oauthHandler.RegLimiter.PruneAll()
				oauthHandler.AuthorizeLimiter.PruneAll()
				if s.elevation != nil {
					s.elevation.PruneAttemptLimiter()
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Health
	healthHandler := s.healthFunc
	if healthHandler == nil {
		healthHandler = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"ok"}`)
		}
	}

	s.routeOnce.Do(func() {
		s.mux.HandleFunc("GET /health", healthHandler)
		s.mux.HandleFunc("GET /healthz", healthHandler)
		s.mux.HandleFunc("POST "+s.mcpPath, TransportHandler(s.info, s.tools))
		s.mux.HandleFunc("GET /.well-known/oauth-authorization-server", oauthHandler.Discovery)
		s.mux.HandleFunc("GET /.well-known/oauth-protected-resource", oauthHandler.ProtectedResource)
		s.mux.HandleFunc("POST /register", oauthHandler.Register)
		s.mux.HandleFunc("GET /authorize", oauthHandler.AuthorizeGET)
		s.mux.HandleFunc("POST /authorize", oauthHandler.AuthorizePOST)
		s.mux.HandleFunc("POST /token", oauthHandler.Token)
		s.mux.HandleFunc("POST /revoke", oauthHandler.Revoke)
	})

	// Wrap with middleware: context-based timeout + optional elevation
	// stamping + bearer auth. The elevation middleware sits INSIDE the
	// bearer check so GetTokenHash is populated when HasCurrentSession
	// runs.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
		defer cancel()
		s.mux.ServeHTTP(w, r.WithContext(ctx))
	})

	var afterAuth http.Handler = inner
	if s.elevation != nil {
		afterAuth = s.elevation.Middleware()(inner)
	}

	var handler http.Handler = auth.BearerMiddleware(
		s.bearerToken, s.tokenValidator, oauthStore, s.oauthConfig.Scope, s.mcpPath,
	)(afterAuth)

	// Apply outer middleware (e.g. auth scope tagging) — runs before bearer auth
	if s.outerMiddleware != nil {
		handler = s.outerMiddleware(handler)
	}

	// Origin allowlist (CORS) — outermost. A pass-through when no
	// origins were configured.
	//
	// Same-origin requests from the server to itself are always safe —
	// the OAuth PIN consent form at /authorize is served from
	// ExternalURL and POSTs back to the same endpoint, carrying
	// Origin: <ExternalURL>. If the consumer didn't include their own
	// URL in WithAllowedOrigins, the form submission gets a 403
	// {"error":"origin not allowed"} and OAuth can never complete.
	//
	// Auto-inject ExternalURL's origin into the effective allowlist.
	// A same-origin POST cannot be a DNS-rebinding attack: the browser
	// can only be on that origin if the user trusts it. Leaves
	// WithAllowedOrigins free to describe *third-party* browser callers
	// (like https://claude.ai), which is the mental model consumers
	// reach for first.
	if len(s.allowedOrigins) > 0 {
		effective := s.allowedOrigins
		if self := selfOriginFromExternalURL(s.oauthConfig.ExternalURL); self != "" {
			seen := false
			for _, o := range effective {
				if o == self {
					seen = true
					break
				}
			}
			if !seen {
				effective = append(append([]string(nil), effective...), self)
			}
		}
		handler = auth.OriginAllowlistMiddleware(effective)(handler)
	}

	log.Printf("mcpserver: %s v%s listening on :%s", s.info.Name, s.info.Version, s.port)
	log.Printf("mcpserver: MCP endpoint: %s", s.mcpPath)
	log.Printf("mcpserver: bearer token configured: %v", s.bearerToken != "")
	log.Printf("mcpserver: token validator configured: %v", s.tokenValidator != nil)
	pinConfigured := pinAtHandlerBuild != ""
	log.Printf("mcpserver: OAuth PIN configured: %v", pinConfigured)
	if !pinConfigured {
		// OAuth endpoints are registered but the consent PIN is empty.
		// AuthorizePOST will reject every attempt with 500 "Server PIN
		// not configured". For static-bearer-only deployments this is
		// the intended state; flagging it prominently so operators
		// don't discover the misconfiguration on the first real
		// authorization attempt.
		log.Printf("mcpserver: =========================================================")
		log.Printf("mcpserver: WARNING: OAuth endpoints are mounted but no consent PIN is")
		log.Printf("mcpserver: configured. Set AUTH_PIN env or use WithPIN() to enable")
		log.Printf("mcpserver: OAuth consent. Static-bearer-only deployments may ignore")
		log.Printf("mcpserver: this warning; deployments expecting to serve claude.ai or")
		log.Printf("mcpserver: other OAuth clients will fail every PIN submission.")
		log.Printf("mcpserver: =========================================================")
	}
	if pinConfigured && len(pinAtHandlerBuild) < 8 {
		log.Printf("mcpserver: =========================================================")
		log.Printf("mcpserver: WARNING: AUTH_PIN is %d characters. With the current 5-per-", len(pinAtHandlerBuild))
		log.Printf("mcpserver: 15-minute rate limit per IP, short numeric PINs fall in")
		log.Printf("mcpserver: days from a single IP and minutes under modest IP")
		log.Printf("mcpserver: distribution. Consider 8+ chars with mixed case/digits.")
		log.Printf("mcpserver: =========================================================")
	}
	if s.oauthConfig.ExternalURL == "" {
		log.Printf("mcpserver: =========================================================")
		log.Printf("mcpserver: WARNING: WithExternalURL is not set. OAuth discovery will")
		log.Printf("mcpserver: only serve metadata to localhost clients. Non-localhost")
		log.Printf("mcpserver: discovery requests will receive HTTP 500. Set")
		log.Printf("mcpserver: WithExternalURL(\"https://...\") for production.")
		log.Printf("mcpserver: =========================================================")
	}

	srv := &http.Server{
		Addr:              ":" + s.port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      s.timeout + 10*time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown: listen for SIGINT/SIGTERM OR for ListenAndServe
	// to return on its own (e.g. bind failure). Either path releases the
	// signal goroutine so we don't leak it on abnormal startup.
	sigCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	serveDone := make(chan struct{})
	go func() {
		select {
		case <-sigCtx.Done():
			log.Println("mcpserver: shutting down...")
			shutCtx, shutCancel := context.WithTimeout(context.Background(), s.drainTime)
			defer shutCancel()
			if err := srv.Shutdown(shutCtx); err != nil {
				log.Printf("mcpserver: shutdown error: %v", err)
			}
		case <-serveDone:
			// ListenAndServe returned before any signal arrived. Nothing
			// to do — the defer on stopSignals releases signal.Notify.
		}
	}()

	serveErr := srv.ListenAndServe()
	close(serveDone)
	if serveErr != nil && serveErr != http.ErrServerClosed {
		return fmt.Errorf("mcpserver: %w", serveErr)
	}
	return nil
}

// selfOriginFromExternalURL extracts the origin (scheme://host[:port])
// from ExternalURL so it can be auto-included in the CORS allowlist.
// Returns "" if externalURL is empty or unparseable — the caller treats
// that as "no self-origin to inject." The server start-up validation
// already rejects malformed ExternalURL values, so returning "" here
// means the feature is simply not configured.
//
// Origin header format per RFC 6454: scheme "://" host [ ":" port ],
// with no trailing slash and no path. url.URL's Host field already
// includes the port when one is present in the source URL, which is
// exactly what we need.
func selfOriginFromExternalURL(externalURL string) string {
	if externalURL == "" {
		return ""
	}
	u, err := url.Parse(externalURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// RunHealthCheck performs an HTTP health check against localhost.
// Useful as a Docker HEALTHCHECK command in distroless images (no curl).
//
// Call from main() when os.Args[1] == "healthcheck":
//
//	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
//	    os.Exit(mcpserver.RunHealthCheck("8080"))
//	}
func RunHealthCheck(port string) int {
	resp, err := http.Get("http://localhost:" + port + "/health")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 1
	}
	return 0
}
