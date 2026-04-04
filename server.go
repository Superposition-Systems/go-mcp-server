package mcpserver

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Superposition-Systems/go-mcp-server/auth"
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
	mux         *http.ServeMux
	info        ServerInfo
	port        string
	timeout     time.Duration
	drainTime   time.Duration
	oauthStore  *auth.OAuthStore
	oauthConfig auth.OAuthConfig
	bearerToken string
	mcpPath     string
	tools       ToolHandler
	healthFunc  http.HandlerFunc
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
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
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

	// OAuth store
	oauthDBPath := os.Getenv("OAUTH_DB_PATH")
	if oauthDBPath == "" {
		oauthDBPath = "/data/oauth.db"
	}
	oauthStore, err := auth.NewOAuthStore(oauthDBPath, s.oauthConfig.Scope)
	if err != nil {
		return fmt.Errorf("mcpserver: oauth store: %w", err)
	}
	defer oauthStore.Close()
	s.oauthStore = oauthStore

	// OAuth cleanup goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				oauthStore.Cleanup()
			case <-ctx.Done():
				return
			}
		}
	}()

	oauthHandler := auth.NewOAuthHandler(oauthStore, s.oauthConfig)

	// Health
	healthHandler := s.healthFunc
	if healthHandler == nil {
		healthHandler = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"ok"}`)
		}
	}
	s.mux.HandleFunc("GET /health", healthHandler)
	s.mux.HandleFunc("GET /healthz", healthHandler)

	// MCP transport
	s.mux.HandleFunc("POST "+s.mcpPath, TransportHandler(s.info, s.tools))

	// OAuth endpoints
	s.mux.HandleFunc("GET /.well-known/oauth-authorization-server", oauthHandler.Discovery)
	s.mux.HandleFunc("GET /.well-known/oauth-protected-resource", oauthHandler.ProtectedResource)
	s.mux.HandleFunc("POST /register", oauthHandler.Register)
	s.mux.HandleFunc("GET /authorize", oauthHandler.AuthorizeGET)
	s.mux.HandleFunc("POST /authorize", oauthHandler.AuthorizePOST)
	s.mux.HandleFunc("POST /token", oauthHandler.Token)

	// Wrap with middleware: timeout + bearer auth
	bearerToken := s.bearerToken
	if bearerToken == "" {
		bearerToken = os.Getenv("BEARER_TOKEN")
	}
	authPIN := s.oauthConfig.PIN
	if authPIN == "" {
		authPIN = os.Getenv("AUTH_PIN")
	}
	s.oauthConfig.PIN = authPIN

	handler := auth.BearerMiddleware(bearerToken, oauthStore, s.mcpPath)(
		http.TimeoutHandler(s.mux, s.timeout, `{"error":"request timeout"}`),
	)

	log.Printf("mcpserver: %s v%s listening on :%s", s.info.Name, s.info.Version, s.port)
	log.Printf("mcpserver: MCP endpoint: %s", s.mcpPath)
	log.Printf("mcpserver: bearer token configured: %v", bearerToken != "")
	log.Printf("mcpserver: OAuth PIN configured: %v", authPIN != "")

	srv := &http.Server{
		Addr:    ":" + s.port,
		Handler: handler,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("mcpserver: shutting down...")
		shutCtx, shutCancel := context.WithTimeout(context.Background(), s.drainTime)
		defer shutCancel()
		srv.Shutdown(shutCtx)
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("mcpserver: %w", err)
	}
	return nil
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
	if err != nil || resp.StatusCode != 200 {
		return 1
	}
	return 0
}
