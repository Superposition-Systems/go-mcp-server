// Example MCP server demonstrating the v0.8.0 ops-facing subpackages:
// diag (SQLite ring-buffer logger) + config (KV store with write-through)
// + webhook (signature-verified HTTP routes).
//
// The diag logger installs as tool-call middleware (every dispatch is
// timestamped into its SQLite file) and auto-registers three query tools.
// The config store auto-registers config_get/set/list/delete. Both stores
// use per-process temporary directories so the example is self-contained
// — swap the paths for /data/server-logs.db and /data/config.db in a
// real deployment.
//
// Two webhook endpoints are mounted on srv.Mux() outside the /mcp path:
//
//	POST /webhooks/github   — HMAC-SHA256 (X-Hub-Signature-256 header)
//	POST /webhooks/jira     — BearerOrQuerySecret (?secret= query)
//
// Run:
//
//	cd example/diag_config_webhook_example
//	BEARER_TOKEN=devtoken AUTH_PIN=123456 \
//	  GITHUB_SECRET=ghsecret JIRA_SECRET=jirasecret \
//	  go run .
//
// Test GitHub webhook (bad signature → 401):
//
//	curl -v -X POST http://localhost:8080/webhooks/github \
//	  -H 'X-Hub-Signature-256: sha256=deadbeef' \
//	  -H 'Content-Type: application/json' \
//	  -d '{"action":"opened"}'
//
// Test GitHub webhook with correct signature:
//
//	BODY='{"action":"opened"}'
//	SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$GITHUB_SECRET" | awk '{print $2}')
//	curl -v -X POST http://localhost:8080/webhooks/github \
//	  -H "X-Hub-Signature-256: sha256=$SIG" \
//	  -H 'Content-Type: application/json' \
//	  -d "$BODY"
//
// Test Jira webhook (query secret):
//
//	curl -v -X POST "http://localhost:8080/webhooks/jira?secret=$JIRA_SECRET" \
//	  -H 'Content-Type: application/json' \
//	  -d '{"issue":{"key":"ABC-1"}}'
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"

	mcp "github.com/Superposition-Systems/go-mcp-server"
	"github.com/Superposition-Systems/go-mcp-server/config"
	"github.com/Superposition-Systems/go-mcp-server/diag"
	"github.com/Superposition-Systems/go-mcp-server/webhook"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(mcp.RunHealthCheck(envOr("PORT", "8080")))
	}

	bearerToken := os.Getenv("BEARER_TOKEN")
	if bearerToken == "" && os.Getenv("AUTH_PIN") == "" {
		log.Fatal("diag_config_webhook_example: BEARER_TOKEN or AUTH_PIN must be set")
	}

	// ── Per-process storage (swap for /data/... in production) ──────────
	tmp, err := os.MkdirTemp("", "mcp-diag-config-")
	if err != nil {
		log.Fatalf("mktemp: %v", err)
	}
	log.Printf("diag_config_webhook_example: storing logs/config under %s", tmp)

	// ── Diagnostic logger ───────────────────────────────────────────────
	dl, err := diag.New(diag.Config{
		DBPath:            filepath.Join(tmp, "logs.db"),
		RingSize:          1000,
		Categories:        []string{"request", "tool", "auth", "api", "lifecycle", "error"},
		AutoRegisterTools: true,
		ElevationRequired: false, // demo convenience — production should leave this true
	})
	if err != nil {
		log.Fatalf("diag.New: %v", err)
	}
	defer dl.Close()

	// ── Config store ────────────────────────────────────────────────────
	cs, err := config.Open(config.Options{
		DBPath:          filepath.Join(tmp, "config.db"),
		CredentialsFile: filepath.Join(tmp, "creds.txt"),
		EnvFallback:     true,
	})
	if err != nil {
		log.Fatalf("config.Open: %v", err)
	}
	defer cs.Close()

	// ── Registry: a couple of demo tools + auto-registered diag/config ──
	reg := mcp.NewRegistry()
	reg.MustRegister(mcp.Tool{
		Name:        "ping",
		Description: "Return pong. Demonstrates that diag middleware logs tool calls.",
		Category:    "Demo",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return map[string]any{"pong": true}, nil
		},
	})
	if err := dl.RegisterTools(reg); err != nil {
		log.Fatalf("diag.RegisterTools: %v", err)
	}
	if err := cs.RegisterTools(reg); err != nil {
		log.Fatalf("config.RegisterTools: %v", err)
	}

	// ── Server: install diag middleware for the tool-call chain ─────────
	srv := mcp.New(
		mcp.WithName("diag-config-webhook-example"),
		mcp.WithVersion("0.1.0"),
		mcp.WithInstructions("Demonstrates diag + config + webhook composition."),
		mcp.WithPort(envOr("PORT", "8080")),
		mcp.WithBearerToken(bearerToken),
		mcp.WithPIN(os.Getenv("AUTH_PIN")),
		mcp.WithExternalURL(os.Getenv("EXTERNAL_URL")),
		mcp.WithConsent("Diag+Config+Webhook Demo", "Enter PIN to connect."),
		mcp.WithToolMiddleware(dl.Middleware()),
	)

	srv.RegisterTools(reg.AsToolHandler())

	// ── Webhook router mounted on the server's raw ServeMux ─────────────
	router := webhook.NewRouter(srv.Mux())

	githubSecret := os.Getenv("GITHUB_SECRET")
	router.Handle("/webhooks/github",
		webhook.HMACSHA256(githubSecret, "X-Hub-Signature-256"),
		http.HandlerFunc(githubHandler),
	)

	jiraSecret := os.Getenv("JIRA_SECRET")
	router.Handle("/webhooks/jira",
		webhook.BearerOrQuerySecret(jiraSecret, "secret"),
		http.HandlerFunc(jiraHandler),
	)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// githubHandler receives verified GitHub webhook deliveries. In a real
// deployment this typically fans the event out to a pipeline queue.
func githubHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("github webhook: %s %s event=%s",
		r.Method, r.URL.Path, r.Header.Get("X-GitHub-Event"))
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(`{"accepted":true}`)); err != nil {
		log.Printf("github webhook: write: %v", err)
	}
}

// jiraHandler receives verified Jira webhook deliveries.
func jiraHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("jira webhook: %s %s", r.Method, r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(`{"accepted":true}`)); err != nil {
		log.Printf("jira webhook: write: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
