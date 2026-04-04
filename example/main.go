// Example MCP server demonstrating the API-first pattern.
//
// This server:
//  1. Defines REST API endpoints (the "API first" part)
//  2. Implements ToolHandler to expose the same logic via MCP
//  3. Uses mcpserver.Server to serve both from a single binary
//
// Run:
//
//	cd example && go run .
//
// Test health:
//
//	curl http://localhost:8080/health
//
// Test REST API:
//
//	curl http://localhost:8080/api/v1/greet?name=World
//
// Test MCP (requires Bearer token):
//
//	curl -X POST http://localhost:8080/mcp \
//	  -H "Content-Type: application/json" \
//	  -H "Accept: application/json, text/event-stream" \
//	  -H "Authorization: Bearer test-token" \
//	  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	mcpserver "github.com/Superposition-Systems/go-mcp-server"
)

func main() {
	// Docker healthcheck mode (distroless has no curl)
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(mcpserver.RunHealthCheck("8080"))
	}

	// 1. Create server
	srv := mcpserver.New(
		mcpserver.WithName("example-mcp"),
		mcpserver.WithVersion("0.1.0"),
		mcpserver.WithInstructions("An example MCP server that greets people."),
		mcpserver.WithPort(envOr("PORT", "8080")),
		mcpserver.WithPIN(envOr("AUTH_PIN", "1234")),
		mcpserver.WithBearerToken(envOr("BEARER_TOKEN", "test-token")),
		mcpserver.WithConsent("Example MCP", "Enter the PIN to connect."),
	)

	// 2. Mount REST API first
	srv.Mux().HandleFunc("GET /api/v1/greet", greetHandler)

	// 3. Register MCP tools (wrapping the same business logic)
	srv.RegisterTools(&GreetTools{})

	// 4. Start
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// --- Business logic (shared by REST and MCP) ---

func greet(name string) string {
	if name == "" {
		name = "World"
	}
	return fmt.Sprintf("Hello, %s!", name)
}

// --- REST handler ---

func greetHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"greeting": greet(name)})
}

// --- MCP ToolHandler ---

type GreetTools struct{}

func (g *GreetTools) ListTools() []mcpserver.ToolDef {
	return []mcpserver.ToolDef{
		{
			Name:        "greet",
			Description: "Greet someone by name.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{"type": "string", "description": "Name to greet"},
				},
				"additionalProperties": false,
			},
		},
	}
}

func (g *GreetTools) Call(_ context.Context, name string, args map[string]any) (any, bool) {
	switch name {
	case "greet":
		personName, _ := args["name"].(string)
		return map[string]string{"greeting": greet(personName)}, false
	default:
		return map[string]string{"error": "unknown tool: " + name}, true
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
