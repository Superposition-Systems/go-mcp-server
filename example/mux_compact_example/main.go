// Example MCP server demonstrating the v0.8.0 composition stack:
// Registry + Mux + CompactREST + parameter aliases + suggestion hook.
//
// Five mock tools are registered across two Categories ("Issues" and
// "Projects"). One tool ("jira_get_issue") returns a noisy payload with
// `self`, `expand`, and `avatarUrls` fields — the mux's CompactREST
// transformer strips these on the way out. Another tool declares its
// canonical parameter as `issueKey` and accepts `key` as a global alias;
// the alias middleware rewrites `key → issueKey` before dispatch.
// Unknown tool names and alias collisions are recorded to
// /tmp/mux_compact_suggest.jsonl by the suggestion hook.
//
// Run:
//
//	cd example/mux_compact_example
//	BEARER_TOKEN=devtoken AUTH_PIN=123456 go run .
//
// Exercise the four mux tools (requires bearer auth):
//
//	# 1. List mux tools (4 dispatcher tools, not 5 underlying tools)
//	curl -X POST http://localhost:8080/mcp \
//	  -H 'Accept: application/json, text/event-stream' \
//	  -H 'Content-Type: application/json' \
//	  -H 'Authorization: Bearer devtoken' \
//	  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
//
//	# 2. Execute with alias "key" (rewritten to "issueKey" internally)
//	curl -X POST http://localhost:8080/mcp \
//	  -H 'Accept: application/json, text/event-stream' \
//	  -H 'Content-Type: application/json' \
//	  -H 'Authorization: Bearer devtoken' \
//	  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"demo_execute","arguments":{"tool":"jira_get_issue","args":{"key":"ABC-1"}}}}'
//
//	# 3. Execute with typo "jira_get_isue" → fuzzy suggestion in error
//	curl -X POST http://localhost:8080/mcp \
//	  -H 'Accept: application/json, text/event-stream' \
//	  -H 'Content-Type: application/json' \
//	  -H 'Authorization: Bearer devtoken' \
//	  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"demo_execute","arguments":{"tool":"jira_get_isue","args":{}}}}'
//
//	# 4. Render the auto-generated skill (tools grouped by Category)
//	curl -X POST http://localhost:8080/mcp \
//	  -H 'Accept: application/json, text/event-stream' \
//	  -H 'Content-Type: application/json' \
//	  -H 'Authorization: Bearer devtoken' \
//	  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"demo_get_skill","arguments":{}}}'
//
// After typo / alias-collision calls, inspect the suggestion log:
//
//	cat /tmp/mux_compact_suggest.jsonl
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	mcp "github.com/Superposition-Systems/go-mcp-server"
	"github.com/Superposition-Systems/go-mcp-server/suggest"
)

// schema is a small helper that produces a flat JSON Schema suitable for
// ExtractParams (no $ref, no oneOf/allOf at root).
func schema(props map[string]string, required ...string) json.RawMessage {
	p := map[string]any{}
	for name, typ := range props {
		p[name] = map[string]any{"type": typ}
	}
	req := make([]string, 0, len(required))
	req = append(req, required...)
	s := map[string]any{
		"type":       "object",
		"properties": p,
	}
	if len(req) > 0 {
		s["required"] = req
	}
	b, _ := json.Marshal(s)
	return json.RawMessage(b)
}

func main() {
	// Docker healthcheck mode (distroless has no curl).
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(mcp.RunHealthCheck(envOr("PORT", "8080")))
	}

	bearerToken := os.Getenv("BEARER_TOKEN")
	if bearerToken == "" && os.Getenv("AUTH_PIN") == "" {
		log.Fatal("mux_compact_example: BEARER_TOKEN or AUTH_PIN must be set")
	}

	// ── Registry: 5 tools across 2 Categories ───────────────────────────
	reg := mcp.NewRegistry()

	// Issues category.
	reg.MustRegister(mcp.Tool{
		Name:        "jira_get_issue",
		Description: "Fetch a Jira issue by key. Returns the full REST payload; CompactREST strips self/expand/avatarUrls.",
		Category:    "Issues",
		InputSchema: schema(map[string]string{
			"issueKey": "string",
		}, "issueKey"),
		// Per-tool alias kept empty; global alias map in WithParamAliases
		// covers "key → issueKey" for every tool.
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			key, _ := args["issueKey"].(string)
			if key == "" {
				key = "ABC-1"
			}
			// Noisy REST envelope — CompactREST strips the junk.
			return map[string]any{
				"self":   "https://example.atlassian.net/rest/api/3/issue/" + key,
				"expand": "renderedFields,names",
				"key":    key,
				"fields": map[string]any{
					"summary": "Example issue " + key,
					"reporter": map[string]any{
						"displayName": "Az",
						"avatarUrls": map[string]any{
							"48x48": "https://example.atlassian.net/avatar/48",
							"24x24": "https://example.atlassian.net/avatar/24",
						},
					},
				},
			}, nil
		},
	})

	reg.MustRegister(mcp.Tool{
		Name:        "jira_search_issues",
		Description: "Search issues by JQL.",
		Category:    "Issues",
		InputSchema: schema(map[string]string{
			"jql":        "string",
			"maxResults": "number",
		}, "jql"),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return map[string]any{"issues": []any{}}, nil
		},
	})

	reg.MustRegister(mcp.Tool{
		Name:        "jira_create_issue",
		Description: "Create a new Jira issue.",
		Category:    "Issues",
		Tags:        []string{"destructive"},
		InputSchema: schema(map[string]string{
			"projectKey": "string",
			"summary":    "string",
		}, "projectKey", "summary"),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return map[string]any{"id": "10001", "key": "NEW-1"}, nil
		},
	})

	// Projects category.
	reg.MustRegister(mcp.Tool{
		Name:        "jira_list_projects",
		Description: "List all projects visible to the caller.",
		Category:    "Projects",
		InputSchema: schema(map[string]string{}),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return map[string]any{"projects": []any{}}, nil
		},
	})

	reg.MustRegister(mcp.Tool{
		Name:        "jira_get_project",
		Description: "Fetch a single project's metadata.",
		Category:    "Projects",
		InputSchema: schema(map[string]string{
			"projectKey": "string",
		}, "projectKey"),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return map[string]any{"key": args["projectKey"], "name": "Demo"}, nil
		},
	})

	// ── Mux: wraps the registry as 4 dispatcher tools ───────────────────
	mux := mcp.NewMux(reg, mcp.MuxConfig{
		Prefix:  "demo",
		Compact: true,
		Skill: mcp.DefaultSkillBuilder(mcp.SkillOptions{
			Title: "Demo MCP — Routing Guide",
			Intro: "Five tools across two categories. Use `demo_execute` with `{tool, args}` to dispatch.",
			Featured: []mcp.Featured{
				{Section: "Jira — Issues", Tools: []string{"jira_get_issue", "jira_search_issues"}},
				{Section: "Jira — Projects", Tools: []string{"jira_list_projects", "jira_get_project"}},
			},
			Categorise: true,
		}),
		HealthCheck: func(ctx context.Context) (map[string]any, error) {
			return map[string]any{"ok": true}, nil
		},
	})

	// ── Server: compose middleware, aliases, and suggestion hook ────────
	srv := mcp.New(
		mcp.WithName("mux-compact-example"),
		mcp.WithVersion("0.1.0"),
		mcp.WithInstructions("Demonstrates Registry + Mux + CompactREST + aliases + suggestion hook."),
		mcp.WithPort(envOr("PORT", "8080")),
		mcp.WithBearerToken(bearerToken),
		mcp.WithPIN(os.Getenv("AUTH_PIN")),
		mcp.WithExternalURL(os.Getenv("EXTERNAL_URL")),
		mcp.WithConsent("Demo MCP", "Enter PIN to connect."),
		// Global alias: every tool that declares `issueKey` accepts `key`
		// as an equivalent. LLMs consistently guess the shorter form.
		mcp.WithParamAliases(map[string]string{
			"key": "issueKey",
		}),
		// Compact REST envelopes by default. When mux compaction is on
		// via MuxConfig.Compact, each dispatched tool's result is passed
		// through this transformer before serialisation.
		mcp.WithResponseTransformer(mcp.CompactREST()),
		// Suggestion telemetry: one JSON line per unknown-name /
		// alias-collision event.
		mcp.WithSuggestionHook(suggest.JSONLFile("/tmp/mux_compact_suggest.jsonl")),
	)

	srv.RegisterTools(mux.AsToolHandler())

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
