// Package mcpserver_test holds the v0.8.0 six-point composition contract
// from docs/plans/v0.8.0-middleware-and-registry.md §8.1 Phase 4.
//
// This file is the integration truth-test for v0.8.0: a single wired-up
// Server exercising Registry + Mux + CompactREST + parameter aliases +
// suggestion hook + diag middleware + schema validator + webhook router,
// asserting the documented end-to-end behaviour.
//
// Phase 0 status: every helper compiles, but most production semantics
// live in tracks that have not yet merged. Each subtest is annotated
// with the track(s) it depends on and currently calls t.Skip — the suite
// stays green while the rest of v0.8.0 lands. Removing the t.Skip line
// is the visible TODO at each merge gate.
//
// Tightening order (one line per subtest):
//
//	(1) needs track 2A (real fuzzy + JSONLFile) + track 3B (mux unknown-tool dispatch)
//	(2) needs track 3A (alias middleware) + track 1B (middleware wiring in transport)
//	(3) needs track 3A + track 2A + track 1B
//	(4) needs track 3B (DefaultSkillBuilder) + track 2C (ExtractParams)
//	(5) needs track 1B (transport-layer middleware wiring + isError contract)
//	(6) needs track 2D (real HMAC verification) — Session 4 sibling
//
// Subtest (6) is intentionally ordered first; it depends only on Session 4's
// own sibling track and is the cheapest scaffold-compiles smoke check.
package mcpserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	mcp "github.com/Superposition-Systems/go-mcp-server"
	"github.com/Superposition-Systems/go-mcp-server/diag"
	"github.com/Superposition-Systems/go-mcp-server/suggest"
	"github.com/Superposition-Systems/go-mcp-server/webhook"
)

// compositionFixture wires every v0.8.0 facility into a single Server +
// http.ServeMux. Returned mux serves both the MCP transport at /mcp and
// the webhook routes at /webhooks/*.
type compositionFixture struct {
	srv               *mcp.Server
	mux               *http.ServeMux
	registry          *mcp.Registry
	jsonlPath         string
	capturedArgs      *capturedArgs
	webhookCalled     *atomic.Bool
	webhookSecret     string
	webhookSigHeader  string
}

// capturedArgs gives subtest (2) and (3) a thread-safe pocket the tool
// handler closes over to record the arguments it actually received.
type capturedArgs struct {
	mu   sync.Mutex
	last map[string]any
}

func (c *capturedArgs) set(args map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make(map[string]any, len(args))
	for k, v := range args {
		cp[k] = v
	}
	c.last = cp
}

func (c *capturedArgs) get() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

func newCompositionFixture(t *testing.T) *compositionFixture {
	t.Helper()

	tmp := t.TempDir()
	jsonlPath := filepath.Join(tmp, "suggest.jsonl")

	captured := &capturedArgs{}
	webhookCalled := &atomic.Bool{}

	// ── Diagnostic logger (middleware-only; tools not registered here) ──
	dl, err := diag.New(diag.Config{
		DBPath:            filepath.Join(tmp, "logs.db"),
		RingSize:          1000,
		AutoRegisterTools: false,
		ElevationRequired: false,
	})
	if err != nil {
		t.Fatalf("diag.New: %v", err)
	}
	t.Cleanup(func() { _ = dl.Close() })

	// ── Registry: 3 tools, 2 categories, 1 schema declares `issueKey` ──
	reg := mcp.NewRegistry()

	reg.MustRegister(mcp.Tool{
		Name:        "jiraGetIssue",
		Description: "Fetch a Jira issue by key.",
		Category:    "Issues",
		InputSchema: json.RawMessage(`{
			"type":"object",
			"properties":{"issueKey":{"type":"string","description":"Issue key"}},
			"required":["issueKey"]
		}`),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			captured.set(args)
			return map[string]any{"key": args["issueKey"], "ok": true}, nil
		},
	})

	reg.MustRegister(mcp.Tool{
		Name:        "jiraListProjects",
		Description: "List Jira projects.",
		Category:    "Projects",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return map[string]any{"projects": []any{}}, nil
		},
	})

	// Subtest (5): a tool that returns a tool-level error (e.g. 404). Per
	// §3.3 the middleware chain must surface this as isError:true with
	// err==nil — not a library failure.
	reg.MustRegister(mcp.Tool{
		Name:        "jiraGetMissingIssue",
		Description: "Always returns 404; exercises §3.3 error-category contract.",
		Category:    "Issues",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return nil, fmt.Errorf("404 not found")
		},
	})

	// ── Mux: wraps the underlying registry as 4 dispatcher tools ────────
	//
	// SuggestionHook and GlobalParamAliases are also set here because the
	// outer Server chain cannot descend into atlassian_execute's nested
	// payload — unknown-tool + alias-collision events fire from inside the
	// mux's execute handler. Sharing the same JSONLFile path across both
	// sinks is intentional: every event of any kind lands in one file.
	muxSuggestHook := suggest.JSONLFile(jsonlPath)
	mux := mcp.NewMux(reg, mcp.MuxConfig{
		Prefix:             "demo",
		Compact:            true,
		SuggestionHook:     muxSuggestHook,
		GlobalParamAliases: map[string]string{"key": "issueKey"},
		Skill: mcp.DefaultSkillBuilder(mcp.SkillOptions{
			Title:      "Composition Test — Routing Guide",
			Intro:      "Three tools across two categories.",
			Featured:   []mcp.Featured{{Section: "Issues", Tools: []string{"jiraGetIssue"}}},
			Categorise: true,
		}),
	})

	// ── Server: every v0.8.0 option in one place ────────────────────────
	srv := mcp.New(
		mcp.WithName("composition-test"),
		mcp.WithVersion("0.0.0-test"),
		mcp.WithToolMiddleware(dl.Middleware()),
		mcp.WithParamAliases(map[string]string{"key": "issueKey"}),
		mcp.WithSuggestionHook(suggest.JSONLFile(jsonlPath)),
		mcp.WithInputValidation(mcp.ValidationStrict()),
		mcp.WithResponseTransformer(mcp.CompactREST()),
	)
	srv.RegisterTools(mux.AsToolHandler())

	// ── HTTP scaffolding: serve MCP + webhooks from one ServeMux ───────
	//
	// We mount TransportHandlerWithMiddleware with srv.ToolCallChain() so
	// each subtest POSTs to /mcp and drives the full Server-level middleware
	// chain (user middlewares → alias rewriter → validator → transformer →
	// dispatch) without the bearer-auth / OAuth bootstrap that
	// Server.ListenAndServe wires up.
	httpMux := srv.Mux()
	info := mcp.ServerInfo{
		Name:    "composition-test",
		Version: "0.0.0-test",
	}
	httpMux.HandleFunc("POST /mcp", mcp.TransportHandlerWithMiddleware(info, mux.AsToolHandler(), srv.ToolCallChain()))

	// ── Webhook: HMAC-protected route used by subtest (6) ──────────────
	router := webhook.NewRouter(httpMux)
	router.Handle("/webhooks/github",
		webhook.HMACSHA256("secret", "X-Hub-Signature-256"),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			webhookCalled.Store(true)
			w.WriteHeader(http.StatusOK)
		}),
	)

	return &compositionFixture{
		srv:              srv,
		mux:              httpMux,
		registry:         reg,
		jsonlPath:        jsonlPath,
		capturedArgs:     captured,
		webhookCalled:    webhookCalled,
		webhookSecret:    "secret",
		webhookSigHeader: "X-Hub-Signature-256",
	}
}

// callTool issues a JSON-RPC tools/call against the test server's /mcp
// handler and returns the parsed JSONRPCResponse plus the raw SSE body.
func (f *compositionFixture) callTool(t *testing.T, ts *httptest.Server, toolName string, args map[string]any) (mcp.JSONRPCResponse, string) {
	t.Helper()
	params := map[string]any{"name": toolName, "arguments": args}
	rawParams, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	body := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  rawParams,
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/mcp", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	raw := buf.String()
	// SSE body is "event: message\ndata: {json}\n\n"; parse the data line.
	var rpc mcp.JSONRPCResponse
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "data: ") {
			if err := json.Unmarshal([]byte(line[len("data: "):]), &rpc); err != nil {
				t.Fatalf("parse SSE data: %v (raw=%q)", err, raw)
			}
			return rpc, raw
		}
	}
	t.Fatalf("no SSE data line in response: %q", raw)
	return rpc, raw
}

// readJSONL returns the slice of decoded suggest.Event lines written to
// path, or an empty slice if the file does not yet exist.
func readJSONL(t *testing.T, path string) []suggest.Event {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read jsonl %s: %v", path, err)
	}
	var out []suggest.Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e suggest.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("parse jsonl line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

// TestComposition_SixPointContract asserts the six end-to-end behaviours
// from §8.1 Phase 4. See the file-level comment for the per-subtest skip
// strategy and the tracks each subtest tightens against.
func TestComposition_SixPointContract(t *testing.T) {
	// Subtest (6) runs first as the cheapest scaffold-compiles smoke
	// check — it touches only the webhook router and atomic flag, no
	// MCP transport at all. The five MCP-stack subtests follow.

	t.Run("6_webhook_bad_hmac_returns_401_before_handler", func(t *testing.T) {

		fx := newCompositionFixture(t)
		ts := httptest.NewServer(fx.mux)
		defer ts.Close()

		fx.webhookCalled.Store(false)
		req, err := http.NewRequest(http.MethodPost,
			ts.URL+"/webhooks/github",
			strings.NewReader(`{"action":"opened"}`))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set(fx.webhookSigHeader, "sha256=deadbeef") // wrong sig
		req.Header.Set("Content-Type", "application/json")

		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status: got %d, want 401", resp.StatusCode)
		}
		if fx.webhookCalled.Load() {
			t.Error("handler ran despite bad signature — verifier should short-circuit")
		}
	})

	t.Run("1_misspelled_tool_emits_fuzzy_error_and_jsonl_line", func(t *testing.T) {

		fx := newCompositionFixture(t)
		ts := httptest.NewServer(fx.mux)
		defer ts.Close()

		rpc, _ := fx.callTool(t, ts, "demo_execute", map[string]any{
			"tool": "jiraGetIsue", // typo for jiraGetIssue
			"args": map[string]any{},
		})

		// Response should carry "did you mean" text in the content array.
		gotResult, _ := json.Marshal(rpc.Result)
		if !strings.Contains(strings.ToLower(string(gotResult)), "did you mean") {
			t.Errorf("expected 'did you mean' in response, got: %s", gotResult)
		}

		// One JSONL line with Kind="tool", Requested="jiraGetIsue".
		events := readJSONL(t, fx.jsonlPath)
		var found bool
		for _, e := range events {
			if e.Kind == suggest.EventUnknownTool && e.Requested == "jiraGetIsue" {
				found = true
				if e.Suggested == "" {
					t.Error("suggested name was empty; fuzzy match should produce a candidate")
				}
				break
			}
		}
		if !found {
			t.Errorf("no EventUnknownTool with Requested=jiraGetIsue in %v", events)
		}
	})

	t.Run("2_alias_resolves_to_canonical_before_handler", func(t *testing.T) {

		fx := newCompositionFixture(t)
		ts := httptest.NewServer(fx.mux)
		defer ts.Close()

		_, _ = fx.callTool(t, ts, "demo_execute", map[string]any{
			"tool": "jiraGetIssue",
			"args": map[string]any{"key": "ABC-1"},
		})

		got := fx.capturedArgs.get()
		if got == nil {
			t.Fatal("handler was not called")
		}
		if v, _ := got["issueKey"].(string); v != "ABC-1" {
			t.Errorf("handler args[issueKey]: got %q, want %q", v, "ABC-1")
		}
		if _, present := got["key"]; present {
			t.Errorf("handler args still contains alias 'key': %v", got)
		}
	})

	t.Run("3_alias_collision_drops_alias_and_writes_jsonl", func(t *testing.T) {

		fx := newCompositionFixture(t)
		ts := httptest.NewServer(fx.mux)
		defer ts.Close()

		_, _ = fx.callTool(t, ts, "demo_execute", map[string]any{
			"tool": "jiraGetIssue",
			"args": map[string]any{"key": "WRONG", "issueKey": "RIGHT"},
		})

		got := fx.capturedArgs.get()
		if got == nil {
			t.Fatal("handler was not called")
		}
		if v, _ := got["issueKey"].(string); v != "RIGHT" {
			t.Errorf("handler args[issueKey]: got %q, want %q (canonical must win on collision)", v, "RIGHT")
		}
		if _, present := got["key"]; present {
			t.Errorf("handler args still contains dropped alias 'key': %v", got)
		}

		events := readJSONL(t, fx.jsonlPath)
		var found bool
		for _, e := range events {
			if e.Kind == suggest.EventAliasCollision &&
				e.Requested == "key" &&
				e.Suggested == "issueKey" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no EventAliasCollision{Requested:key, Suggested:issueKey} in %v", events)
		}
	})

	t.Run("4_get_skill_renders_categories_and_signatures", func(t *testing.T) {

		fx := newCompositionFixture(t)
		ts := httptest.NewServer(fx.mux)
		defer ts.Close()

		rpc, _ := fx.callTool(t, ts, "demo_get_skill", map[string]any{})

		// The skill content lives in result.content[0].text after the
		// transport wraps it. Stringify the whole result for a robust
		// substring search.
		blob, _ := json.Marshal(rpc.Result)
		text := string(blob)

		for _, cat := range fx.registry.Categories() {
			if !strings.Contains(text, cat) {
				t.Errorf("skill output missing category %q in: %s", cat, text)
			}
		}
		// At least one rendered signature like `jiraGetIssue(issueKey: string)`.
		if !strings.Contains(text, "issueKey") || !strings.Contains(text, "string") {
			t.Errorf("skill output missing rendered parameter signature; got: %s", text)
		}
	})

	t.Run("5_tool_level_404_yields_isError_true_err_nil", func(t *testing.T) {

		fx := newCompositionFixture(t)
		ts := httptest.NewServer(fx.mux)
		defer ts.Close()

		rpc, _ := fx.callTool(t, ts, "demo_execute", map[string]any{
			"tool": "jiraGetMissingIssue",
			"args": map[string]any{},
		})

		// The library-level error channel must be empty: this is a
		// successful call that reports a tool-level error, not a
		// middleware short-circuit.
		if rpc.Error != nil {
			t.Errorf("expected no JSON-RPC error, got %+v", rpc.Error)
		}
		// The result envelope should mark isError:true.
		resultMap, ok := rpc.Result.(map[string]any)
		if !ok {
			t.Fatalf("result is not a map: %T %+v", rpc.Result, rpc.Result)
		}
		isError, _ := resultMap["isError"].(bool)
		if !isError {
			t.Errorf("expected isError:true, got %+v", resultMap)
		}
	})
}
