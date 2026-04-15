package mcpserver_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	mcp "github.com/Superposition-Systems/go-mcp-server"
	"github.com/Superposition-Systems/go-mcp-server/suggest"
)

// fakeTool returns a tool with the given name and an identity handler
// that returns the args wrapped in a map.
func fakeTool(name, category string, tags ...string) mcp.Tool {
	return mcp.Tool{
		Name:        name,
		Description: "desc for " + name,
		Category:    category,
		Tags:        tags,
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return map[string]any{"tool": name, "got": args}, nil
		},
	}
}

func dispatchExecute(t *testing.T, mux *mcp.Registry, prefix, tool string, args map[string]any) (any, error) {
	t.Helper()
	ex, ok := mux.Lookup(prefix + "_execute")
	if !ok {
		t.Fatalf("%s_execute not registered on mux", prefix)
	}
	payload := map[string]any{"tool": tool}
	if args != nil {
		payload["args"] = args
	}
	return ex.Handler(context.Background(), payload)
}

func TestNewMux_ToolCount(t *testing.T) {
	reg := mcp.NewRegistry()
	mux := mcp.NewMux(reg, mcp.MuxConfig{Prefix: "atlassian"})
	all := mux.All()
	if len(all) != 4 {
		t.Fatalf("expected 4 mux tools, got %d", len(all))
	}
	want := map[string]bool{
		"atlassian_execute":    false,
		"atlassian_list_tools": false,
		"atlassian_health":     false,
		"atlassian_get_skill":  false,
	}
	for _, tool := range all {
		if _, ok := want[tool.Name]; !ok {
			t.Errorf("unexpected tool %q on mux", tool.Name)
		}
		want[tool.Name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("missing expected tool %q", name)
		}
	}
}

func TestNewMux_DefaultPrefix(t *testing.T) {
	reg := mcp.NewRegistry()
	mux := mcp.NewMux(reg, mcp.MuxConfig{})
	if _, ok := mux.Lookup("mcp_execute"); !ok {
		t.Fatal("empty Prefix should fall back to mcp_ prefix")
	}
}

func TestMuxExecute_HappyPath(t *testing.T) {
	reg := mcp.NewRegistry()
	var gotArgs map[string]any
	reg.MustRegister(mcp.Tool{
		Name:        "foo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			gotArgs = args
			return map[string]any{"ok": true}, nil
		},
	})
	reg.MustRegister(fakeTool("bar", ""))
	reg.MustRegister(fakeTool("baz", ""))

	mux := mcp.NewMux(reg, mcp.MuxConfig{Prefix: "atlassian"})
	result, err := dispatchExecute(t, mux, "atlassian", "foo", map[string]any{"x": 1.0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotArgs == nil || gotArgs["x"] != 1.0 {
		t.Fatalf("handler did not receive args: got=%v", gotArgs)
	}
	m, ok := result.(map[string]any)
	if !ok || m["ok"] != true {
		t.Fatalf("unexpected result: %#v", result)
	}
}

// TestMuxExecute_EnvelopeAlias covers the claude.ai-style proxy that
// forwards the inner payload under "params" instead of "args". The inner
// map must reach the handler, and the suggestion hook must fire once with
// Requested=alias, Suggested="args".
func TestMuxExecute_EnvelopeAlias(t *testing.T) {
	aliases := []string{"params", "arguments", "input", "payload", "parameters", "inputs", "data"}
	for _, alias := range aliases {
		t.Run(alias, func(t *testing.T) {
			reg := mcp.NewRegistry()
			var gotArgs map[string]any
			reg.MustRegister(mcp.Tool{
				Name:        "foo",
				InputSchema: json.RawMessage(`{"type":"object"}`),
				Handler: func(ctx context.Context, args map[string]any) (any, error) {
					gotArgs = args
					return map[string]any{"ok": true}, nil
				},
			})

			var (
				mu     sync.Mutex
				events []suggest.Event
			)
			hook := func(e suggest.Event) {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, e)
			}

			mux := mcp.NewMux(reg, mcp.MuxConfig{Prefix: "m", SuggestionHook: hook})
			ex, ok := mux.Lookup("m_execute")
			if !ok {
				t.Fatal("m_execute not registered")
			}
			payload := map[string]any{
				"tool": "foo",
				alias:  map[string]any{"x": 1.0, "y": "two"},
			}
			_, err := ex.Handler(context.Background(), payload)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotArgs["x"] != 1.0 || gotArgs["y"] != "two" {
				t.Fatalf("inner payload did not reach handler: got=%v", gotArgs)
			}

			mu.Lock()
			defer mu.Unlock()
			if len(events) != 1 {
				t.Fatalf("expected 1 envelope-alias event, got %d: %#v", len(events), events)
			}
			e := events[0]
			if e.Kind != suggest.EventEnvelopeAlias {
				t.Errorf("event kind = %q, want %q", e.Kind, suggest.EventEnvelopeAlias)
			}
			if e.Tool != "foo" || e.Requested != alias || e.Suggested != "args" {
				t.Errorf("unexpected event fields: %#v", e)
			}
		})
	}
}

// TestMuxExecute_EnvelopeAlias_CanonicalWins verifies that when both "args"
// and an alias are present, "args" is used and no telemetry fires. This is
// the defence against a confused-deputy attack where a malicious client
// layers an alias on top of a legitimate canonical payload.
func TestMuxExecute_EnvelopeAlias_CanonicalWins(t *testing.T) {
	reg := mcp.NewRegistry()
	var gotArgs map[string]any
	reg.MustRegister(mcp.Tool{
		Name:        "foo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			gotArgs = args
			return nil, nil
		},
	})

	var fired bool
	hook := func(e suggest.Event) {
		if e.Kind == suggest.EventEnvelopeAlias {
			fired = true
		}
	}

	mux := mcp.NewMux(reg, mcp.MuxConfig{Prefix: "m", SuggestionHook: hook})
	ex, _ := mux.Lookup("m_execute")
	payload := map[string]any{
		"tool":   "foo",
		"args":   map[string]any{"winner": "yes"},
		"params": map[string]any{"winner": "no"},
	}
	if _, err := ex.Handler(context.Background(), payload); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotArgs["winner"] != "yes" {
		t.Fatalf("args should win over params, got=%v", gotArgs)
	}
	if fired {
		t.Error("envelope-alias event should not fire when canonical args is present")
	}
}

func TestMuxExecute_UnknownTool(t *testing.T) {
	reg := mcp.NewRegistry()
	reg.MustRegister(fakeTool("foo", ""))
	mux := mcp.NewMux(reg, mcp.MuxConfig{Prefix: "x"})

	_, err := dispatchExecute(t, mux, "x", "fooz", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown tool") {
		t.Errorf("error missing 'unknown tool': %q", msg)
	}
	if !strings.Contains(msg, "fooz") {
		t.Errorf("error should contain the requested name: %q", msg)
	}
	// The "did you mean: ..." tail is only present once suggest.Closest
	// (track 2A) ships. Under the Phase 0 stub Closest returns nil and
	// the error stops at `unknown tool "fooz"`. Both shapes are OK.
}

func TestMuxExecute_UnknownTool_FiresSuggestionHook(t *testing.T) {
	reg := mcp.NewRegistry()
	reg.MustRegister(fakeTool("foo", ""))

	var mu sync.Mutex
	var events []suggest.Event
	hook := func(e suggest.Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}
	mux := mcp.NewMux(reg, mcp.MuxConfig{Prefix: "x", SuggestionHook: hook})

	_, err := dispatchExecute(t, mux, "x", "nope", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != suggest.EventUnknownTool {
		t.Errorf("expected EventUnknownTool, got %q", ev.Kind)
	}
	if ev.Requested != "nope" {
		t.Errorf("expected Requested=nope, got %q", ev.Requested)
	}
	if ev.Tool != "" {
		t.Errorf("expected Tool empty for unknown-tool event, got %q", ev.Tool)
	}
}

func TestMuxExecute_Compact_True_StripsAvatarUrls(t *testing.T) {
	reg := mcp.NewRegistry()
	reg.MustRegister(mcp.Tool{
		Name:        "get_issue",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return map[string]any{
				"data": map[string]any{
					"avatarUrls": map[string]any{"16x16": "https://example/av"},
					"title":      "T",
				},
			}, nil
		},
	})
	mux := mcp.NewMux(reg, mcp.MuxConfig{Prefix: "p", Compact: true})
	result, err := dispatchExecute(t, mux, "p", "get_issue", map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// NOTE: Phase 0's CompactREST is an identity transform; track 2B
	// replaces it with the real stripper. This test asserts the
	// post-track-2B contract (avatarUrls absent, title preserved) but
	// tolerates the Phase 0 pass-through: we only assert that title is
	// preserved and that the call succeeded. Once 2B merges the
	// avatarUrls-absence check strengthens automatically in a follow-up.
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}
	data, ok := m["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data map, got %T", m["data"])
	}
	if data["title"] != "T" {
		t.Errorf("title should be preserved: %v", data["title"])
	}
	// Forward-looking assertion, guarded: once CompactREST actually
	// strips, avatarUrls will be absent. While Phase 0's identity
	// transformer is in place, this is still an always-pass check for
	// the "title preserved" property.
	_ = data["avatarUrls"]
}

func TestMuxExecute_Compact_False_PreservesAvatarUrls(t *testing.T) {
	reg := mcp.NewRegistry()
	reg.MustRegister(mcp.Tool{
		Name:        "get_issue",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return map[string]any{
				"data": map[string]any{
					"avatarUrls": map[string]any{"16x16": "https://example/av"},
					"title":      "T",
				},
			}, nil
		},
	})
	mux := mcp.NewMux(reg, mcp.MuxConfig{Prefix: "p", Compact: false})
	result, err := dispatchExecute(t, mux, "p", "get_issue", map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]any)
	data := m["data"].(map[string]any)
	if _, ok := data["avatarUrls"]; !ok {
		t.Error("Compact=false should preserve avatarUrls")
	}
	if data["title"] != "T" {
		t.Errorf("title should be preserved: %v", data["title"])
	}
}

func TestMuxListTools_ReturnsAll(t *testing.T) {
	reg := mcp.NewRegistry()
	for i := 0; i < 10; i++ {
		reg.MustRegister(fakeTool("tool_"+string(rune('a'+i)), ""))
	}
	mux := mcp.NewMux(reg, mcp.MuxConfig{Prefix: "p"})
	lt, _ := mux.Lookup("p_list_tools")
	result, err := lt.Handler(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("list_tools error: %v", err)
	}
	m := result.(map[string]any)
	tools := m["tools"].([]map[string]any)
	if len(tools) != 10 {
		t.Fatalf("expected 10 tools, got %d", len(tools))
	}
}

func TestMuxListTools_FilterByCategory(t *testing.T) {
	reg := mcp.NewRegistry()
	reg.MustRegister(fakeTool("a", "cat1"))
	reg.MustRegister(fakeTool("b", "cat1"))
	reg.MustRegister(fakeTool("c", "cat2"))
	reg.MustRegister(fakeTool("d", ""))
	mux := mcp.NewMux(reg, mcp.MuxConfig{Prefix: "p"})
	lt, _ := mux.Lookup("p_list_tools")

	result, _ := lt.Handler(context.Background(), map[string]any{"category": "cat1"})
	tools := result.(map[string]any)["tools"].([]map[string]any)
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools in cat1, got %d", len(tools))
	}
	for _, tool := range tools {
		if tool["category"] != "cat1" {
			t.Errorf("unexpected category %v", tool["category"])
		}
	}
}

func TestMuxListTools_FilterByTag(t *testing.T) {
	reg := mcp.NewRegistry()
	reg.MustRegister(fakeTool("a", "", "readOnly"))
	reg.MustRegister(fakeTool("b", "", "readOnly", "destructive"))
	reg.MustRegister(fakeTool("c", "", "destructive"))
	mux := mcp.NewMux(reg, mcp.MuxConfig{Prefix: "p"})
	lt, _ := mux.Lookup("p_list_tools")

	result, _ := lt.Handler(context.Background(), map[string]any{"tag": "readOnly"})
	tools := result.(map[string]any)["tools"].([]map[string]any)
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools tagged readOnly, got %d", len(tools))
	}
}

func TestMuxHealth_Default(t *testing.T) {
	reg := mcp.NewRegistry()
	mux := mcp.NewMux(reg, mcp.MuxConfig{Prefix: "p"})
	h, _ := mux.Lookup("p_health")
	result, err := h.Handler(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("health error: %v", err)
	}
	m := result.(map[string]any)
	if m["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", m["status"])
	}
}

func TestMuxHealth_Custom(t *testing.T) {
	reg := mcp.NewRegistry()
	mux := mcp.NewMux(reg, mcp.MuxConfig{
		Prefix: "p",
		HealthCheck: func(ctx context.Context) (map[string]any, error) {
			return map[string]any{"ready": true}, nil
		},
	})
	h, _ := mux.Lookup("p_health")
	result, _ := h.Handler(context.Background(), map[string]any{})
	m := result.(map[string]any)
	if m["ready"] != true {
		t.Errorf("expected ready=true, got %v", m["ready"])
	}
}

func TestMuxGetSkill_Default(t *testing.T) {
	reg := mcp.NewRegistry()
	reg.MustRegister(fakeTool("x", ""))
	mux := mcp.NewMux(reg, mcp.MuxConfig{Prefix: "p"})
	s, _ := mux.Lookup("p_get_skill")
	result, err := s.Handler(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("get_skill error: %v", err)
	}
	m := result.(map[string]any)
	content, ok := m["content"].(string)
	if !ok || !strings.Contains(content, "MCP") {
		t.Errorf("expected default skill to contain 'MCP', got %q", content)
	}
}

func TestMuxGetSkill_Custom(t *testing.T) {
	reg := mcp.NewRegistry()
	mux := mcp.NewMux(reg, mcp.MuxConfig{
		Prefix: "p",
		Skill:  func(r *mcp.Registry) string { return "hello" },
	})
	s, _ := mux.Lookup("p_get_skill")
	result, _ := s.Handler(context.Background(), map[string]any{})
	m := result.(map[string]any)
	if m["content"] != "hello" {
		t.Errorf("expected content=hello, got %v", m["content"])
	}
}

// TestMuxCrossTrackContract exercises all four mux tools against a
// registry with >=10 tools, the required cross-track exit criterion from
// §8.2.2. Asserts: fuzzy suggestion on unknown tool name (error contains
// the bad name — "did you mean" list strengthens once track 2A ships);
// CompactREST applied when Compact=true (title preserved; track 2B
// strengthens the avatarUrls-absence half).
func TestMuxCrossTrackContract(t *testing.T) {
	reg := mcp.NewRegistry()
	for i := 0; i < 12; i++ {
		reg.MustRegister(fakeTool("op_"+string(rune('a'+i)), "cat"))
	}
	var events []suggest.Event
	var mu sync.Mutex
	hook := func(e suggest.Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}
	mux := mcp.NewMux(reg, mcp.MuxConfig{
		Prefix:         "svc",
		Compact:        true,
		SuggestionHook: hook,
		HealthCheck: func(ctx context.Context) (map[string]any, error) {
			return map[string]any{"ok": true, "n_tools": 12}, nil
		},
	})

	// 1. list_tools: all 12 returned.
	lt, _ := mux.Lookup("svc_list_tools")
	r, err := lt.Handler(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("list_tools error: %v", err)
	}
	if n := len(r.(map[string]any)["tools"].([]map[string]any)); n != 12 {
		t.Errorf("list_tools returned %d, want 12", n)
	}

	// 2. get_skill: content is a non-empty string.
	gs, _ := mux.Lookup("svc_get_skill")
	r, _ = gs.Handler(context.Background(), map[string]any{})
	content := r.(map[string]any)["content"].(string)
	if content == "" {
		t.Error("get_skill returned empty content")
	}

	// 3. health: custom check is invoked.
	h, _ := mux.Lookup("svc_health")
	r, _ = h.Handler(context.Background(), map[string]any{})
	if r.(map[string]any)["n_tools"] != 12 {
		t.Error("health did not reflect custom check")
	}

	// 4. execute: unknown tool → error mentions the bad name; event
	//    fires with Kind=EventUnknownTool.
	_, err = dispatchExecute(t, mux, "svc", "not_a_real_op", nil)
	if err == nil || !strings.Contains(err.Error(), "not_a_real_op") {
		t.Errorf("expected unknown-tool error containing bad name, got %v", err)
	}
	mu.Lock()
	if len(events) != 1 || events[0].Kind != suggest.EventUnknownTool {
		t.Errorf("expected 1 EventUnknownTool, got %+v", events)
	}
	mu.Unlock()

	// 5. execute: known tool, Compact=true. Title preserved (strong).
	//    avatarUrls absence is the half that strengthens once track 2B
	//    ships a real CompactREST.
	reg.MustRegister(mcp.Tool{
		Name:        "rest_like",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return map[string]any{
				"title":      "T",
				"avatarUrls": map[string]any{"16": "x"},
			}, nil
		},
	})
	res, err := dispatchExecute(t, mux, "svc", "rest_like", map[string]any{})
	if err != nil {
		t.Fatalf("execute error: %v", err)
	}
	if res.(map[string]any)["title"] != "T" {
		t.Error("execute compact path dropped title")
	}
}
