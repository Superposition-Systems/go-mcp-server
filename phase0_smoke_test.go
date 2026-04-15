package mcpserver_test

import (
	"context"
	"encoding/json"
	"testing"

	mcp "github.com/Superposition-Systems/go-mcp-server"
	"github.com/Superposition-Systems/go-mcp-server/config"
	"github.com/Superposition-Systems/go-mcp-server/diag"
	"github.com/Superposition-Systems/go-mcp-server/suggest"
)

// TestPhase0APICompiles exercises every exported §4 API sketch to confirm
// the Phase 0 scaffold compiles as the plan's exit criteria require
// ("every §4 API sketch compiles as-is"). It is not a behaviour test —
// each later track ships its own coverage. Track 4B (composition suite)
// may delete or absorb this file.
func TestPhase0APICompiles(t *testing.T) {
	// §4.1 Registry + Tool
	reg := mcp.NewRegistry()
	reg.MustRegister(mcp.Tool{
		Name:         "echo",
		Description:  "echo the input",
		InputSchema:  json.RawMessage(`{"type":"object","properties":{"msg":{"type":"string"}}}`),
		Category:     "utility",
		Tags:         []string{"readOnly"},
		ParamAliases: map[string]string{"m": "msg"},
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return map[string]any{"content": []map[string]any{{"type": "text", "text": "ok"}}}, nil
		},
	})
	if _, ok := reg.Lookup("echo"); !ok {
		t.Fatal("registry Lookup failed for registered tool")
	}
	if len(reg.All()) != 1 {
		t.Fatalf("registry All: got %d, want 1", len(reg.All()))
	}
	if got := reg.Categories(); len(got) != 1 || got[0] != "utility" {
		t.Fatalf("registry Categories: got %v", got)
	}
	var _ mcp.ToolHandler = reg.AsToolHandler()

	// §4.2 Middleware chain types (internal wiring is Session 2 track 1B)
	var mw mcp.ToolMiddleware = func(next mcp.ToolCallFunc) mcp.ToolCallFunc { return next }

	// §4.3 Transformer
	var _ mcp.ResponseTransformer = mcp.CompactREST()
	_ = mcp.CompactResponse(mcp.StripFields("foo"), mcp.StripNulls(), mcp.StripEmptyArrays())

	// §4.4 Mux + Skill
	out := mcp.NewMux(reg, mcp.MuxConfig{
		Prefix: "atlassian",
		Skill: mcp.DefaultSkillBuilder(mcp.SkillOptions{
			Title:    "test",
			Featured: []mcp.Featured{{Section: "demo", Tools: []string{"echo"}}},
		}),
		Compact: true,
	})
	if out == nil {
		t.Fatal("NewMux returned nil")
	}

	// §4.5 / §4.11 Suggest
	_ = suggest.Closest("echo", []string{"echo"}, 3)
	var _ suggest.Hook = suggest.Multi(suggest.JSONLFile(""))
	_ = suggest.Event{Kind: suggest.EventUnknownTool}
	_ = suggest.Event{Kind: suggest.EventUnknownParam}
	_ = suggest.Event{Kind: suggest.EventAliasCollision}

	// §4.6 Validator
	_ = mcp.WithInputValidation(mcp.ValidationStrict(), mcp.ValidationCoerce())

	// §4.7 Diag
	dl, err := diag.New(diag.Config{DBPath: ":memory:", RingSize: 10})
	if err != nil {
		t.Fatalf("diag.New: %v", err)
	}
	if dl.Slog() == nil {
		t.Fatal("diag.Slog() returned nil")
	}
	var _ mcp.ToolMiddleware = dl.Middleware()
	_ = dl.RegisterTools(reg)
	_ = dl.Close()

	// §4.8 Config
	cs, err := config.Open(config.Options{DBPath: ":memory:", EnvFallback: true})
	if err != nil {
		t.Fatalf("config.Open: %v", err)
	}
	_ = cs.Set("k", "v")
	if v, ok := cs.Get("k"); !ok || v != "v" {
		t.Fatalf("config get: %q ok=%v", v, ok)
	}
	_ = cs.List()
	_ = cs.Delete("k")
	_ = cs.RegisterTools(reg)
	_ = cs.Close()

	// Server constructor accepts every new option.
	srv := mcp.New(
		mcp.WithName("smoke"),
		mcp.WithToolMiddleware(mw),
		mcp.WithResponseTransformer(mcp.CompactREST()),
		mcp.WithParamAliases(map[string]string{"k": "key"}),
		mcp.WithInputValidation(mcp.ValidationStrict()),
		mcp.WithSuggestionHook(suggest.JSONLFile("")),
	)
	if srv == nil {
		t.Fatal("New returned nil")
	}
}
