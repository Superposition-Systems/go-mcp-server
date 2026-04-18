package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Superposition-Systems/go-mcp-server/internal/schema"
	"github.com/Superposition-Systems/go-mcp-server/suggest"
)

// MuxConfig configures a mux-mode dispatcher. See §4.4.
//
// Prefix, Skill, HealthCheck, Compact, and GlobalParamAliases mirror the
// §4.4 sketch. SuggestionHook is an additive field over §4.4 (documented
// per the §4.11 Hook contract) that lets a mux-owned consumer fire
// EventUnknownTool without having to reach back into a Server. Callers
// typically pass the same suggest.Hook they installed via
// WithSuggestionHook; the mux is self-contained so a nil hook silently
// skips event emission.
type MuxConfig struct {
	// Prefix is the tool-name prefix for the 4 dispatch tools. Empty
	// falls back to "mcp". Tool names use underscore separator per §3.6:
	// <prefix>_execute, <prefix>_list_tools, <prefix>_health,
	// <prefix>_get_skill.
	Prefix string

	// Skill renders the markdown content returned by <prefix>_get_skill.
	// If nil, DefaultSkillBuilder(SkillOptions{}) is used.
	Skill SkillBuilder

	// HealthCheck, when non-nil, is invoked by <prefix>_health. If nil,
	// <prefix>_health returns {"status": "ok"}.
	HealthCheck func(ctx context.Context) (map[string]any, error)

	// Compact, when true, applies CompactREST() to successful results
	// from <prefix>_execute. Tool-level errors bypass compaction.
	Compact bool

	// GlobalParamAliases is reserved for §4.10 alias middleware wiring.
	// It is not consumed by the mux itself — the alias-middleware track
	// will install these as the global map on the Server. The field
	// lives on MuxConfig so a single MuxConfig can configure both.
	GlobalParamAliases map[string]string

	// SuggestionHook, when non-nil, receives one EventUnknownTool event
	// per unknown tool name seen by <prefix>_execute. Additive over §4.4
	// per the §4.11 Hook contract: must be safe for concurrent use and
	// must not block. Callers typically pass the same hook they
	// installed via WithSuggestionHook on the Server.
	SuggestionHook suggest.Hook
}

// muxPrefix returns the effective prefix (fallback "mcp").
func muxPrefix(cfg MuxConfig) string {
	if cfg.Prefix == "" {
		return "mcp"
	}
	return cfg.Prefix
}

// NewMux wraps a Registry and returns a new Registry that exposes exactly
// 4 dispatcher tools instead of the underlying tools:
//
//	<prefix>_execute     — dispatch any operation by name with a payload
//	<prefix>_list_tools  — discover operations, filter by category/tag
//	<prefix>_health      — optional HealthCheck result
//	<prefix>_get_skill   — routing-guide content from cfg.Skill
//
// The returned Registry is fresh: the underlying Registry is not mutated.
// Unknown-tool dispatches run suggest.Closest and, when SuggestionHook is
// non-nil, fire suggest.EventUnknownTool. When cfg.Compact is true the
// execute tool applies CompactREST() to successful results.
func NewMux(underlying *Registry, cfg MuxConfig) *Registry {
	prefix := muxPrefix(cfg)
	out := NewRegistry()
	// Chain the underlying registry so the Server's markStarted seal
	// cascades to it. Without this the outer mux registry (bound to the
	// Server) is sealed but the underlying — whose tools are captured in
	// every mux handler closure — stays mutable, letting a caller
	// register new tools against live dispatch.
	out.parent = underlying

	// Resolve skill builder once — consumers can override per MuxConfig.
	skillFn := cfg.Skill
	if skillFn == nil {
		skillFn = DefaultSkillBuilder(SkillOptions{})
	}

	// Compaction transformer; nil when disabled.
	var compact ResponseTransformer
	if cfg.Compact {
		compact = CompactREST()
	}

	out.MustRegister(Tool{
		Name:        prefix + "_execute",
		Description: "Dispatch any underlying operation by name. Pass the tool name in 'tool' and its arguments in 'args'.",
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "tool": {"type": "string", "description": "Name of the underlying tool to dispatch."},
    "args": {"type": "object", "description": "Arguments passed to the underlying tool's handler."}
  },
  "required": ["tool"]
}`),
		Handler: muxExecuteHandler(underlying, cfg.SuggestionHook, compact, cfg.GlobalParamAliases),
	})

	out.MustRegister(Tool{
		Name:        prefix + "_list_tools",
		Description: "List the underlying operations available to " + prefix + "_execute. Optionally filter by category or tag.",
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "category": {"type": "string", "description": "Return only tools whose Category matches this value."},
    "tag": {"type": "string", "description": "Return only tools whose Tags contain this value."}
  }
}`),
		Handler: muxListToolsHandler(underlying),
	})

	out.MustRegister(Tool{
		Name:        prefix + "_health",
		Description: "Return server health. Reports {\"status\": \"ok\"} by default, or the result of the configured HealthCheck.",
		InputSchema: json.RawMessage(`{"type": "object", "properties": {}}`),
		Handler:     muxHealthHandler(cfg.HealthCheck),
	})

	out.MustRegister(Tool{
		Name:        prefix + "_get_skill",
		Description: "Return the markdown routing guide for this mux. Call " + prefix + "_list_tools for full schemas.",
		InputSchema: json.RawMessage(`{"type": "object", "properties": {}}`),
		Handler:     muxGetSkillHandler(underlying, skillFn),
	})

	return out
}

// muxExecuteHandler returns the handler for <prefix>_execute.
//
// When globalAliases is non-empty or any looked-up tool has ParamAliases,
// the handler rewrites the inner args map before dispatching — mirroring the
// outer WithParamAliases middleware but applied to the nested payload the
// mux sees. Per-tool aliases (Tool.ParamAliases) override global aliases;
// collisions fire EventAliasCollision through hook. §4.4 + §4.10.
func muxExecuteHandler(underlying *Registry, hook suggest.Hook, compact ResponseTransformer, globalAliases map[string]string) func(context.Context, map[string]any) (any, error) {
	return func(ctx context.Context, args map[string]any) (any, error) {
		name, _ := args["tool"].(string)
		if name == "" {
			return nil, fmt.Errorf("missing required argument \"tool\"")
		}
		inner := extractInnerArgs(args, name, hook)

		t, ok := underlying.Lookup(name)
		if !ok {
			// Build candidate list from the underlying registry.
			all := underlying.All()
			names := make([]string, 0, len(all))
			for _, u := range all {
				names = append(names, u.Name)
			}
			suggestions := suggest.Closest(name, names, 3)

			if hook != nil {
				ev := suggest.Event{
					Kind:      suggest.EventUnknownTool,
					Tool:      "",
					Requested: name,
					Timestamp: time.Now(),
				}
				if len(suggestions) > 0 {
					ev.Suggested = suggestions[0]
				}
				hook(ev)
			}

			if len(suggestions) == 0 {
				return nil, fmt.Errorf("unknown tool %q", name)
			}
			return nil, fmt.Errorf("unknown tool %q — did you mean: %s?", name, strings.Join(suggestions, ", "))
		}

		// Apply parameter-alias rewriting to the inner payload before
		// dispatching. Outer-chain alias middleware cannot reach nested
		// args in atlassian_execute, so the mux performs the same rewrite
		// locally using the same helpers (mergeAliasMaps +
		// applyAliasRewrites) as §4.10's middleware.
		if effective := mergeAliasMaps(globalAliases, t.ParamAliases); len(effective) > 0 && len(inner) > 0 {
			params := schema.ExtractParams(t.InputSchema)
			if len(params) > 0 {
				canonicals := make(map[string]struct{}, len(params))
				for _, p := range params {
					canonicals[p.Name] = struct{}{}
				}
				inner = applyAliasRewrites(inner, effective, canonicals, name, hook)
			}
		}

		result, err := t.Handler(ctx, inner)
		if err != nil {
			// Tool-level errors bypass compaction per §4.3.
			return nil, err
		}
		if compact != nil {
			result = compact(name, result)
		}
		return result, nil
	}
}

// envelopeAliases are the non-canonical top-level keys the mux accepts for
// the inner payload in <prefix>_execute dispatch, in preference order.
//
// The canonical is "args" (see dispatchExecute in mux_test.go for the wire
// shape). The aliases cover common drift observed in the wild:
//   - "params" — used by some JSON-RPC-style SDKs and proxy layers.
//   - "arguments" — the literal MCP protocol name for tool-call args
//     (tools/call carries {name, arguments}), sometimes passed through
//     one layer too deep by clients.
//   - "input" — used by a handful of generic LLM-tool wrappers and the
//     Anthropic API's tool_use block.
//   - "payload" — the canonical choice in TypeScript MCP servers (e.g.
//     atlassian-mcp-server) and REST-style wrapper conventions.
//   - "parameters" — the unabbreviated synonym of "params".
//   - "inputs" — plural typo safeguard for "input".
//   - "data" — generic REST-style envelope, occasionally used as
//     the inner-payload key by hand-rolled clients.
//
// Accepting these does not change canonical behaviour: a payload with a
// valid "args" map is always used, regardless of what else is present.
// Only when "args" is absent or non-map do we fall back, and every
// fallback fires an EventEnvelopeAlias telemetry event so operators can
// see which clients are drifting from spec.
var envelopeAliases = []string{
	"params",
	"arguments",
	"input",
	"payload",
	"parameters",
	"inputs",
	"data",
}

// extractInnerArgs pulls the inner-payload map from the outer envelope,
// tolerating alias keys for proxy clients that forward the wrong name.
// Always returns a non-nil map — the caller never has to nil-check.
//
// toolName is the value of outer["tool"], forwarded into the telemetry
// event so operators can see which call site was affected.
func extractInnerArgs(outer map[string]any, toolName string, hook suggest.Hook) map[string]any {
	if m, ok := outer["args"].(map[string]any); ok {
		return m
	}
	for _, alias := range envelopeAliases {
		m, ok := outer[alias].(map[string]any)
		if !ok {
			continue
		}
		if hook != nil {
			hook(suggest.Event{
				Kind:      suggest.EventEnvelopeAlias,
				Tool:      toolName,
				Requested: alias,
				Suggested: "args",
				Timestamp: time.Now(),
			})
		}
		return m
	}
	return map[string]any{}
}

// muxListToolsHandler returns the handler for <prefix>_list_tools.
func muxListToolsHandler(underlying *Registry) func(context.Context, map[string]any) (any, error) {
	return func(ctx context.Context, args map[string]any) (any, error) {
		wantCategory, _ := args["category"].(string)
		wantTag, _ := args["tag"].(string)

		all := underlying.All() // already sorted by name
		out := make([]map[string]any, 0, len(all))
		for _, t := range all {
			if wantCategory != "" && t.Category != wantCategory {
				continue
			}
			if wantTag != "" && !containsTag(t.Tags, wantTag) {
				continue
			}
			entry := map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"category":    t.Category,
				"tags":        append([]string(nil), t.Tags...),
			}
			if t.Annotations != nil {
				entry["annotations"] = t.Annotations
			}
			out = append(out, entry)
		}
		return map[string]any{"tools": out}, nil
	}
}

// containsTag reports whether tags contains the given value.
func containsTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

// muxHealthHandler returns the handler for <prefix>_health.
func muxHealthHandler(check func(context.Context) (map[string]any, error)) func(context.Context, map[string]any) (any, error) {
	return func(ctx context.Context, _ map[string]any) (any, error) {
		if check == nil {
			return map[string]any{"status": "ok"}, nil
		}
		m, err := check(ctx)
		if err != nil {
			return nil, err
		}
		if m == nil {
			m = map[string]any{}
		}
		return m, nil
	}
}

// muxGetSkillHandler returns the handler for <prefix>_get_skill.
//
// Output is cached after the first call. The registry is sealed by
// Server.ToolCallChain / ListenAndServe before dispatch begins, so
// every subsequent render would produce byte-identical markdown —
// DefaultSkillBuilder walks the registry, runs ExtractParams per tool,
// and allocates a few hundred intermediate objects on every call,
// which is pure waste under an LLM loop that polls _get_skill. One
// sync.Once turns that into a one-shot cost.
func muxGetSkillHandler(underlying *Registry, skillFn SkillBuilder) func(context.Context, map[string]any) (any, error) {
	var (
		once   sync.Once
		cached string
	)
	return func(ctx context.Context, _ map[string]any) (any, error) {
		once.Do(func() {
			cached = skillFn(underlying)
		})
		return map[string]any{"content": cached}, nil
	}
}

