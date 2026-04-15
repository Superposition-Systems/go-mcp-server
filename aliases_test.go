package mcpserver

import (
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"testing"

	"github.com/Superposition-Systems/go-mcp-server/suggest"
)

// captureHook returns a suggest.Hook that records every event it receives
// plus a pointer to the accumulated slice for test assertions. Safe for
// concurrent use — the middleware itself never calls the hook concurrently
// for a single invocation, but the helper matches the Hook concurrency
// contract for good measure.
func captureHook() (suggest.Hook, *[]suggest.Event) {
	var events []suggest.Event
	var mu sync.Mutex
	hook := func(e suggest.Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}
	return hook, &events
}

// recordingNext returns a ToolCallFunc that records the args map reference
// and contents it was invoked with, and returns a trivial success.
func recordingNext() (ToolCallFunc, *map[string]any) {
	var seen map[string]any
	next := func(ctx context.Context, name string, args map[string]any) (any, bool, error) {
		seen = args
		return "ok", false, nil
	}
	return next, &seen
}

// registerTool is a small helper that stuffs a single tool into a fresh
// Registry; returns the registry. The handler is a no-op because the
// middleware never calls it directly (we inject our own next).
func registerTool(t *testing.T, tool Tool) *Registry {
	t.Helper()
	reg := NewRegistry()
	if tool.Handler == nil {
		tool.Handler = func(ctx context.Context, args map[string]any) (any, error) { return nil, nil }
	}
	if err := reg.Register(tool); err != nil {
		t.Fatalf("register: %v", err)
	}
	return reg
}

func TestParamAliasMiddleware(t *testing.T) {
	ctx := context.Background()

	t.Run("global alias rewrite happy path", func(t *testing.T) {
		reg := registerTool(t, Tool{
			Name:        "jira.get",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"issueKey":{"type":"string"}}}`),
		})
		hook, events := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"key": "issueKey"}, reg, hook)
		next, seen := recordingNext()

		_, _, err := mw(next)(ctx, "jira.get", map[string]any{"key": "ABC-1"})
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		want := map[string]any{"issueKey": "ABC-1"}
		if !reflect.DeepEqual(*seen, want) {
			t.Fatalf("rewrite: got %v, want %v", *seen, want)
		}
		if len(*events) != 0 {
			t.Fatalf("no events expected, got %v", *events)
		}
	})

	t.Run("per-tool override overrides global", func(t *testing.T) {
		reg := registerTool(t, Tool{
			Name:         "t",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"x":{"type":"string"},"y":{"type":"string"}}}`),
			ParamAliases: map[string]string{"k": "y"},
		})
		hook, events := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"k": "x"}, reg, hook)
		next, seen := recordingNext()

		_, _, err := mw(next)(ctx, "t", map[string]any{"k": "v"})
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		if got, ok := (*seen)["y"]; !ok || got != "v" {
			t.Fatalf("per-tool should win: got %v, expected y=v", *seen)
		}
		if _, hasX := (*seen)["x"]; hasX {
			t.Fatalf("global canonical should not win: got %v", *seen)
		}
		if _, hasK := (*seen)["k"]; hasK {
			t.Fatalf("alias should be dropped: got %v", *seen)
		}
		if len(*events) != 0 {
			t.Fatalf("no events expected, got %v", *events)
		}
	})

	// The cross-track exit assertion from §8.2.1: an alias-collision call
	// produces the documented EventAliasCollision with Requested = dropped
	// alias and Suggested = winning canonical.
	t.Run("a collision call produces the documented EventAliasCollision with Requested = dropped alias, Suggested = winning canonical", func(t *testing.T) {
		reg := registerTool(t, Tool{
			Name:        "jira.get",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"issueKey":{"type":"string"}}}`),
		})
		hook, events := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"key": "issueKey"}, reg, hook)
		next, seen := recordingNext()

		_, _, err := mw(next)(ctx, "jira.get", map[string]any{"key": "X", "issueKey": "Y"})
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		// Canonical preserved, alias dropped.
		if got, ok := (*seen)["issueKey"]; !ok || got != "Y" {
			t.Fatalf("canonical should be preserved: got %v", *seen)
		}
		if _, hasKey := (*seen)["key"]; hasKey {
			t.Fatalf("alias should be dropped: got %v", *seen)
		}
		if len(*seen) != 1 {
			t.Fatalf("expected exactly one key, got %v", *seen)
		}
		// Event contract.
		if len(*events) != 1 {
			t.Fatalf("want 1 event, got %d: %v", len(*events), *events)
		}
		e := (*events)[0]
		if e.Kind != suggest.EventAliasCollision {
			t.Errorf("Kind: got %q, want %q", e.Kind, suggest.EventAliasCollision)
		}
		if e.Tool != "jira.get" {
			t.Errorf("Tool: got %q, want %q", e.Tool, "jira.get")
		}
		if e.Requested != "key" {
			t.Errorf("Requested: got %q, want %q", e.Requested, "key")
		}
		if e.Suggested != "issueKey" {
			t.Errorf("Suggested: got %q, want %q", e.Suggested, "issueKey")
		}
		if e.Timestamp.IsZero() {
			t.Error("Timestamp should be non-zero")
		}
	})

	t.Run("canonical not declared in schema", func(t *testing.T) {
		reg := registerTool(t, Tool{
			Name:        "t",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"other":{"type":"string"}}}`),
		})
		hook, events := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"k": "missing"}, reg, hook)
		next, seen := recordingNext()

		input := map[string]any{"k": "v"}
		_, _, err := mw(next)(ctx, "t", input)
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		if !reflect.DeepEqual(*seen, input) {
			t.Fatalf("args should pass through unchanged: got %v, want %v", *seen, input)
		}
		if len(*events) != 0 {
			t.Fatalf("no events expected, got %v", *events)
		}
	})

	t.Run("alias not in args", func(t *testing.T) {
		reg := registerTool(t, Tool{
			Name:        "t",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"x":{"type":"string"}}}`),
		})
		hook, events := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"k": "x"}, reg, hook)
		next, seen := recordingNext()

		input := map[string]any{"y": "z"}
		_, _, err := mw(next)(ctx, "t", input)
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		if !reflect.DeepEqual(*seen, input) {
			t.Fatalf("args should pass through: got %v, want %v", *seen, input)
		}
		if len(*events) != 0 {
			t.Fatalf("no events expected, got %v", *events)
		}
	})

	t.Run("tool without InputSchema", func(t *testing.T) {
		reg := registerTool(t, Tool{
			Name: "t",
			// InputSchema deliberately nil.
		})
		hook, events := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"k": "x"}, reg, hook)
		next, seen := recordingNext()

		input := map[string]any{"k": "v"}
		_, _, err := mw(next)(ctx, "t", input)
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		if !reflect.DeepEqual(*seen, input) {
			t.Fatalf("args should pass through: got %v, want %v", *seen, input)
		}
		if len(*events) != 0 {
			t.Fatalf("no events expected, got %v", *events)
		}
	})

	t.Run("tool with non-flat schema (root $ref)", func(t *testing.T) {
		reg := registerTool(t, Tool{
			Name:        "t",
			InputSchema: json.RawMessage(`{"$ref":"#/definitions/Foo"}`),
		})
		hook, events := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"k": "x"}, reg, hook)
		next, seen := recordingNext()

		input := map[string]any{"k": "v"}
		_, _, err := mw(next)(ctx, "t", input)
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		if !reflect.DeepEqual(*seen, input) {
			t.Fatalf("args should pass through: got %v, want %v", *seen, input)
		}
		if len(*events) != 0 {
			t.Fatalf("no events expected, got %v", *events)
		}
	})

	t.Run("unknown tool name", func(t *testing.T) {
		reg := registerTool(t, Tool{
			Name:        "known",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"x":{"type":"string"}}}`),
		})
		hook, events := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"k": "x"}, reg, hook)
		next, seen := recordingNext()

		input := map[string]any{"k": "v"}
		_, _, err := mw(next)(ctx, "unknown", input)
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		if !reflect.DeepEqual(*seen, input) {
			t.Fatalf("args should pass through: got %v, want %v", *seen, input)
		}
		if len(*events) != 0 {
			t.Fatalf("no events expected, got %v", *events)
		}
	})

	t.Run("nil registry produces identity middleware", func(t *testing.T) {
		hook, events := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"k": "x"}, nil, hook)
		next, seen := recordingNext()

		input := map[string]any{"k": "v"}
		_, _, err := mw(next)(ctx, "anything", input)
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		if !reflect.DeepEqual(*seen, input) {
			t.Fatalf("args should pass through: got %v, want %v", *seen, input)
		}
		if len(*events) != 0 {
			t.Fatalf("no events expected, got %v", *events)
		}
	})

	t.Run("nil global and nil per-tool maps pass through", func(t *testing.T) {
		reg := registerTool(t, Tool{
			Name:        "t",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"x":{"type":"string"}}}`),
			// ParamAliases nil.
		})
		hook, events := captureHook()
		mw := newParamAliasMiddleware(nil, reg, hook)
		next, seen := recordingNext()

		input := map[string]any{"x": "v", "k": "w"}
		_, _, err := mw(next)(ctx, "t", input)
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		if !reflect.DeepEqual(*seen, input) {
			t.Fatalf("args should pass through: got %v, want %v", *seen, input)
		}
		if len(*events) != 0 {
			t.Fatalf("no events expected, got %v", *events)
		}
	})

	t.Run("nil hook on collision does not panic", func(t *testing.T) {
		reg := registerTool(t, Tool{
			Name:        "t",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"x":{"type":"string"}}}`),
		})
		mw := newParamAliasMiddleware(map[string]string{"k": "x"}, reg, nil)
		next, seen := recordingNext()

		_, _, err := mw(next)(ctx, "t", map[string]any{"k": "A", "x": "B"})
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		// Canonical preserved, alias dropped.
		if got, ok := (*seen)["x"]; !ok || got != "B" {
			t.Fatalf("canonical should be preserved on collision: got %v", *seen)
		}
		if _, hasK := (*seen)["k"]; hasK {
			t.Fatalf("alias should be dropped: got %v", *seen)
		}
	})

	t.Run("args copy-on-write: caller map unchanged after rewrite", func(t *testing.T) {
		reg := registerTool(t, Tool{
			Name:        "t",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"x":{"type":"string"}}}`),
		})
		hook, _ := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"k": "x"}, reg, hook)
		next, seen := recordingNext()

		input := map[string]any{"k": "v"}
		// Snapshot caller's view: keys and values.
		origKeys := make(map[string]any, len(input))
		for k, v := range input {
			origKeys[k] = v
		}

		_, _, err := mw(next)(ctx, "t", input)
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}

		// next saw the rewritten map.
		if _, ok := (*seen)["x"]; !ok {
			t.Fatalf("handler should have seen canonical: got %v", *seen)
		}
		// Caller's original reference must be untouched.
		if !reflect.DeepEqual(input, origKeys) {
			t.Fatalf("caller's args mutated: got %v, want %v", input, origKeys)
		}
		// And the seen map must not be the same reference as the caller's.
		// (Can't use == on maps; use pointer to underlying via reflect.)
		if reflect.ValueOf(*seen).Pointer() == reflect.ValueOf(input).Pointer() {
			t.Fatal("seen map shares reference with caller's args; copy-on-write broken")
		}
	})

	t.Run("args pass-through preserves reference when no rewrite", func(t *testing.T) {
		reg := registerTool(t, Tool{
			Name:        "t",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"x":{"type":"string"}}}`),
		})
		hook, _ := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"k": "x"}, reg, hook)
		next, seen := recordingNext()

		// Alias not present → no rewrite → same reference threads through.
		input := map[string]any{"x": "v"}
		_, _, err := mw(next)(ctx, "t", input)
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		if reflect.ValueOf(*seen).Pointer() != reflect.ValueOf(input).Pointer() {
			t.Fatal("no-rewrite path should preserve the input map reference")
		}
	})

	t.Run("multiple aliases rewritten in one call", func(t *testing.T) {
		reg := registerTool(t, Tool{
			Name: "t",
			InputSchema: json.RawMessage(
				`{"type":"object","properties":{"alpha":{"type":"string"},"beta":{"type":"string"}}}`),
		})
		hook, events := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"a": "alpha", "b": "beta"}, reg, hook)
		next, seen := recordingNext()

		_, _, err := mw(next)(ctx, "t", map[string]any{"a": "1", "b": "2"})
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		want := map[string]any{"alpha": "1", "beta": "2"}
		if !reflect.DeepEqual(*seen, want) {
			t.Fatalf("multi-rewrite: got %v, want %v", *seen, want)
		}
		if len(*events) != 0 {
			t.Fatalf("no events expected, got %v", *events)
		}
	})

	t.Run("alias equals canonical (self-map) is a no-op", func(t *testing.T) {
		reg := registerTool(t, Tool{
			Name:        "t",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"x":{"type":"string"}}}`),
		})
		hook, events := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"x": "x"}, reg, hook)
		next, seen := recordingNext()

		input := map[string]any{"x": "v"}
		_, _, err := mw(next)(ctx, "t", input)
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		if !reflect.DeepEqual(*seen, input) {
			t.Fatalf("self-map should be a no-op: got %v, want %v", *seen, input)
		}
		if len(*events) != 0 {
			t.Fatalf("self-map should fire no event, got %v", *events)
		}
		// Reference preserved (no copy-on-write triggered).
		if reflect.ValueOf(*seen).Pointer() != reflect.ValueOf(input).Pointer() {
			t.Fatal("self-map should not trigger copy-on-write")
		}
	})

	t.Run("canonical membership is case-sensitive", func(t *testing.T) {
		// Alias "Key" → canonical "issueKey". Schema declares "issueKey",
		// not "Key"; the canonical-membership test is case-sensitive
		// against the schema, so the rewrite SHOULD fire on the input
		// alias "Key" because "issueKey" is a declared property.
		reg := registerTool(t, Tool{
			Name:        "t",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"issueKey":{"type":"string"}}}`),
		})
		hook, events := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"Key": "issueKey"}, reg, hook)
		next, seen := recordingNext()

		_, _, err := mw(next)(ctx, "t", map[string]any{"Key": "ABC-1"})
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		if got, ok := (*seen)["issueKey"]; !ok || got != "ABC-1" {
			t.Fatalf("rewrite should fire: got %v", *seen)
		}
		if _, hasKey := (*seen)["Key"]; hasKey {
			t.Fatalf("alias 'Key' should be dropped: got %v", *seen)
		}
		if len(*events) != 0 {
			t.Fatalf("rewrite (not collision) should fire no event, got %v", *events)
		}
	})

	t.Run("per-tool override with same canonical collides with global", func(t *testing.T) {
		// Sanity check: if per-tool maps alias → canonical identical to
		// global, behaviour is identical (idempotent override).
		reg := registerTool(t, Tool{
			Name:         "t",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"x":{"type":"string"}}}`),
			ParamAliases: map[string]string{"k": "x"},
		})
		hook, events := captureHook()
		mw := newParamAliasMiddleware(map[string]string{"k": "x"}, reg, hook)
		next, seen := recordingNext()

		_, _, err := mw(next)(ctx, "t", map[string]any{"k": "v"})
		if err != nil {
			t.Fatalf("middleware err: %v", err)
		}
		if got, ok := (*seen)["x"]; !ok || got != "v" {
			t.Fatalf("rewrite should fire: got %v", *seen)
		}
		if len(*events) != 0 {
			t.Fatalf("no events expected, got %v", *events)
		}
	})
}

// TestMergeAliasMaps exercises mergeAliasMaps in isolation to cover the
// empty / nil edges that the middleware's fast-path short-circuits skip.
func TestMergeAliasMaps(t *testing.T) {
	if got := mergeAliasMaps(nil, nil); got != nil {
		t.Errorf("nil+nil: got %v, want nil", got)
	}
	if got := mergeAliasMaps(map[string]string{}, map[string]string{}); got != nil {
		t.Errorf("empty+empty: got %v, want nil", got)
	}
	got := mergeAliasMaps(map[string]string{"k": "x"}, map[string]string{"k": "y"})
	if got["k"] != "y" {
		t.Errorf("per-tool should win: got %v", got)
	}
	got = mergeAliasMaps(map[string]string{"a": "1"}, map[string]string{"b": "2"})
	if got["a"] != "1" || got["b"] != "2" {
		t.Errorf("disjoint merge: got %v", got)
	}
}
