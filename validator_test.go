package mcpserver

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/Superposition-Systems/go-mcp-server/suggest"
)

// helpers --------------------------------------------------------------------

// recordingHook returns a Hook plus a thread-safe accessor for the events it
// observed.
func recordingHook() (suggest.Hook, func() []suggest.Event) {
	var (
		mu     sync.Mutex
		events []suggest.Event
	)
	hook := func(e suggest.Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}
	return hook, func() []suggest.Event {
		mu.Lock()
		defer mu.Unlock()
		out := make([]suggest.Event, len(events))
		copy(out, events)
		return out
	}
}

// captureCall records the args observed by the inner handler and returns a
// fixed result.
func captureCall(t *testing.T) (ToolCallFunc, *map[string]any, *bool) {
	t.Helper()
	var (
		gotArgs map[string]any
		called  bool
	)
	fn := func(ctx context.Context, name string, args map[string]any) (any, bool, error) {
		called = true
		// Snapshot — handlers are allowed to retain args.
		gotArgs = make(map[string]any, len(args))
		for k, v := range args {
			gotArgs[k] = v
		}
		return map[string]any{"ok": true}, false, nil
	}
	return fn, &gotArgs, &called
}

func mustRegister(t *testing.T, r *Registry, tool Tool) {
	t.Helper()
	if err := r.Register(tool); err != nil {
		t.Fatalf("Register(%s): %v", tool.Name, err)
	}
}

// raw is a tiny helper that converts a JSON literal to json.RawMessage and
// fails the test if the literal is malformed.
func raw(t *testing.T, s string) json.RawMessage {
	t.Helper()
	var probe any
	if err := json.Unmarshal([]byte(s), &probe); err != nil {
		t.Fatalf("invalid json literal: %v\n%s", err, s)
	}
	return json.RawMessage(s)
}

// tests ----------------------------------------------------------------------

func TestValidator_HappyPath(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg, Tool{
		Name: "t",
		InputSchema: raw(t, `{
			"type":"object",
			"properties":{"name":{"type":"string"},"count":{"type":"integer"}},
			"required":["name","count"]
		}`),
	})
	inner, gotArgs, called := captureCall(t)
	mw := buildValidationMiddleware(reg, nil, nil)
	chain := mw(inner)

	res, isErr, err := chain(context.Background(), "t", map[string]any{"name": "foo", "count": 3})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if isErr {
		t.Fatal("isError should be false")
	}
	if !*called {
		t.Fatal("handler not invoked")
	}
	if (*gotArgs)["name"] != "foo" {
		t.Fatalf("name: %v", (*gotArgs)["name"])
	}
	if res == nil {
		t.Fatal("result nil")
	}
}

func TestValidator_MissingRequired(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg, Tool{
		Name: "t",
		InputSchema: raw(t, `{
			"type":"object",
			"properties":{"name":{"type":"string"},"count":{"type":"integer"}},
			"required":["name","count"]
		}`),
	})
	inner, _, called := captureCall(t)
	chain := buildValidationMiddleware(reg, nil, nil)(inner)

	_, _, err := chain(context.Background(), "t", map[string]any{"name": "foo"})
	if err == nil {
		t.Fatal("expected validation error for missing required field")
	}
	if *called {
		t.Fatal("handler should not be invoked when validation fails")
	}
}

func TestValidator_WrongType(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg, Tool{
		Name: "t",
		InputSchema: raw(t, `{
			"type":"object",
			"properties":{"name":{"type":"string"},"count":{"type":"integer"}},
			"required":["name","count"]
		}`),
	})
	inner, _, called := captureCall(t)
	chain := buildValidationMiddleware(reg, nil, nil)(inner)

	_, _, err := chain(context.Background(), "t", map[string]any{"name": "foo", "count": "three"})
	if err == nil {
		t.Fatal("expected validation error for wrong type")
	}
	if *called {
		t.Fatal("handler should not be invoked")
	}
}

func TestValidator_NoSchemaPasses(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg, Tool{Name: "t" /* no InputSchema */})
	inner, _, called := captureCall(t)
	chain := buildValidationMiddleware(reg, nil, nil)(inner)

	_, _, err := chain(context.Background(), "t", map[string]any{"foo": "bar"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !*called {
		t.Fatal("handler should be invoked when schema is empty")
	}
}

func TestValidator_UnknownToolPasses(t *testing.T) {
	reg := NewRegistry()
	inner, _, called := captureCall(t)
	chain := buildValidationMiddleware(reg, nil, nil)(inner)

	_, _, err := chain(context.Background(), "ghost", map[string]any{"x": 1})
	if err != nil {
		t.Fatalf("expected passthrough, got err: %v", err)
	}
	if !*called {
		t.Fatal("handler should be invoked for unknown tool (downstream handles it)")
	}
}

func TestValidator_MissingDollarSchemaDefaultsTo2020_12(t *testing.T) {
	// prefixItems is a 2020-12-only keyword. If the library defaulted to
	// draft-7, prefixItems would silently no-op and validation against an
	// array shape would not enforce the per-position constraint.
	reg := NewRegistry()
	mustRegister(t, reg, Tool{
		Name: "t",
		InputSchema: raw(t, `{
			"type":"object",
			"properties":{
				"pair":{
					"type":"array",
					"prefixItems":[{"type":"string"},{"type":"integer"}],
					"items":false
				}
			},
			"required":["pair"]
		}`),
	})
	inner, _, _ := captureCall(t)
	chain := buildValidationMiddleware(reg, nil, nil)(inner)

	// Valid: ["a", 1] matches prefixItems and items:false caps length at 2.
	if _, _, err := chain(context.Background(), "t", map[string]any{"pair": []any{"a", 1}}); err != nil {
		t.Fatalf("valid prefixItems instance rejected: %v", err)
	}
	// Invalid: integer in slot 0 should fail under prefixItems.
	if _, _, err := chain(context.Background(), "t", map[string]any{"pair": []any{1, 1}}); err == nil {
		t.Fatal("expected prefixItems violation, got nil")
	}
}

func TestValidator_DraftExplicitStillHonoured(t *testing.T) {
	// Schema explicitly says draft-07; library should respect the declared
	// draft rather than upgrading to 2020-12.
	reg := NewRegistry()
	mustRegister(t, reg, Tool{
		Name: "t",
		InputSchema: raw(t, `{
			"$schema":"http://json-schema.org/draft-07/schema#",
			"type":"object",
			"properties":{"name":{"type":"string"}},
			"required":["name"]
		}`),
	})
	inner, _, _ := captureCall(t)
	chain := buildValidationMiddleware(reg, nil, nil)(inner)

	if _, _, err := chain(context.Background(), "t", map[string]any{"name": "ok"}); err != nil {
		t.Fatalf("draft-7 valid instance rejected: %v", err)
	}
	if _, _, err := chain(context.Background(), "t", map[string]any{"name": 42}); err == nil {
		t.Fatal("expected draft-7 type violation, got nil")
	}
}

func TestValidator_Strict_RejectsUnknownField(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg, Tool{
		Name: "t",
		InputSchema: raw(t, `{
			"type":"object",
			"properties":{"name":{"type":"string"}}
		}`),
	})
	hook, events := recordingHook()
	inner, _, called := captureCall(t)
	chain := buildValidationMiddleware(reg, hook, []ValidationOption{ValidationStrict()})(inner)

	_, _, err := chain(context.Background(), "t", map[string]any{"name": "x", "extra": "y"})
	if err == nil {
		t.Fatal("expected strict-mode rejection for unknown field")
	}
	if *called {
		t.Fatal("handler should not be invoked")
	}
	evs := events()
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	if evs[0].Kind != suggest.EventUnknownParam {
		t.Errorf("kind: got %v", evs[0].Kind)
	}
	if evs[0].Tool != "t" || evs[0].Requested != "extra" {
		t.Errorf("event: %+v", evs[0])
	}
	// Suggested may be empty (Phase 0 suggest.Closest stub) — we only assert
	// that the field exists on the event, not its value.
	_ = evs[0].Suggested
}

func TestValidator_Strict_FiresEventPerExtra(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg, Tool{
		Name: "t",
		InputSchema: raw(t, `{
			"type":"object",
			"properties":{"name":{"type":"string"}}
		}`),
	})
	hook, events := recordingHook()
	inner, _, _ := captureCall(t)
	chain := buildValidationMiddleware(reg, hook, []ValidationOption{ValidationStrict()})(inner)

	_, _, err := chain(context.Background(), "t", map[string]any{"name": "x", "a": 1, "b": 2})
	if err == nil {
		t.Fatal("expected strict-mode error")
	}
	evs := events()
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %d: %+v", len(evs), evs)
	}
	got := map[string]bool{}
	for _, e := range evs {
		if e.Kind != suggest.EventUnknownParam {
			t.Errorf("kind: %v", e.Kind)
		}
		got[e.Requested] = true
	}
	if !got["a"] || !got["b"] {
		t.Errorf("missing event for one of {a,b}: %v", got)
	}
}

func TestValidator_Coerce_StringToInt(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg, Tool{
		Name: "t",
		InputSchema: raw(t, `{
			"type":"object",
			"properties":{"count":{"type":"integer"}},
			"required":["count"]
		}`),
	})
	inner, gotArgs, called := captureCall(t)
	chain := buildValidationMiddleware(reg, nil, []ValidationOption{ValidationCoerce()})(inner)

	if _, _, err := chain(context.Background(), "t", map[string]any{"count": "42"}); err != nil {
		t.Fatalf("coerce: %v", err)
	}
	if !*called {
		t.Fatal("handler not invoked")
	}
	v := (*gotArgs)["count"]
	switch x := v.(type) {
	case float64:
		if x != 42 {
			t.Errorf("count: %v", x)
		}
	case int, int64:
		// also acceptable
	default:
		t.Errorf("unexpected coerced type %T (%v)", v, v)
	}
}

func TestValidator_Coerce_StringToBool(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg, Tool{
		Name: "t",
		InputSchema: raw(t, `{
			"type":"object",
			"properties":{"flag":{"type":"boolean"}},
			"required":["flag"]
		}`),
	})
	inner, gotArgs, _ := captureCall(t)
	chain := buildValidationMiddleware(reg, nil, []ValidationOption{ValidationCoerce()})(inner)

	if _, _, err := chain(context.Background(), "t", map[string]any{"flag": "TRUE"}); err != nil {
		t.Fatalf("coerce: %v", err)
	}
	if got, ok := (*gotArgs)["flag"].(bool); !ok || !got {
		t.Errorf("flag: got %v %T", (*gotArgs)["flag"], (*gotArgs)["flag"])
	}

	// "false" too
	inner2, gotArgs2, _ := captureCall(t)
	chain2 := buildValidationMiddleware(reg, nil, []ValidationOption{ValidationCoerce()})(inner2)
	if _, _, err := chain2(context.Background(), "t", map[string]any{"flag": "false"}); err != nil {
		t.Fatalf("coerce false: %v", err)
	}
	if got, ok := (*gotArgs2)["flag"].(bool); !ok || got {
		t.Errorf("flag false: got %v %T", (*gotArgs2)["flag"], (*gotArgs2)["flag"])
	}
}

func TestValidator_Coerce_LeavesStringsForStringField(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg, Tool{
		Name: "t",
		InputSchema: raw(t, `{
			"type":"object",
			"properties":{"name":{"type":"string"}},
			"required":["name"]
		}`),
	})
	inner, gotArgs, _ := captureCall(t)
	chain := buildValidationMiddleware(reg, nil, []ValidationOption{ValidationCoerce()})(inner)

	if _, _, err := chain(context.Background(), "t", map[string]any{"name": "foo"}); err != nil {
		t.Fatalf("err: %v", err)
	}
	if got, ok := (*gotArgs)["name"].(string); !ok || got != "foo" {
		t.Errorf("name: %v %T", (*gotArgs)["name"], (*gotArgs)["name"])
	}
}

func TestValidator_Coerce_NumberToString(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg, Tool{
		Name: "t",
		InputSchema: raw(t, `{
			"type":"object",
			"properties":{"id":{"type":"string"}},
			"required":["id"]
		}`),
	})
	inner, gotArgs, _ := captureCall(t)
	chain := buildValidationMiddleware(reg, nil, []ValidationOption{ValidationCoerce()})(inner)

	if _, _, err := chain(context.Background(), "t", map[string]any{"id": 42}); err != nil {
		t.Fatalf("err: %v", err)
	}
	if got, ok := (*gotArgs)["id"].(string); !ok || got != "42" {
		t.Errorf("id: %v %T", (*gotArgs)["id"], (*gotArgs)["id"])
	}

	// float that is not an integer keeps decimal precision
	inner2, gotArgs2, _ := captureCall(t)
	chain2 := buildValidationMiddleware(reg, nil, []ValidationOption{ValidationCoerce()})(inner2)
	if _, _, err := chain2(context.Background(), "t", map[string]any{"id": 3.14}); err != nil {
		t.Fatalf("err: %v", err)
	}
	if got, ok := (*gotArgs2)["id"].(string); !ok || got != "3.14" {
		t.Errorf("id: %v %T", (*gotArgs2)["id"], (*gotArgs2)["id"])
	}
}

func TestValidator_SchemaCacheKey_BustsOnReRegister(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg, Tool{
		Name: "t",
		InputSchema: raw(t, `{
			"type":"object",
			"properties":{"a":{"type":"string"}},
			"required":["a"]
		}`),
	})
	inner, _, _ := captureCall(t)
	mw := buildValidationMiddleware(reg, nil, nil)
	chain := mw(inner)

	// First call valid under schema A.
	if _, _, err := chain(context.Background(), "t", map[string]any{"a": "x"}); err != nil {
		t.Fatalf("schema A valid call rejected: %v", err)
	}

	// Re-register the same name with schema B (requires "b", not "a").
	mustRegister(t, reg, Tool{
		Name: "t",
		InputSchema: raw(t, `{
			"type":"object",
			"properties":{"b":{"type":"integer"}},
			"required":["b"]
		}`),
	})

	// Now {a:"x"} should be invalid (b is required, a is allowed by default
	// since additionalProperties is unset). And {b:1} should be valid.
	if _, _, err := chain(context.Background(), "t", map[string]any{"a": "x"}); err == nil {
		t.Fatal("schema B should reject missing 'b'; cache may be serving stale schema A")
	}
	if _, _, err := chain(context.Background(), "t", map[string]any{"b": 1}); err != nil {
		t.Fatalf("schema B valid call rejected: %v", err)
	}
}

func TestValidator_ErrorCategory(t *testing.T) {
	// §3.3 contract: validation failures return err != nil — NOT isError=true.
	reg := NewRegistry()
	mustRegister(t, reg, Tool{
		Name: "t",
		InputSchema: raw(t, `{
			"type":"object",
			"properties":{"n":{"type":"integer"}},
			"required":["n"]
		}`),
	})
	inner, _, _ := captureCall(t)
	chain := buildValidationMiddleware(reg, nil, nil)(inner)

	res, isErr, err := chain(context.Background(), "t", map[string]any{"n": "not-an-int"})
	if err == nil {
		t.Fatal("want err != nil")
	}
	if isErr {
		t.Errorf("want isError=false (library failure), got true")
	}
	if res != nil {
		t.Errorf("want nil result on validation failure, got %v", res)
	}
}

// Phase 0 identity middleware compatibility — confirm the legacy entrypoint
// still returns an identity middleware (Session 2 will switch the chain
// over to buildValidationMiddleware).
func TestValidator_Phase0EntrypointIsIdentity(t *testing.T) {
	mw := inputValidationMiddleware([]ValidationOption{ValidationStrict(), ValidationCoerce()})
	called := false
	inner := ToolCallFunc(func(ctx context.Context, name string, args map[string]any) (any, bool, error) {
		called = true
		// The Phase 0 stub MUST not validate — it's an identity passthrough.
		return "ok", false, nil
	})
	chain := mw(inner)
	res, isErr, err := chain(context.Background(), "anything", map[string]any{"unknown": 1})
	if err != nil || isErr || res != "ok" || !called {
		t.Fatalf("identity middleware misbehaved: res=%v isErr=%v err=%v called=%v", res, isErr, err, called)
	}
}
