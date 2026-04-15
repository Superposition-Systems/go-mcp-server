package mcpserver

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

// stubHandler is a minimal ToolHandler for middleware tests. It records
// each Call() invocation so tests can assert whether dispatch ran.
type stubHandler struct {
	result  any
	isError bool
	calls   int
	lastArg map[string]any
}

func (s *stubHandler) ListTools() []ToolDef { return nil }
func (s *stubHandler) Call(_ context.Context, _ string, args map[string]any) (any, bool) {
	s.calls++
	s.lastArg = args
	return s.result, s.isError
}

// ─────────────────────────────────────────────────────────────────────────────
// adaptToolHandler
// ─────────────────────────────────────────────────────────────────────────────

func TestAdaptToolHandler_TranslatesSuccess(t *testing.T) {
	h := &stubHandler{result: map[string]any{"ok": true}, isError: false}
	fn := adaptToolHandler(h)
	result, isError, err := fn(context.Background(), "x", map[string]any{"a": 1})
	if err != nil {
		t.Fatalf("expected nil err from raw ToolHandler adaptation, got %v", err)
	}
	if isError {
		t.Fatal("expected isError=false")
	}
	if !reflect.DeepEqual(result, map[string]any{"ok": true}) {
		t.Fatalf("result mismatch: %v", result)
	}
	if h.calls != 1 {
		t.Fatalf("expected 1 dispatch, got %d", h.calls)
	}
}

func TestAdaptToolHandler_TranslatesToolLevelError(t *testing.T) {
	h := &stubHandler{result: map[string]any{"msg": "not found"}, isError: true}
	fn := adaptToolHandler(h)
	result, isError, err := fn(context.Background(), "x", nil)
	if err != nil {
		t.Fatalf("adaptToolHandler MUST always return nil err (§3.3), got %v", err)
	}
	if !isError {
		t.Fatal("expected isError=true to propagate")
	}
	if !reflect.DeepEqual(result, map[string]any{"msg": "not found"}) {
		t.Fatalf("result mismatch: %v", result)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// applyMiddlewares — ordering and short-circuit semantics
// ─────────────────────────────────────────────────────────────────────────────

func TestApplyMiddlewares_EmptyList_PassThrough(t *testing.T) {
	h := &stubHandler{result: "raw", isError: false}
	chain := applyMiddlewares(adaptToolHandler(h), nil)
	result, isError, err := chain(context.Background(), "x", map[string]any{"k": "v"})
	if err != nil || isError {
		t.Fatalf("empty list should be pass-through: err=%v isError=%v", err, isError)
	}
	if result != "raw" {
		t.Fatalf("expected raw, got %v", result)
	}
	if h.calls != 1 || h.lastArg["k"] != "v" {
		t.Fatalf("dispatch not invoked or args mutated: calls=%d lastArg=%v", h.calls, h.lastArg)
	}
}

func TestApplyMiddlewares_SingleMiddleware_WrapsBothWays(t *testing.T) {
	// Middleware mutates args on the way in and result on the way out.
	mw := func(next ToolCallFunc) ToolCallFunc {
		return func(ctx context.Context, name string, args map[string]any) (any, bool, error) {
			// Pre-dispatch: add a marker.
			args["pre"] = true
			result, isError, err := next(ctx, name, args)
			// Post-dispatch: wrap the result.
			if err == nil && !isError {
				result = map[string]any{"wrapped": result}
			}
			return result, isError, err
		}
	}
	h := &stubHandler{result: "inner", isError: false}
	chain := applyMiddlewares(adaptToolHandler(h), []ToolMiddleware{mw})

	result, _, _ := chain(context.Background(), "x", map[string]any{})
	if h.lastArg["pre"] != true {
		t.Fatalf("middleware did not mutate args before dispatch; lastArg=%v", h.lastArg)
	}
	wrapped, ok := result.(map[string]any)
	if !ok || wrapped["wrapped"] != "inner" {
		t.Fatalf("middleware did not wrap result after dispatch; result=%v", result)
	}
}

func TestApplyMiddlewares_ThreeMiddlewares_OutermostFirst(t *testing.T) {
	// Record pre-dispatch and post-dispatch markers from a, b, c so we
	// can assert the interleaving: a(b(c(dispatch))) =
	// a-pre, b-pre, c-pre, dispatch, c-post, b-post, a-post.
	var trace []string
	record := func(name string) ToolMiddleware {
		return func(next ToolCallFunc) ToolCallFunc {
			return func(ctx context.Context, n string, args map[string]any) (any, bool, error) {
				trace = append(trace, name+"-pre")
				r, ie, err := next(ctx, n, args)
				trace = append(trace, name+"-post")
				return r, ie, err
			}
		}
	}
	h := &stubHandler{result: "done"}
	inner := adaptToolHandler(h)
	// Add a sentinel dispatch marker by wrapping inner once more.
	instrumentedInner := func(ctx context.Context, n string, args map[string]any) (any, bool, error) {
		trace = append(trace, "dispatch")
		return inner(ctx, n, args)
	}
	chain := applyMiddlewares(instrumentedInner, []ToolMiddleware{record("a"), record("b"), record("c")})
	if _, _, err := chain(context.Background(), "x", map[string]any{}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	want := []string{"a-pre", "b-pre", "c-pre", "dispatch", "c-post", "b-post", "a-post"}
	if !reflect.DeepEqual(trace, want) {
		t.Fatalf("ordering mismatch:\n got  %v\n want %v", trace, want)
	}
}

func TestApplyMiddlewares_ShortCircuit_InnerNotCalled(t *testing.T) {
	var trace []string
	outer := func(next ToolCallFunc) ToolCallFunc {
		return func(ctx context.Context, n string, args map[string]any) (any, bool, error) {
			trace = append(trace, "outer-pre")
			r, ie, err := next(ctx, n, args)
			trace = append(trace, "outer-post")
			return r, ie, err
		}
	}
	sentinel := errors.New("short-circuit")
	middle := func(_ ToolCallFunc) ToolCallFunc {
		return func(_ context.Context, _ string, _ map[string]any) (any, bool, error) {
			trace = append(trace, "middle-return-err")
			return nil, false, sentinel
		}
	}
	inner := func(next ToolCallFunc) ToolCallFunc {
		return func(ctx context.Context, n string, args map[string]any) (any, bool, error) {
			trace = append(trace, "inner-pre")
			return next(ctx, n, args)
		}
	}
	h := &stubHandler{result: "unreached"}
	chain := applyMiddlewares(adaptToolHandler(h), []ToolMiddleware{outer, middle, inner})

	_, _, err := chain(context.Background(), "x", map[string]any{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel err to propagate, got %v", err)
	}
	if h.calls != 0 {
		t.Fatalf("dispatch must not run after short-circuit, got %d calls", h.calls)
	}
	want := []string{"outer-pre", "middle-return-err", "outer-post"}
	if !reflect.DeepEqual(trace, want) {
		t.Fatalf("trace mismatch:\n got  %v\n want %v", trace, want)
	}
}

func TestApplyMiddlewares_ToolLevelError_DoesNotShortCircuit(t *testing.T) {
	// isError: true with err == nil is a tool-level error — it MUST
	// flow through the whole chain like a normal return (§3.3). We
	// prove this by wrapping a handler that returns isError=true with a
	// middleware that counts post-dispatch visits.
	var postCount int
	mw := func(next ToolCallFunc) ToolCallFunc {
		return func(ctx context.Context, n string, args map[string]any) (any, bool, error) {
			r, ie, err := next(ctx, n, args)
			postCount++
			return r, ie, err
		}
	}
	h := &stubHandler{result: map[string]any{"msg": "tool-level 404"}, isError: true}
	chain := applyMiddlewares(adaptToolHandler(h), []ToolMiddleware{mw})

	result, isError, err := chain(context.Background(), "x", map[string]any{})
	if err != nil {
		t.Fatalf("tool-level error must NOT produce library err; got %v", err)
	}
	if !isError {
		t.Fatal("isError=true must propagate")
	}
	if h.calls != 1 {
		t.Fatalf("dispatch must run, got %d calls", h.calls)
	}
	if postCount != 1 {
		t.Fatalf("middleware post-dispatch must run for tool-level error, got %d", postCount)
	}
	if got, ok := result.(map[string]any); !ok || got["msg"] != "tool-level 404" {
		t.Fatalf("result mismatch: %v", result)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// responseTransformerMiddleware
// ─────────────────────────────────────────────────────────────────────────────

func TestResponseTransformerMiddleware_TransformsOnSuccess(t *testing.T) {
	t0 := ResponseTransformer(func(name string, result any) any {
		m := result.(map[string]any)
		m["_transformed_by"] = name
		return m
	})
	inner := func(_ context.Context, _ string, _ map[string]any) (any, bool, error) {
		return map[string]any{"raw": 1}, false, nil
	}
	chain := responseTransformerMiddleware(t0)(inner)

	result, _, err := chain(context.Background(), "toolX", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	got, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("result wrong type: %T", result)
	}
	if got["_transformed_by"] != "toolX" || got["raw"] != 1 {
		t.Fatalf("transform not applied: %v", got)
	}
}

func TestResponseTransformerMiddleware_BypassesOnError(t *testing.T) {
	called := false
	t0 := ResponseTransformer(func(string, any) any {
		called = true
		return "MUTATED"
	})
	boom := errors.New("boom")
	inner := func(_ context.Context, _ string, _ map[string]any) (any, bool, error) {
		return map[string]any{"data": 1}, false, boom
	}
	chain := responseTransformerMiddleware(t0)(inner)

	result, _, err := chain(context.Background(), "t", nil)
	if !errors.Is(err, boom) {
		t.Fatalf("expected boom to propagate, got %v", err)
	}
	if called {
		t.Fatal("transformer MUST NOT run when err != nil (§9 risk 5)")
	}
	if got, ok := result.(map[string]any); !ok || got["data"] != 1 {
		t.Fatalf("result should be untouched on err; got %v", result)
	}
}

func TestResponseTransformerMiddleware_BypassesOnToolLevelError(t *testing.T) {
	called := false
	t0 := ResponseTransformer(func(string, any) any {
		called = true
		return "MUTATED"
	})
	inner := func(_ context.Context, _ string, _ map[string]any) (any, bool, error) {
		return map[string]any{"msg": "not found"}, true, nil
	}
	chain := responseTransformerMiddleware(t0)(inner)

	result, isError, err := chain(context.Background(), "t", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !isError {
		t.Fatal("isError must propagate")
	}
	if called {
		t.Fatal("transformer MUST NOT run when isError==true (§9 risk 5)")
	}
	if got, ok := result.(map[string]any); !ok || got["msg"] != "not found" {
		t.Fatalf("result should be untouched on tool-level error; got %v", result)
	}
}

func TestResponseTransformerMiddleware_BypassesOnNilResult(t *testing.T) {
	// If the handler returns nil result, the transformer has nothing to
	// act on — calling t(name, nil) is the transformer's problem but we
	// choose to skip it for safety. The chain-builder doc comment
	// advertises this.
	called := false
	t0 := ResponseTransformer(func(string, any) any {
		called = true
		return "MUTATED"
	})
	inner := func(_ context.Context, _ string, _ map[string]any) (any, bool, error) {
		return nil, false, nil
	}
	chain := responseTransformerMiddleware(t0)(inner)
	result, _, _ := chain(context.Background(), "t", nil)
	if called {
		t.Fatal("transformer should not run on nil result")
	}
	if result != nil {
		t.Fatalf("nil result should round-trip, got %v", result)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// buildToolCallChain — integration of all facility slots
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildToolCallChain_EmptyServer_DispatchesDirectly(t *testing.T) {
	h := &stubHandler{result: "raw", isError: false}
	s := &Server{tools: h}
	chain := buildToolCallChain(s)
	result, isError, err := chain(context.Background(), "x", map[string]any{})
	if err != nil || isError {
		t.Fatalf("plain chain should pass through: err=%v isError=%v", err, isError)
	}
	if result != "raw" {
		t.Fatalf("expected raw, got %v", result)
	}
}

func TestBuildToolCallChain_TransformerOnlyRunsOnSuccess(t *testing.T) {
	h := &stubHandler{result: map[string]any{"a": 1}, isError: false}
	s := &Server{
		tools: h,
		responseTransformer: func(name string, result any) any {
			m := result.(map[string]any)
			m["touched"] = name
			return m
		},
	}
	chain := buildToolCallChain(s)
	result, _, _ := chain(context.Background(), "foo", map[string]any{})
	got := result.(map[string]any)
	if got["touched"] != "foo" {
		t.Fatalf("transformer not applied on success: %v", got)
	}
}

func TestBuildToolCallChain_AllFacilities_UserMiddlewareOutermost(t *testing.T) {
	// Instrumented user middleware records the state it sees on the way
	// in and on the way out. Because user middleware is outermost:
	//   - pre-dispatch args include whatever the consumer sent (pre-alias)
	//   - post-dispatch result is whatever the transformer produced (post-transform)
	// Phase 0 aliases and validator are identity middlewares, so we prove
	// ordering by:
	//   (a) transformer mutated the result BEFORE user-mw sees it on the
	//       way out (user-mw is outermost, transformer is innermost).
	var seenArgIn map[string]any
	var seenResultOut any
	userMW := func(next ToolCallFunc) ToolCallFunc {
		return func(ctx context.Context, n string, args map[string]any) (any, bool, error) {
			seenArgIn = copyMap(args)
			r, ie, err := next(ctx, n, args)
			seenResultOut = r
			return r, ie, err
		}
	}
	h := &stubHandler{result: map[string]any{"data": "x"}, isError: false}

	s := &Server{
		tools:          h,
		toolMiddleware: []ToolMiddleware{userMW},
		responseTransformer: func(_ string, result any) any {
			m := result.(map[string]any)
			m["compacted"] = true
			return m
		},
		paramAliases:      map[string]string{"k": "key"}, // identity in Phase 0
		validationOptions: []ValidationOption{ValidationStrict()},
	}
	chain := buildToolCallChain(s)

	in := map[string]any{"k": "v"}
	result, _, err := chain(context.Background(), "toolX", in)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// User middleware sees the raw args on the way in (Phase 0 aliases
	// are identity, so this is trivially true; still worth asserting).
	if seenArgIn["k"] != "v" {
		t.Fatalf("user-mw did not see pre-chain args: %v", seenArgIn)
	}

	// User middleware sees the transformer's output on the way out —
	// proving the transformer sits inside the user middleware.
	got := seenResultOut.(map[string]any)
	if got["compacted"] != true {
		t.Fatalf("user-mw saw untransformed result — transformer wiring wrong: %v", got)
	}
	if result.(map[string]any)["compacted"] != true {
		t.Fatalf("final result missing transform: %v", result)
	}
}

func TestBuildToolCallChain_UserMiddlewareOrder(t *testing.T) {
	// WithToolMiddleware(a, b, c) yields a(b(c(...))). Assert via a
	// pre-dispatch trace.
	var trace []string
	mk := func(tag string) ToolMiddleware {
		return func(next ToolCallFunc) ToolCallFunc {
			return func(ctx context.Context, n string, args map[string]any) (any, bool, error) {
				trace = append(trace, tag)
				return next(ctx, n, args)
			}
		}
	}
	h := &stubHandler{}
	s := &Server{
		tools:          h,
		toolMiddleware: []ToolMiddleware{mk("a"), mk("b"), mk("c")},
	}
	chain := buildToolCallChain(s)
	_, _, _ = chain(context.Background(), "x", nil)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(trace, want) {
		t.Fatalf("user middleware order wrong: got %v want %v", trace, want)
	}
}

// WithToolMiddleware accumulates rather than replacing.
func TestWithToolMiddleware_Accumulates(t *testing.T) {
	mk := func(ToolCallFunc) ToolCallFunc { return nil }
	s := &Server{}
	WithToolMiddleware(ToolMiddleware(mk))(s)
	WithToolMiddleware(ToolMiddleware(mk), ToolMiddleware(mk))(s)
	if got := len(s.toolMiddleware); got != 3 {
		t.Fatalf("expected 3 accumulated middlewares, got %d", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
