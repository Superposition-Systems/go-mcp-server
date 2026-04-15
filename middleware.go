package mcpserver

import "context"

// ToolCallFunc is the signature every tool and middleware produces.
// See docs/plans/v0.8.0-middleware-and-registry.md §4.2 + §3.3.
//
// err != nil indicates a library/middleware-level failure (schema
// validation failed, middleware panicked). isError: true with err == nil
// indicates a successful tool call that is reporting a tool-level error
// to the client (e.g. 404 from a wrapped REST call).
type ToolCallFunc func(ctx context.Context, name string, args map[string]any) (result any, isError bool, err error)

// ToolMiddleware wraps a ToolCallFunc with additional behaviour.
// Middlewares installed via WithToolMiddleware run outermost-first:
// WithToolMiddleware(a, b, c) produces a(b(c(dispatch))).
type ToolMiddleware func(next ToolCallFunc) ToolCallFunc

// applyMiddlewares wraps inner with mws in outermost-first order.
// applyMiddlewares(inner, []{a,b,c}) = a(b(c(inner))).
//
// Phase 0 exposes this helper so Session 2 (track 1B) can call it from the
// transport-layer wiring it adds in transport.go.
func applyMiddlewares(inner ToolCallFunc, mws []ToolMiddleware) ToolCallFunc {
	for i := len(mws) - 1; i >= 0; i-- {
		inner = mws[i](inner)
	}
	return inner
}

// adaptToolHandler returns a ToolCallFunc that dispatches to a ToolHandler,
// translating the handler's (any, bool) return into the three-state
// (any, bool, error) contract used by middleware. The handler never errors
// at the library level in this adaptation — all errors are tool-level.
//
// Phase 0: Session 2 (track 1B) uses this when wiring the chain into the
// existing tools/call path.
func adaptToolHandler(h ToolHandler) ToolCallFunc {
	return func(ctx context.Context, name string, args map[string]any) (any, bool, error) {
		result, isError := h.Call(ctx, name, args)
		return result, isError, nil
	}
}
