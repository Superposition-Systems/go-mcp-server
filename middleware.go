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

// responseTransformerMiddleware adapts a ResponseTransformer into a
// ToolMiddleware. It calls next, and on a successful result
// (err == nil && !isError && result != nil) replaces result with
// t(name, result). Library errors (err != nil) and tool-level errors
// (isError == true) bypass the transform — see §9 risk 5 in the plan.
//
// Owned by middleware.go (track 1B). The ResponseTransformer type itself
// lives in transformer.go (track 2B).
func responseTransformerMiddleware(t ResponseTransformer) ToolMiddleware {
	return func(next ToolCallFunc) ToolCallFunc {
		return func(ctx context.Context, name string, args map[string]any) (any, bool, error) {
			result, isError, err := next(ctx, name, args)
			if err == nil && !isError && result != nil {
				result = t(name, result)
			}
			return result, isError, err
		}
	}
}

// buildToolCallChain assembles the tool-call middleware chain for a
// Server. The ordering (outermost → innermost) is:
//
//	user middlewares (in order passed to WithToolMiddleware)
//	  → param aliases (if s.paramAliases != nil)
//	    → schema validator (if len(s.validationOptions) > 0)
//	      → response transformer (if s.responseTransformer != nil)
//	        → dispatch (adaptToolHandler(s.tools))
//
// See §3.2, §5, and §8.2.2 of docs/plans/v0.8.0-middleware-and-registry.md.
//
// The transformer sits innermost (just above dispatch) so it only ever
// sees the handler's successful result — it bypasses on library errors
// (err != nil) and tool-level errors (isError == true), matching the
// "err != nil skips transformer" invariant in §9 risk 5.
//
// Aliases precede the validator so the validator only ever sees
// canonical names (§3.9).
//
// User middlewares are outermost so they observe the full picture —
// pre-alias args in, post-transform result out — which is what observer
// middlewares (logging, metrics, diag) need.
func buildToolCallChain(s *Server) ToolCallFunc {
	inner := adaptToolHandler(s.tools)

	// Innermost wrappers first (they sit closest to dispatch).
	if s.responseTransformer != nil {
		inner = responseTransformerMiddleware(s.responseTransformer)(inner)
	}
	if len(s.validationOptions) > 0 {
		inner = inputValidationMiddleware(s.validationOptions)(inner)
	}
	if s.paramAliases != nil {
		inner = paramAliasMiddleware(s.paramAliases)(inner)
	}

	// User middlewares outermost, applied in the order passed to
	// WithToolMiddleware — applyMiddlewares handles the outermost-first
	// wrapping.
	return applyMiddlewares(inner, s.toolMiddleware)
}
