package mcpserver

import (
	"context"
	"time"

	"github.com/Superposition-Systems/go-mcp-server/internal/schema"
	"github.com/Superposition-Systems/go-mcp-server/suggest"
)

// newParamAliasMiddleware builds the parameter-alias-resolution middleware
// consumed by WithParamAliases. See
// docs/plans/v0.8.0-middleware-and-registry.md §3.9 (independence from
// validation), §3.10 (collision telemetry via callback), and §4.10 (rewrite
// rule). The constructor is unexported — the exported seam is
// WithParamAliases plus the per-tool Tool.ParamAliases field.
//
// Parameters:
//   - global: the library-wide alias → canonical map (from WithParamAliases).
//     May be nil. Overridden by per-tool aliases on conflict (both key and
//     value sides) — if the same alias appears in both maps, the per-tool
//     canonical wins.
//   - reg: the tool registry used to look up a tool's InputSchema and
//     per-tool ParamAliases at call time. May be nil; a nil registry
//     produces an identity middleware because aliases need per-tool
//     InputSchema to validate that the canonical is a declared property.
//   - hook: the suggestion hook used to fire suggest.EventAliasCollision
//     when both the alias and canonical are present. May be nil; a nil
//     hook silently drops collision events (the rewrite still happens).
//
// Rewrite rule per §3.9 / §4.10, applied to every (alias, canonical) pair
// in the effective map for the tool being called:
//
//   - alias ∈ args ∧ canonical ∈ schema.properties ∧ canonical ∉ args →
//     rewrite: args[canonical] = args[alias]; delete args[alias].
//   - alias ∈ args ∧ canonical ∈ args → collision: delete args[alias];
//     preserve the existing args[canonical] unchanged; fire
//     suggest.EventAliasCollision with Requested = dropped alias,
//     Suggested = winning canonical, Tool = <tool name>,
//     Timestamp = time.Now().
//   - otherwise: no-op for that pair.
//
// Copy-on-write: if any rewrite or collision-drop is about to occur, the
// middleware clones the incoming args map before mutating; callers that
// retain a reference to the original map (e.g. the transport logging
// layer) are never surprised by mutation. If no rewrite is needed the
// original map is passed through unchanged.
//
// Pass-through contract: after rewriting, the middleware invokes next
// exactly once and returns its result verbatim. Unknown tool names,
// validation failures, and handler errors are all downstream concerns —
// this middleware never short-circuits.
func newParamAliasMiddleware(global map[string]string, reg *Registry, hook suggest.Hook) ToolMiddleware {
	// A nil registry means no per-tool InputSchema / ParamAliases are
	// reachable, so canonical-membership testing is impossible for every
	// tool — the middleware degrades to identity. Documented explicitly
	// so Session 2 (track 1B) knows that installing the middleware with
	// no registry is a well-defined no-op rather than a panic.
	if reg == nil {
		return func(next ToolCallFunc) ToolCallFunc { return next }
	}

	return func(next ToolCallFunc) ToolCallFunc {
		return func(ctx context.Context, name string, args map[string]any) (any, bool, error) {
			// Tool not in registry → pass through. A downstream layer
			// (mux / registry dispatch) will reject the name; we have no
			// canonical list to rewrite against.
			tool, ok := reg.Lookup(name)
			if !ok {
				return next(ctx, name, args)
			}

			effective := mergeAliasMaps(global, tool.ParamAliases)
			if len(effective) == 0 || len(args) == 0 {
				return next(ctx, name, args)
			}

			// Build the set of canonical property names from the tool's
			// InputSchema. ExtractParams returns nil for empty, non-flat,
			// or malformed schemas — in all those cases we have no
			// canonical set to rewrite against, so pass through.
			params := schema.ExtractParams(tool.InputSchema)
			if len(params) == 0 {
				return next(ctx, name, args)
			}
			canonicals := make(map[string]struct{}, len(params))
			for _, p := range params {
				canonicals[p.Name] = struct{}{}
			}

			rewritten := applyAliasRewrites(args, effective, canonicals, name, hook)
			return next(ctx, name, rewritten)
		}
	}
}

// mergeAliasMaps returns the effective alias → canonical map for a tool,
// merging the global and per-tool maps. Per-tool entries win on conflict
// (both key and value sides — if the same alias key appears in both, the
// per-tool canonical replaces the global one entirely).
//
// Returns nil when both inputs are empty so the caller can fast-path.
func mergeAliasMaps(global, perTool map[string]string) map[string]string {
	if len(global) == 0 && len(perTool) == 0 {
		return nil
	}
	out := make(map[string]string, len(global)+len(perTool))
	for k, v := range global {
		out[k] = v
	}
	for k, v := range perTool {
		out[k] = v // per-tool overrides
	}
	return out
}

// applyAliasRewrites walks the effective alias map and returns the args
// map with every applicable rewrite / collision-drop applied. When no
// change is needed it returns the original args reference unchanged (so
// callers that rely on map identity for pass-through detection see the
// original). When any change is needed it clones args first (copy-on-
// write, §3.9) and mutates only the clone.
//
// toolName is threaded through solely so collision events carry the
// parent tool. hook may be nil; when nil, collisions still drop the alias
// and preserve canonical but no event fires.
func applyAliasRewrites(
	args map[string]any,
	effective map[string]string,
	canonicals map[string]struct{},
	toolName string,
	hook suggest.Hook,
) map[string]any {
	// First pass: detect whether any (alias, canonical) pair in effective
	// actually triggers a rewrite or collision. If not, keep args as-is
	// to preserve reference identity.
	needsWrite := false
	for alias, canonical := range effective {
		if alias == canonical {
			// Self-map is a documented no-op — the rewrite would write
			// args[alias] = args[alias] then delete itself, losing data.
			continue
		}
		if _, ok := args[alias]; !ok {
			continue
		}
		if _, declared := canonicals[canonical]; !declared {
			continue
		}
		// Either a rewrite (canonical absent) or a collision (canonical
		// present) will happen — both mutate args.
		needsWrite = true
		break
	}
	if !needsWrite {
		return args
	}

	// Copy-on-write: never mutate the caller's map.
	out := make(map[string]any, len(args))
	for k, v := range args {
		out[k] = v
	}

	for alias, canonical := range effective {
		if alias == canonical {
			continue
		}
		aliasVal, hasAlias := out[alias]
		if !hasAlias {
			continue
		}
		if _, declared := canonicals[canonical]; !declared {
			continue
		}
		if _, hasCanonical := out[canonical]; hasCanonical {
			// Collision: drop the alias, preserve the canonical, fire
			// EventAliasCollision. §3.10 / §4.10.
			delete(out, alias)
			if hook != nil {
				hook(suggest.Event{
					Kind:      suggest.EventAliasCollision,
					Tool:      toolName,
					Requested: alias,
					Suggested: canonical,
					Timestamp: time.Now(),
				})
			}
			continue
		}
		// Plain rewrite.
		out[canonical] = aliasVal
		delete(out, alias)
	}
	return out
}
