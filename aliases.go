package mcpserver

// paramAliasMiddleware builds the alias-resolution middleware used by
// WithParamAliases. See §4.10.
//
// Rewrite rule: for each (alias → canonical) in the merged per-tool +
// global map, rewrite args[alias] → args[canonical] iff
//   - alias is present in args
//   - canonical is a declared property of the tool's InputSchema
//   - canonical is not already present in args
//
// Alias collision (both present) drops the alias and fires
// suggest.EventAliasCollision.
//
// Phase 0 minimal impl: returns an identity middleware so the chain
// compiles with aliases installed. Session 1 (track 3A) replaces the body
// with the real rewrite + collision logic, consuming the suggest.Hook from
// Server's configured hook.
func paramAliasMiddleware(global map[string]string) ToolMiddleware {
	_ = global
	return func(next ToolCallFunc) ToolCallFunc { return next }
}
