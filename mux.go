package mcpserver

import "context"

// MuxConfig configures a mux-mode dispatcher. See §4.4.
type MuxConfig struct {
	Prefix             string
	Skill              SkillBuilder
	HealthCheck        func(ctx context.Context) (map[string]any, error)
	Compact            bool
	GlobalParamAliases map[string]string
}

// NewMux wraps a Registry and returns a new Registry that exposes exactly
// 4 dispatcher tools instead of the underlying tools:
//
//	<prefix>_execute     — dispatch any operation by name with a payload
//	<prefix>_list_tools  — discover operations, filter by category
//	<prefix>_health      — optional HealthCheck result
//	<prefix>_get_skill   — routing guide content from cfg.Skill
//
// Phase 0 minimal impl: returns the underlying registry unchanged so
// dependent code compiles. Session 2 (track 3B) replaces this with the
// full 4-tool dispatcher registering into a fresh Registry.
func NewMux(underlying *Registry, cfg MuxConfig) *Registry {
	_ = cfg
	return underlying
}
