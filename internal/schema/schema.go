// Package schema provides a minimal top-level JSON Schema reader used by
// DefaultSkillBuilder and the parameter-alias middleware to extract human-
// readable parameter signatures from a tool's InputSchema.
//
// See §3.11 of the v0.8.0 plan. This package is deliberately not exported
// beyond the module — consumers that want the same data can parse the
// schema themselves.
package schema

import "encoding/json"

// ParamInfo describes a single top-level input parameter.
type ParamInfo struct {
	Name        string
	Type        string // "string" | "number" | "boolean" | "array" | "object" — empty if absent
	Required    bool
	Description string
}

// ExtractParams parses the top level of a JSON Schema and returns a slice of
// ParamInfo, one per property under "properties", with "required" applied.
//
// If the schema is empty, is not a flat object (uses $ref, oneOf, allOf at
// the root), or cannot be parsed, ExtractParams returns nil. The caller
// treats this as "no renderable signature" and falls back to `tool(...)`.
//
// Phase 0 minimal impl: returns nil for every input. Session 1 (track 2C)
// replaces with the real parser that handles flat schemas gracefully and
// detects non-flat roots (returning nil) without panic.
func ExtractParams(raw json.RawMessage) []ParamInfo {
	_ = raw
	return nil
}
