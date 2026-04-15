// Package schema provides a minimal top-level JSON Schema reader used by
// DefaultSkillBuilder and the parameter-alias middleware to extract human-
// readable parameter signatures from a tool's InputSchema.
//
// The motivating use case is §3.11 of the v0.8.0 plan
// (docs/plans/v0.8.0-middleware-and-registry.md): the default skill builder
// renders each tool as `name(param: type, ...)` by parsing the top level of
// the schema at render time, trading a small amount of complexity for
// single-source-of-truth guarantees (no parallel `Tool.Params` display
// field that can drift from the real schema).
//
// The parser deliberately handles only the flat, top-level shape. Schemas
// that use `$ref`, `oneOf`, `anyOf`, or `allOf` at the root, non-object
// roots, empty payloads, and malformed JSON all return nil so the caller
// can fall back to rendering `name(...)` with no arg list.
//
// This package is deliberately not exported beyond the module — consumers
// that want the same data can parse the schema themselves.
package schema

import (
	"encoding/json"
	"sort"
)

// ParamInfo describes a single top-level input parameter.
type ParamInfo struct {
	Name        string
	Type        string // "string" | "number" | "boolean" | "array" | "object" — empty if absent or an array of types
	Required    bool
	Description string
}

// rootSchema is the tolerant shape we decode into: every field is kept as
// a json.RawMessage so we can introspect presence and arbitrary JSON types
// (strings, arrays, objects) without committing to a rigid schema.
type rootSchema struct {
	Ref        json.RawMessage            `json:"$ref"`
	OneOf      json.RawMessage            `json:"oneOf"`
	AnyOf      json.RawMessage            `json:"anyOf"`
	AllOf      json.RawMessage            `json:"allOf"`
	Type       json.RawMessage            `json:"type"`
	Properties map[string]json.RawMessage `json:"properties"`
	Required   json.RawMessage            `json:"required"`
}

// ExtractParams parses the top level of a JSON Schema and returns a slice
// of ParamInfo, one per property under `properties`, with `required`
// applied and sorted alphabetically by Name for deterministic output.
//
// It returns nil (never panics) when:
//   - raw is empty or JSON null;
//   - the root carries `$ref`, `oneOf`, `anyOf`, or `allOf`;
//   - the root's `type` is present and is not the string "object";
//   - the root JSON does not parse as an object.
//
// Individual malformed properties (e.g. a property whose value is a JSON
// string instead of an object) are silently skipped rather than failing
// the whole parse. Names listed in `required` that have no matching
// property are silently ignored.
func ExtractParams(raw json.RawMessage) []ParamInfo {
	// Empty payload → no renderable signature.
	if len(raw) == 0 {
		return nil
	}
	// JSON "null" → no renderable signature.
	if isJSONNull(raw) {
		return nil
	}

	var root rootSchema
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil
	}

	// Any composition keyword at the root means the schema is not flat.
	if len(root.Ref) > 0 || len(root.OneOf) > 0 || len(root.AnyOf) > 0 || len(root.AllOf) > 0 {
		return nil
	}

	// If `type` is present it must be the string "object"; anything else
	// (including an array-of-types) is treated as non-flat → nil.
	if len(root.Type) > 0 {
		var t string
		if err := json.Unmarshal(root.Type, &t); err != nil {
			return nil
		}
		if t != "object" {
			return nil
		}
	}
	// Note: `type` may be missing entirely; hand-written schemas often
	// omit it when `properties` is present. That is fine — proceed.

	// Collect the set of required names. Silently drop if malformed.
	required := map[string]struct{}{}
	if len(root.Required) > 0 {
		var names []string
		if err := json.Unmarshal(root.Required, &names); err == nil {
			for _, n := range names {
				required[n] = struct{}{}
			}
		}
	}

	out := make([]ParamInfo, 0, len(root.Properties))
	for name, rawProp := range root.Properties {
		info, ok := parseProperty(name, rawProp)
		if !ok {
			continue
		}
		if _, isReq := required[name]; isReq {
			info.Required = true
		}
		out = append(out, info)
	}

	if len(out) == 0 {
		// Preserve nil semantics for "no usable properties" rather than
		// returning a zero-length non-nil slice.
		return nil
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// parseProperty decodes a single property subschema. It tolerates a
// missing or array-valued `type` (treating Type as ""), a missing or
// non-string `description`, and skips the property outright if the value
// is not a JSON object.
func parseProperty(name string, raw json.RawMessage) (ParamInfo, bool) {
	if len(raw) == 0 {
		return ParamInfo{}, false
	}
	var prop struct {
		Type        json.RawMessage `json:"type"`
		Description json.RawMessage `json:"description"`
	}
	if err := json.Unmarshal(raw, &prop); err != nil {
		// Not a JSON object — malformed property, skip silently.
		return ParamInfo{}, false
	}

	info := ParamInfo{Name: name}

	if len(prop.Type) > 0 {
		var t string
		if err := json.Unmarshal(prop.Type, &t); err == nil {
			info.Type = t
		}
		// else: array-of-types or other non-string shape → Type stays "".
	}
	if len(prop.Description) > 0 {
		var d string
		if err := json.Unmarshal(prop.Description, &d); err == nil {
			info.Description = d
		}
	}
	return info, true
}

// isJSONNull reports whether raw decodes to a literal JSON `null`, after
// trimming any surrounding whitespace the JSON spec permits between
// tokens. Using json.Unmarshal here also catches `null` with leading
// whitespace (e.g. " null ") without pulling in strings.TrimSpace.
func isJSONNull(raw json.RawMessage) bool {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	return v == nil
}
