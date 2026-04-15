package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Superposition-Systems/go-mcp-server/suggest"
)

// ValidationOption configures WithInputValidation. See §4.6.
type ValidationOption func(*validationConfig)

type validationConfig struct {
	strict bool
	coerce bool
}

// ValidationStrict makes the validator reject unknown fields (equivalent to
// additionalProperties: false at the top level).
//
// On a rejected unknown field, the middleware also fires
// suggest.EventUnknownParam through the configured suggestion hook (if any),
// with Suggested set to the closest canonical name via suggest.Closest.
func ValidationStrict() ValidationOption {
	return func(c *validationConfig) { c.strict = true }
}

// ValidationCoerce makes the validator coerce scalar values where the
// top-level schema permits (e.g. string "42" → int 42, "true" → true,
// number 42 → "42" for a string-typed field). Nested objects/arrays are not
// touched; only top-level properties are inspected.
func ValidationCoerce() ValidationOption {
	return func(c *validationConfig) { c.coerce = true }
}

// inputValidationMiddleware preserves the Phase 0 signature so existing
// wiring keeps compiling. The Phase 0 stub returned an identity middleware.
//
// This continues to return an identity middleware: it has no Registry to
// look schemas up in. Session 2 (track 1B) wires the chain into transport
// and should call buildValidationMiddleware(reg, hook, opts) instead — that
// function returns the production middleware closing over the per-Server
// registry and suggestion hook. Both helpers are unexported; the public
// surface is WithInputValidation/ValidationStrict/ValidationCoerce.
//
// Wired by track 1B.
func inputValidationMiddleware(opts []ValidationOption) ToolMiddleware {
	cfg := &validationConfig{}
	for _, o := range opts {
		o(cfg)
	}
	_ = cfg
	return func(next ToolCallFunc) ToolCallFunc { return next }
}

// buildValidationMiddleware returns the production JSON-Schema validation
// middleware. Session 2 (track 1B) calls this from its transport-layer
// chain assembly with the server's *Registry and suggest.Hook.
//
// Behaviour:
//   - Look up the tool by name. Unknown tools pass through (other layers
//     produce the unknown-tool error).
//   - Tools without an InputSchema (empty or zero RawMessage) pass through.
//   - The schema is compiled with santhosh-tekuri/jsonschema/v6. If the raw
//     schema lacks "$schema", draft 2020-12 is injected before compile so
//     hand-written MCP schemas (which often omit it) get the right draft
//     instead of whatever the library happens to default to today (§9 item 4).
//   - Compiled schemas are cached in a sync.Map keyed by tool name plus a
//     SHA-256 of the raw schema bytes — re-registering a tool with a new
//     schema busts the cache automatically.
//   - On ValidationCoerce: top-level scalar properties are coerced into the
//     declared type (int/number/bool/string) before validation runs.
//   - On ValidationStrict: any args key not declared under properties fires
//     suggest.EventUnknownParam (with the closest canonical as Suggested)
//     and the request is rejected.
//   - On any validation failure, the middleware short-circuits with
//     err != nil (per §3.3, library-level failure — NOT isError=true).
func buildValidationMiddleware(reg *Registry, hook suggest.Hook, opts []ValidationOption) ToolMiddleware {
	cfg := &validationConfig{}
	for _, o := range opts {
		o(cfg)
	}
	cache := &schemaCache{}
	return func(next ToolCallFunc) ToolCallFunc {
		return func(ctx context.Context, name string, args map[string]any) (any, bool, error) {
			if reg == nil {
				return next(ctx, name, args)
			}
			tool, ok := reg.Lookup(name)
			if !ok {
				return next(ctx, name, args)
			}
			if len(tool.InputSchema) == 0 {
				return next(ctx, name, args)
			}

			props, propTypes, declared := topLevelProperties(tool.InputSchema)

			if cfg.coerce && len(propTypes) > 0 {
				args = coerceArgs(args, propTypes)
			}

			if cfg.strict && declared {
				var unknowns []string
				for k := range args {
					if _, known := props[k]; !known {
						unknowns = append(unknowns, k)
					}
				}
				if len(unknowns) > 0 {
					if hook != nil {
						canonical := make([]string, 0, len(props))
						for k := range props {
							canonical = append(canonical, k)
						}
						for _, u := range unknowns {
							var sug string
							if matches := suggest.Closest(u, canonical, 1); len(matches) > 0 {
								sug = matches[0]
							}
							hook(suggest.Event{
								Kind:      suggest.EventUnknownParam,
								Tool:      name,
								Requested: u,
								Suggested: sug,
								Timestamp: time.Now(),
							})
						}
					}
					return nil, false, fmt.Errorf("input validation failed for %q: unknown field(s): %s", name, strings.Join(unknowns, ", "))
				}
			}

			schema, err := cache.get(tool.Name, tool.InputSchema)
			if err != nil {
				return nil, false, fmt.Errorf("input validation failed for %q: schema compile: %w", name, err)
			}

			instance, err := normalizeForValidation(args)
			if err != nil {
				return nil, false, fmt.Errorf("input validation failed for %q: %w", name, err)
			}
			if err := schema.Validate(instance); err != nil {
				return nil, false, fmt.Errorf("input validation failed for %q: %w", name, err)
			}

			return next(ctx, name, args)
		}
	}
}

// schemaCache memoises compiled schemas keyed by tool name + a hash of the
// raw schema bytes. Re-registering a tool with a new schema yields a
// different key and therefore a fresh compile.
type schemaCache struct {
	m sync.Map // key: "name\x00<sha256-hex>" → *jsonschema.Schema
}

func (c *schemaCache) get(name string, raw json.RawMessage) (*jsonschema.Schema, error) {
	sum := sha256.Sum256(raw)
	key := name + "\x00" + hex.EncodeToString(sum[:])
	if v, ok := c.m.Load(key); ok {
		return v.(*jsonschema.Schema), nil
	}
	sch, err := compileSchema(name, raw)
	if err != nil {
		return nil, err
	}
	actual, _ := c.m.LoadOrStore(key, sch)
	return actual.(*jsonschema.Schema), nil
}

// compileSchema parses the raw schema, injects $schema = draft 2020-12 if it
// is missing, and compiles it via jsonschema.Compiler.
func compileSchema(name string, raw json.RawMessage) (*jsonschema.Schema, error) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("invalid schema JSON: %w", err)
	}
	if obj, ok := doc.(map[string]any); ok {
		if _, has := obj["$schema"]; !has {
			obj["$schema"] = "https://json-schema.org/draft/2020-12/schema"
		}
	}
	c := jsonschema.NewCompiler()
	// Default draft for any sub-schemas without their own $schema.
	c.DefaultDraft(jsonschema.Draft2020)
	url := "mem:///" + safeURLPart(name) + ".json"
	if err := c.AddResource(url, doc); err != nil {
		return nil, fmt.Errorf("add resource: %w", err)
	}
	sch, err := c.Compile(url)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	return sch, nil
}

// safeURLPart strips characters that could break the in-memory URL we use
// as the schema location — schema names are simple identifiers in practice
// but defensively replace anything not in [A-Za-z0-9_-].
func safeURLPart(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "schema"
	}
	return b.String()
}

// topLevelProperties parses the raw schema and extracts the top-level
// "properties" map. The first return is the set of declared property names;
// the second is a name → type map for ValidationCoerce. The third return is
// true iff the schema actually declared a properties object — used by
// strict mode to distinguish "no properties section" (skip strict) from
// "properties: {}" (everything is unknown).
//
// The validator does this locally rather than calling
// internal/schema.ExtractParams because that helper is itself a Phase 0 stub
// returning nil — track 2C will land the real implementation. We keep this
// parser narrow to the keys validator.go actually uses.
func topLevelProperties(raw json.RawMessage) (set map[string]struct{}, types map[string]string, declared bool) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, false
	}
	propsRaw, ok := doc["properties"].(map[string]any)
	if !ok {
		return nil, nil, false
	}
	set = make(map[string]struct{}, len(propsRaw))
	types = make(map[string]string, len(propsRaw))
	for name, v := range propsRaw {
		set[name] = struct{}{}
		if pm, ok := v.(map[string]any); ok {
			if t, ok := pm["type"].(string); ok {
				types[name] = t
			}
		}
	}
	return set, types, true
}

// coerceArgs returns a shallow copy of args with top-level scalar values
// coerced toward the declared property types. Coercion never errors —
// values that cannot be coerced are passed through untouched and the
// schema validator catches the type mismatch downstream.
func coerceArgs(args map[string]any, types map[string]string) map[string]any {
	out := make(map[string]any, len(args))
	for k, v := range args {
		t, ok := types[k]
		if !ok {
			out[k] = v
			continue
		}
		out[k] = coerceScalar(v, t)
	}
	return out
}

// coerceScalar attempts a single scalar coercion based on the declared
// schema type. Returns the input unchanged if no coercion applies.
func coerceScalar(v any, t string) any {
	switch t {
	case "integer":
		switch x := v.(type) {
		case string:
			if n, err := strconv.ParseInt(x, 10, 64); err == nil {
				return float64(n) // align with json.Unmarshal numeric decoding
			}
		}
	case "number":
		switch x := v.(type) {
		case string:
			if f, err := strconv.ParseFloat(x, 64); err == nil {
				return f
			}
		}
	case "boolean":
		if s, ok := v.(string); ok {
			switch strings.ToLower(s) {
			case "true":
				return true
			case "false":
				return false
			}
		}
	case "string":
		switch x := v.(type) {
		case float64:
			// Render integers without trailing ".0".
			if x == float64(int64(x)) {
				return strconv.FormatInt(int64(x), 10)
			}
			return strconv.FormatFloat(x, 'f', -1, 64)
		case int:
			return strconv.Itoa(x)
		case int64:
			return strconv.FormatInt(x, 10)
		case bool:
			return strconv.FormatBool(x)
		}
	}
	return v
}

// normalizeForValidation round-trips args through encoding/json so the
// jsonschema library sees the same shapes (json.Number-free, all numeric
// types as float64) it would see for an instance decoded from the wire.
func normalizeForValidation(args map[string]any) (any, error) {
	b, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("marshal args: %w", err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("unmarshal args: %w", err)
	}
	return out, nil
}
