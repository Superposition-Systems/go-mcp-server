package schema_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Superposition-Systems/go-mcp-server/internal/schema"
)

func TestExtractParams(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		if got := schema.ExtractParams(nil); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})

	t.Run("empty RawMessage returns nil", func(t *testing.T) {
		if got := schema.ExtractParams(json.RawMessage("")); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})

	t.Run("literal JSON null returns nil", func(t *testing.T) {
		if got := schema.ExtractParams(json.RawMessage(`null`)); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})

	t.Run("flat schema happy path", func(t *testing.T) {
		raw := json.RawMessage(`{
			"type":"object",
			"properties":{
				"msg":{"type":"string","description":"the message"},
				"count":{"type":"integer"}
			},
			"required":["msg"]
		}`)
		got := schema.ExtractParams(raw)
		want := []schema.ParamInfo{
			{Name: "count", Type: "integer", Required: false, Description: ""},
			{Name: "msg", Type: "string", Required: true, Description: "the message"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("happy path mismatch\n got: %#v\nwant: %#v", got, want)
		}
	})

	t.Run("property ordering deterministic", func(t *testing.T) {
		// Declare keys in reverse-alphabetical-ish order; returned slice
		// must still be sorted ascending by Name.
		raw := json.RawMessage(`{
			"type":"object",
			"properties":{
				"zeta":{"type":"string"},
				"alpha":{"type":"string"},
				"mike":{"type":"string"},
				"bravo":{"type":"string"}
			}
		}`)
		got := schema.ExtractParams(raw)
		wantNames := []string{"alpha", "bravo", "mike", "zeta"}
		if len(got) != len(wantNames) {
			t.Fatalf("length: got %d want %d (%v)", len(got), len(wantNames), got)
		}
		for i, n := range wantNames {
			if got[i].Name != n {
				t.Fatalf("pos %d: got %q want %q (full: %v)", i, got[i].Name, n, got)
			}
		}
	})

	t.Run("missing required array means all params are not required", func(t *testing.T) {
		raw := json.RawMessage(`{
			"type":"object",
			"properties":{
				"a":{"type":"string"},
				"b":{"type":"number"}
			}
		}`)
		got := schema.ExtractParams(raw)
		if len(got) != 2 {
			t.Fatalf("want 2 params, got %d: %v", len(got), got)
		}
		for _, p := range got {
			if p.Required {
				t.Errorf("param %q: Required=true, want false", p.Name)
			}
		}
	})

	t.Run("required names a missing property is silently ignored", func(t *testing.T) {
		raw := json.RawMessage(`{
			"type":"object",
			"properties":{
				"a":{"type":"string"}
			},
			"required":["a","ghost","phantom"]
		}`)
		got := schema.ExtractParams(raw)
		want := []schema.ParamInfo{{Name: "a", Type: "string", Required: true}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v want %#v", got, want)
		}
	})

	t.Run("root with $ref returns nil", func(t *testing.T) {
		raw := json.RawMessage(`{"$ref":"#/definitions/Foo","properties":{"a":{"type":"string"}}}`)
		if got := schema.ExtractParams(raw); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})

	t.Run("root with oneOf returns nil", func(t *testing.T) {
		raw := json.RawMessage(`{"oneOf":[{"type":"object"}],"properties":{"a":{"type":"string"}}}`)
		if got := schema.ExtractParams(raw); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})

	t.Run("root with anyOf returns nil", func(t *testing.T) {
		raw := json.RawMessage(`{"anyOf":[{"type":"object"}],"properties":{"a":{"type":"string"}}}`)
		if got := schema.ExtractParams(raw); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})

	t.Run("root with allOf returns nil", func(t *testing.T) {
		raw := json.RawMessage(`{"allOf":[{"type":"object"}],"properties":{"a":{"type":"string"}}}`)
		if got := schema.ExtractParams(raw); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})

	t.Run("root type array returns nil", func(t *testing.T) {
		raw := json.RawMessage(`{"type":"array","items":{"type":"string"}}`)
		if got := schema.ExtractParams(raw); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})

	t.Run("root type string returns nil", func(t *testing.T) {
		raw := json.RawMessage(`{"type":"string"}`)
		if got := schema.ExtractParams(raw); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})

	t.Run("root type array-of-types returns nil", func(t *testing.T) {
		// Root type as an array is not a flat object schema for our purposes.
		raw := json.RawMessage(`{"type":["object","null"],"properties":{"a":{"type":"string"}}}`)
		if got := schema.ExtractParams(raw); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})

	t.Run("root type missing but properties present parses as object", func(t *testing.T) {
		raw := json.RawMessage(`{
			"properties":{
				"name":{"type":"string","description":"a name"}
			},
			"required":["name"]
		}`)
		got := schema.ExtractParams(raw)
		want := []schema.ParamInfo{{Name: "name", Type: "string", Required: true, Description: "a name"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v want %#v", got, want)
		}
	})

	t.Run("property value not a JSON object is silently skipped", func(t *testing.T) {
		raw := json.RawMessage(`{
			"type":"object",
			"properties":{
				"msg":"just a string",
				"valid":{"type":"number"}
			}
		}`)
		got := schema.ExtractParams(raw)
		want := []schema.ParamInfo{{Name: "valid", Type: "number"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v want %#v", got, want)
		}
	})

	t.Run("property type as array-of-types yields empty Type", func(t *testing.T) {
		raw := json.RawMessage(`{
			"type":"object",
			"properties":{
				"maybe":{"type":["string","null"],"description":"nullable"}
			}
		}`)
		got := schema.ExtractParams(raw)
		want := []schema.ParamInfo{{Name: "maybe", Type: "", Description: "nullable"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v want %#v", got, want)
		}
	})

	t.Run("malformed root JSON returns nil", func(t *testing.T) {
		raw := json.RawMessage(`{invalid`)
		if got := schema.ExtractParams(raw); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})

	t.Run("nested object property stays top-level only", func(t *testing.T) {
		raw := json.RawMessage(`{
			"type":"object",
			"properties":{
				"filter":{
					"type":"object",
					"properties":{
						"inner":{"type":"string"}
					}
				}
			}
		}`)
		got := schema.ExtractParams(raw)
		want := []schema.ParamInfo{{Name: "filter", Type: "object"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v want %#v", got, want)
		}
	})

	t.Run("description that is not a string is silently dropped", func(t *testing.T) {
		// Additional robustness check: a non-string description should
		// not panic or fail the whole property — just leave Description "".
		raw := json.RawMessage(`{
			"type":"object",
			"properties":{
				"a":{"type":"string","description":42}
			}
		}`)
		got := schema.ExtractParams(raw)
		want := []schema.ParamInfo{{Name: "a", Type: "string"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v want %#v", got, want)
		}
	})

	t.Run("empty properties map returns nil", func(t *testing.T) {
		// No usable properties → nil (preserving "no renderable signature"
		// semantics for the caller).
		raw := json.RawMessage(`{"type":"object","properties":{}}`)
		if got := schema.ExtractParams(raw); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})

	t.Run("malformed required array is silently ignored", func(t *testing.T) {
		// required as an object rather than array → drop, keep parse going.
		raw := json.RawMessage(`{
			"type":"object",
			"properties":{"a":{"type":"string"}},
			"required":{"not":"an array"}
		}`)
		got := schema.ExtractParams(raw)
		want := []schema.ParamInfo{{Name: "a", Type: "string", Required: false}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v want %#v", got, want)
		}
	})
}
