package mcpserver_test

import (
	"encoding/json"
	"reflect"
	"testing"

	mcp "github.com/Superposition-Systems/go-mcp-server"
)

// TestCompactResponse_Identity — no options installed ⇒ identity transform.
func TestCompactResponse_Identity(t *testing.T) {
	tr := mcp.CompactResponse()
	in := map[string]any{"a": 1, "b": []any{"x"}, "c": nil}
	out := tr("sometool", in)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("identity: got %#v want %#v", out, in)
	}
}

// TestCompactResponse_StripFieldsNested — keys drop at any depth.
func TestCompactResponse_StripFieldsNested(t *testing.T) {
	tr := mcp.CompactResponse(mcp.StripFields("avatarUrls"))
	in := map[string]any{
		"a": map[string]any{
			"avatarUrls": map[string]any{"16x16": "u"},
			"x":          1,
		},
	}
	got := tr("", in).(map[string]any)
	inner := got["a"].(map[string]any)
	if _, ok := inner["avatarUrls"]; ok {
		t.Fatalf("nested avatarUrls not stripped: %#v", inner)
	}
	if inner["x"] != 1 {
		t.Fatalf("sibling mutated: %#v", inner)
	}
}

// TestCompactResponse_StripFieldsInArrayOfMaps — stripping applied to each
// map element inside a slice.
func TestCompactResponse_StripFieldsInArrayOfMaps(t *testing.T) {
	tr := mcp.CompactResponse(mcp.StripFields("expand"))
	in := map[string]any{
		"items": []any{
			map[string]any{"id": 1, "expand": "foo"},
			map[string]any{"id": 2},
		},
	}
	got := tr("", in).(map[string]any)
	items := got["items"].([]any)
	first := items[0].(map[string]any)
	if _, ok := first["expand"]; ok {
		t.Fatalf("expand not stripped: %#v", first)
	}
	if first["id"] != 1 {
		t.Fatalf("id missing: %#v", first)
	}
	// Also verify []map[string]any container type.
	in2 := map[string]any{
		"items": []map[string]any{
			{"id": 1, "expand": "foo"},
			{"id": 2},
		},
	}
	got2 := tr("", in2).(map[string]any)
	items2 := got2["items"].([]map[string]any)
	if _, ok := items2[0]["expand"]; ok {
		t.Fatalf("typed-slice: expand not stripped: %#v", items2[0])
	}
}

// TestCompactResponse_StripNulls — nils drop at top level and nested.
func TestCompactResponse_StripNulls(t *testing.T) {
	tr := mcp.CompactResponse(mcp.StripNulls())
	in := map[string]any{
		"x": nil,
		"y": 1,
		"nested": map[string]any{
			"a": nil,
			"b": 2,
		},
	}
	got := tr("", in).(map[string]any)
	if _, ok := got["x"]; ok {
		t.Fatalf("top-level nil not stripped: %#v", got)
	}
	inner := got["nested"].(map[string]any)
	if _, ok := inner["a"]; ok {
		t.Fatalf("nested nil not stripped: %#v", inner)
	}
	if inner["b"] != 2 {
		t.Fatalf("nested b missing: %#v", inner)
	}
}

// TestCompactResponse_StripEmptyArrays — empty-slice entries drop at any
// depth, including typed slices.
func TestCompactResponse_StripEmptyArrays(t *testing.T) {
	tr := mcp.CompactResponse(mcp.StripEmptyArrays())
	in := map[string]any{
		"tags":   []any{},
		"other":  []any{1},
		"typed":  []string{},
		"inside": map[string]any{"a": []int{}, "b": 3},
	}
	got := tr("", in).(map[string]any)
	if _, ok := got["tags"]; ok {
		t.Fatalf("[]any{} not stripped: %#v", got)
	}
	if _, ok := got["typed"]; ok {
		t.Fatalf("typed empty slice not stripped: %#v", got)
	}
	if len(got["other"].([]any)) != 1 {
		t.Fatalf("other mutated: %#v", got)
	}
	inner := got["inside"].(map[string]any)
	if _, ok := inner["a"]; ok {
		t.Fatalf("nested empty typed slice not stripped: %#v", inner)
	}
	if inner["b"] != 3 {
		t.Fatalf("nested b missing: %#v", inner)
	}
}

// TestCompactResponse_NoMutation — input must be left untouched even when
// strips apply.
func TestCompactResponse_NoMutation(t *testing.T) {
	tr := mcp.CompactResponse(mcp.StripFields("drop"), mcp.StripNulls(), mcp.StripEmptyArrays())
	inner := map[string]any{"drop": "x", "keep": 1}
	in := map[string]any{
		"outer": inner,
		"null":  nil,
		"empty": []any{},
		"arr":   []any{map[string]any{"drop": "y", "k": 2}},
	}
	_ = tr("", in)
	// Original map untouched.
	if _, ok := in["null"]; !ok {
		t.Fatalf("input mutated: null removed")
	}
	if _, ok := in["empty"]; !ok {
		t.Fatalf("input mutated: empty removed")
	}
	if _, ok := inner["drop"]; !ok {
		t.Fatalf("input mutated: inner drop removed")
	}
	if inner["keep"] != 1 {
		t.Fatalf("input mutated: inner keep changed")
	}
	arr := in["arr"].([]any)
	if _, ok := arr[0].(map[string]any)["drop"]; !ok {
		t.Fatalf("input mutated: array element modified")
	}
}

// TestCompactResponse_TopLevelSlice — result is a slice, not a map.
func TestCompactResponse_TopLevelSlice(t *testing.T) {
	tr := mcp.CompactResponse(mcp.StripFields("drop"))
	in := []any{
		map[string]any{"drop": 1, "keep": 2},
		map[string]any{"keep": 3},
	}
	got := tr("", in).([]any)
	first := got[0].(map[string]any)
	if _, ok := first["drop"]; ok {
		t.Fatalf("top-level slice: drop not stripped: %#v", first)
	}
}

// TestCompactResponse_TopLevelScalar — scalars pass through unchanged.
func TestCompactResponse_TopLevelScalar(t *testing.T) {
	tr := mcp.CompactResponse(mcp.StripFields("x"), mcp.StripNulls(), mcp.StripEmptyArrays())
	for _, v := range []any{"hello", 42, 3.14, true, nil} {
		if got := tr("", v); !reflect.DeepEqual(got, v) {
			t.Fatalf("scalar %v: got %v", v, got)
		}
	}
}

// TestCompactResponse_RawMessage — json.RawMessage is walked.
func TestCompactResponse_RawMessage(t *testing.T) {
	tr := mcp.CompactResponse(mcp.StripFields("drop"))
	raw := json.RawMessage(`{"drop":1,"keep":2}`)
	got := tr("", raw)
	b, ok := got.(json.RawMessage)
	if !ok {
		t.Fatalf("raw message: type %T", got)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, has := m["drop"]; has {
		t.Fatalf("raw: drop not stripped: %s", b)
	}
	if _, has := m["keep"]; !has {
		t.Fatalf("raw: keep missing: %s", b)
	}
}

// TestCompactREST_StripKeysNested — the preset drops avatarUrls, avatarUrl,
// iconUrl, expand at every depth.
func TestCompactREST_StripKeysNested(t *testing.T) {
	tr := mcp.CompactREST()
	in := map[string]any{
		"user": map[string]any{
			"avatarUrls": map[string]any{"16x16": "u"},
			"name":       "x",
		},
		"name": "x",
	}
	got := tr("", in).(map[string]any)
	user := got["user"].(map[string]any)
	if _, ok := user["avatarUrls"]; ok {
		t.Fatalf("CompactREST: nested avatarUrls kept: %#v", user)
	}
	if user["name"] != "x" {
		t.Fatalf("CompactREST: sibling mutated: %#v", user)
	}
	// We deliberately preserve the now-empty-map-like object (it still has
	// "name"); this test also documents the choice not to collapse empty
	// maps — the empty-map collapse is the caller's business, matching the
	// Node reference.
}

// TestCompactREST_SelfURLStripped — string-valued self parseable as URL
// drops; non-URL self is preserved.
func TestCompactREST_SelfURLStripped(t *testing.T) {
	tr := mcp.CompactREST()

	// Valid URL → stripped.
	in := map[string]any{"self": "https://jira.example/rest/api/2/issue/1", "id": 1}
	got := tr("", in).(map[string]any)
	if _, ok := got["self"]; ok {
		t.Fatalf("URL self not stripped: %#v", got)
	}

	// Object self → preserved.
	in2 := map[string]any{"self": map[string]any{"ref": "x"}, "id": 1}
	got2 := tr("", in2).(map[string]any)
	if _, ok := got2["self"]; !ok {
		t.Fatalf("object self should be preserved: %#v", got2)
	}

	// Non-URL string → preserved (no scheme/host).
	in3 := map[string]any{"self": "not-a-url", "id": 1}
	got3 := tr("", in3).(map[string]any)
	if _, ok := got3["self"]; !ok {
		t.Fatalf("non-URL string self should be preserved: %#v", got3)
	}

	// Nested URL self → stripped.
	in4 := map[string]any{
		"data": map[string]any{"self": "https://jira.example/rest/2/project/1", "k": 1},
	}
	got4 := tr("", in4).(map[string]any)
	nested := got4["data"].(map[string]any)
	if _, ok := nested["self"]; ok {
		t.Fatalf("nested URL self not stripped: %#v", nested)
	}
}

// TestCompactREST_SchemaTopLevelOnly — top-level schema drops; nested
// schema preserved.
func TestCompactREST_SchemaTopLevelOnly(t *testing.T) {
	tr := mcp.CompactREST()

	in := map[string]any{"schema": map[string]any{"x": 1}, "issues": []any{1, 2}}
	got := tr("", in).(map[string]any)
	if _, ok := got["schema"]; ok {
		t.Fatalf("top-level schema kept: %#v", got)
	}
	if _, ok := got["issues"]; !ok {
		t.Fatalf("issues missing: %#v", got)
	}

	in2 := map[string]any{"data": map[string]any{"schema": "x", "y": 2}}
	got2 := tr("", in2).(map[string]any)
	inner := got2["data"].(map[string]any)
	if _, ok := inner["schema"]; !ok {
		t.Fatalf("nested schema should be preserved: %#v", inner)
	}
}

// TestCompactREST_NullsTopLevelOnly — top-level nulls drop; nested nulls
// preserved (documents the intentional asymmetry with CompactResponse).
func TestCompactREST_NullsTopLevelOnly(t *testing.T) {
	tr := mcp.CompactREST()

	in := map[string]any{
		"x": nil,
		"y": 1,
		"nested": map[string]any{
			"a": nil,
			"b": 2,
		},
	}
	got := tr("", in).(map[string]any)
	if _, ok := got["x"]; ok {
		t.Fatalf("top-level nil kept: %#v", got)
	}
	inner := got["nested"].(map[string]any)
	if _, ok := inner["a"]; !ok {
		t.Fatalf("nested nil should be preserved by CompactREST: %#v", inner)
	}
	if inner["b"] != 2 {
		t.Fatalf("nested b mutated: %#v", inner)
	}
}

// TestCompactREST_NoMutation — preset must also be side-effect-free.
func TestCompactREST_NoMutation(t *testing.T) {
	tr := mcp.CompactREST()
	nested := map[string]any{"avatarUrls": map[string]any{"u": "v"}, "name": "n"}
	in := map[string]any{
		"self":   "https://jira.example/x",
		"schema": map[string]any{"f": 1},
		"user":   nested,
		"x":      nil,
	}
	_ = tr("", in)
	if _, ok := in["self"]; !ok {
		t.Fatalf("input mutated: self removed")
	}
	if _, ok := in["schema"]; !ok {
		t.Fatalf("input mutated: schema removed")
	}
	if _, ok := in["x"]; !ok {
		t.Fatalf("input mutated: null removed")
	}
	if _, ok := nested["avatarUrls"]; !ok {
		t.Fatalf("input mutated: nested avatarUrls removed")
	}
}

// TestCompactREST_ToolNamePassthrough — the transformer accepts a tool name
// and does not reject / modify anything based on it (Phase 2B does not
// look tools up).
func TestCompactREST_ToolNamePassthrough(t *testing.T) {
	tr := mcp.CompactREST()
	in := map[string]any{"k": 1}
	out := tr("any-tool-name-here", in)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("toolName should not affect identity pass: got %#v", out)
	}
}

// TestCompactResponse_Signature — the ResponseTransformer signature is
// stable: (toolName string, result any) any.
func TestCompactResponse_Signature(t *testing.T) {
	var tr mcp.ResponseTransformer = mcp.CompactResponse(mcp.StripFields("x"))
	_ = tr // compiles ⇒ signature stable
}
