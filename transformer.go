package mcpserver

import (
	"encoding/json"
	"net/url"
	"reflect"
)

// ResponseTransformer mutates or replaces the result of a successful tool
// call before it is serialised to the wire. See §4.3.
type ResponseTransformer func(toolName string, result any) any

// CompactOption configures CompactResponse.
type CompactOption func(*compactConfig)

type compactConfig struct {
	stripFields      map[string]struct{}
	stripNulls       bool
	stripEmptyArrays bool
}

// StripFields returns a CompactOption that strips the given field names at
// any depth in the result tree (top-level map, nested maps, maps inside
// slices — key-name matching is case-sensitive exact match, mirroring the
// Node reference implementation at mux-tools.mjs:189-214).
func StripFields(fieldNames ...string) CompactOption {
	return func(c *compactConfig) {
		if c.stripFields == nil {
			c.stripFields = map[string]struct{}{}
		}
		for _, f := range fieldNames {
			c.stripFields[f] = struct{}{}
		}
	}
}

// StripNulls returns a CompactOption that drops map entries whose value is
// Go nil (including JSON null when the value is an already-decoded any).
// Applies at every depth that CompactResponse walks.
func StripNulls() CompactOption { return func(c *compactConfig) { c.stripNulls = true } }

// StripEmptyArrays returns a CompactOption that drops map entries whose
// value is a zero-length slice of any element type. Applies at every depth.
func StripEmptyArrays() CompactOption {
	return func(c *compactConfig) { c.stripEmptyArrays = true }
}

// CompactResponse returns a ResponseTransformer that walks the result
// recursively and removes entries per the supplied options:
//
//   - StripFields: drop any map key whose name appears in the set, at any
//     depth. Matching is case-sensitive.
//   - StripNulls: drop map entries whose value is Go nil.
//   - StripEmptyArrays: drop map entries whose value is a zero-length
//     slice of any element type.
//
// The returned transformer is pure: it never mutates its input. Branches
// that contain no strips are returned as-is (shallow) to avoid allocation;
// branches that do need a strip are rebuilt as fresh maps/slices. With no
// options, the transformer is an identity function.
//
// Recognised container shapes: `map[string]any`, `[]any`, `[]map[string]any`,
// and the typed `[]T` case (walked via reflect only deeply enough to detect
// empty-slice values; element contents of arbitrary `[]T` are not rewritten).
// A `json.RawMessage` is decoded into `any` for walking and re-encoded on
// the way out; if decode fails the raw bytes pass through unchanged.
func CompactResponse(opts ...CompactOption) ResponseTransformer {
	cfg := &compactConfig{}
	for _, o := range opts {
		o(cfg)
	}
	// No options → identity. Avoids any allocation on the hot path.
	if len(cfg.stripFields) == 0 && !cfg.stripNulls && !cfg.stripEmptyArrays {
		return func(_ string, result any) any { return result }
	}
	return func(_ string, result any) any {
		return compactWalk(result, cfg, true)
	}
}

// CompactREST is a preset matching the Node reference implementation at
// mux-tools.mjs:178-214. It applies these strips:
//
//   - At ANY depth: drop keys `avatarUrls`, `avatarUrl`, `iconUrl`, `expand`.
//   - At ANY depth: drop key `self` iff its value is a string parseable as a
//     URL with both a non-empty Scheme and Host. Non-URL `self` values
//     (e.g. a self-reference object) are preserved.
//   - At the ROOT only: drop key `schema`.
//   - At the ROOT only: drop entries whose value is Go nil.
//
// Note the deliberate asymmetry: `schema` and null-stripping are top-level
// only (matching Node's `compactResponse` in the reference), while the
// key-name and URL-self strips recurse. Callers who want nested nulls
// dropped should compose CompactResponse(StripNulls()) themselves.
//
// As with CompactResponse, the returned transformer never mutates its
// input. Empty maps left behind after stripping are preserved (not
// collapsed) — the Node implementation does not collapse them either, and
// callers that want the collapse can strip the parent key explicitly.
func CompactREST() ResponseTransformer {
	stripKeys := map[string]struct{}{
		"avatarUrls": {},
		"avatarUrl":  {},
		"iconUrl":    {},
		"expand":     {},
	}
	return func(_ string, result any) any {
		return compactRESTWalk(result, stripKeys, true)
	}
}

// compactWalk recursively applies cfg to v. `root` is true only at the
// outermost invocation; nested calls pass false. The current implementation
// applies every configured strip at every depth (no top-level-only rules),
// so `root` is accepted for future-proofing and ignored here.
func compactWalk(v any, cfg *compactConfig, _ bool) any {
	switch m := v.(type) {
	case map[string]any:
		return compactMap(m, cfg)
	case []any:
		return compactSlice(m, cfg)
	case []map[string]any:
		// Walk each element; rebuild only if any element changes.
		out := make([]map[string]any, len(m))
		changed := false
		for i, e := range m {
			w := compactMap(e, cfg)
			if wm, ok := w.(map[string]any); ok {
				// compactMap may return the same map unchanged, or a fresh one.
				if !changed && !sameMap(e, wm) {
					changed = true
				}
				out[i] = wm
			} else {
				changed = true
				// Coerce: fall through to []any path by rebuilding there.
				// In practice compactMap always returns map[string]any for
				// map[string]any input, so this branch is unreachable.
				out[i] = e
			}
		}
		if !changed {
			return m
		}
		return out
	case json.RawMessage:
		if len(m) == 0 {
			return m
		}
		var decoded any
		if err := json.Unmarshal(m, &decoded); err != nil {
			return m
		}
		walked := compactWalk(decoded, cfg, false)
		enc, err := json.Marshal(walked)
		if err != nil {
			return m
		}
		return json.RawMessage(enc)
	default:
		return v
	}
}

// compactMap walks a map[string]any. Returns the input map unchanged (same
// pointer) if no entries were stripped or rewritten; otherwise returns a
// fresh map.
func compactMap(m map[string]any, cfg *compactConfig) any {
	// First pass: determine whether we need to rebuild. If any key must be
	// dropped, or any child value changes identity, rebuild.
	var out map[string]any
	ensureOut := func() {
		if out == nil {
			out = make(map[string]any, len(m))
			for k, v := range m {
				out[k] = v
			}
		}
	}
	for k, v := range m {
		// StripFields at any depth.
		if _, drop := cfg.stripFields[k]; drop {
			ensureOut()
			delete(out, k)
			continue
		}
		// StripNulls at any depth.
		if cfg.stripNulls && v == nil {
			ensureOut()
			delete(out, k)
			continue
		}
		// StripEmptyArrays at any depth.
		if cfg.stripEmptyArrays && isEmptySlice(v) {
			ensureOut()
			delete(out, k)
			continue
		}
		// Recurse into nested containers.
		nv := compactWalk(v, cfg, false)
		if !sameValue(v, nv) {
			ensureOut()
			out[k] = nv
		}
	}
	if out == nil {
		return m
	}
	return out
}

// compactSlice walks a []any.
func compactSlice(s []any, cfg *compactConfig) any {
	var out []any
	for i, e := range s {
		ne := compactWalk(e, cfg, false)
		if !sameValue(e, ne) {
			if out == nil {
				out = make([]any, len(s))
				copy(out, s)
			}
			out[i] = ne
		}
	}
	if out == nil {
		return s
	}
	return out
}

// compactRESTWalk implements the CompactREST semantics. `root` true signals
// that the extra top-level-only rules (strip `schema`, strip nulls) apply.
func compactRESTWalk(v any, stripKeys map[string]struct{}, root bool) any {
	switch m := v.(type) {
	case map[string]any:
		return compactRESTMap(m, stripKeys, root)
	case []any:
		var out []any
		for i, e := range m {
			ne := compactRESTWalk(e, stripKeys, false)
			if !sameValue(e, ne) {
				if out == nil {
					out = make([]any, len(m))
					copy(out, m)
				}
				out[i] = ne
			}
		}
		if out == nil {
			return m
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, len(m))
		changed := false
		for i, e := range m {
			w := compactRESTMap(e, stripKeys, false)
			if wm, ok := w.(map[string]any); ok {
				if !changed && !sameMap(e, wm) {
					changed = true
				}
				out[i] = wm
			} else {
				changed = true
				out[i] = e
			}
		}
		if !changed {
			return m
		}
		return out
	case json.RawMessage:
		if len(m) == 0 {
			return m
		}
		var decoded any
		if err := json.Unmarshal(m, &decoded); err != nil {
			return m
		}
		walked := compactRESTWalk(decoded, stripKeys, root)
		enc, err := json.Marshal(walked)
		if err != nil {
			return m
		}
		return json.RawMessage(enc)
	default:
		return v
	}
}

func compactRESTMap(m map[string]any, stripKeys map[string]struct{}, root bool) any {
	var out map[string]any
	ensureOut := func() {
		if out == nil {
			out = make(map[string]any, len(m))
			for k, v := range m {
				out[k] = v
			}
		}
	}
	for k, v := range m {
		if _, drop := stripKeys[k]; drop {
			ensureOut()
			delete(out, k)
			continue
		}
		if k == "self" && isURLString(v) {
			ensureOut()
			delete(out, k)
			continue
		}
		if root && k == "schema" {
			ensureOut()
			delete(out, k)
			continue
		}
		if root && v == nil {
			ensureOut()
			delete(out, k)
			continue
		}
		nv := compactRESTWalk(v, stripKeys, false)
		if !sameValue(v, nv) {
			ensureOut()
			out[k] = nv
		}
	}
	if out == nil {
		return m
	}
	return out
}

// isURLString reports whether v is a non-empty string that parses as a URL
// with a non-empty Scheme and Host (mirrors the Node self-URL check).
func isURLString(v any) bool {
	s, ok := v.(string)
	if !ok || s == "" {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}

// isEmptySlice reports whether v is any kind of slice with zero length.
// Uses reflect to handle both []any and typed slices ([]string, []int, ...).
func isEmptySlice(v any) bool {
	if v == nil {
		return false
	}
	// Fast path for common case.
	if s, ok := v.([]any); ok {
		return len(s) == 0
	}
	if s, ok := v.([]map[string]any); ok {
		return len(s) == 0
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice {
		return rv.Len() == 0
	}
	return false
}

// sameMap reports whether two map[string]any share the same underlying
// header (i.e. compactMap returned the input unchanged).
func sameMap(a, b map[string]any) bool {
	// Two maps share identity iff reflect.ValueOf(...).Pointer() agree.
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

// sameValue reports whether two arbitrary values refer to the same
// underlying container (for maps/slices), or are equal primitives. Used to
// detect whether a recursive walk rewrote a child so the parent can decide
// whether to rebuild.
func sameValue(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	ra := reflect.ValueOf(a)
	rb := reflect.ValueOf(b)
	if ra.Kind() != rb.Kind() {
		return false
	}
	switch ra.Kind() {
	case reflect.Map, reflect.Slice:
		if ra.IsNil() != rb.IsNil() {
			return false
		}
		if ra.Len() != rb.Len() {
			return false
		}
		return ra.Pointer() == rb.Pointer()
	default:
		// For primitives we only need "did the walk change the value".
		// Walks never rewrite primitives, so returning true here is safe
		// and avoids a reflect.DeepEqual on every leaf.
		return true
	}
}
