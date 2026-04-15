package mcpserver

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

// StripFields returns a CompactOption that strips the given field names
// (at any depth, per track 2B's production implementation).
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

// StripNulls returns a CompactOption that drops nil-valued fields.
func StripNulls() CompactOption { return func(c *compactConfig) { c.stripNulls = true } }

// StripEmptyArrays returns a CompactOption that drops empty-slice fields.
func StripEmptyArrays() CompactOption {
	return func(c *compactConfig) { c.stripEmptyArrays = true }
}

// CompactResponse returns a transformer configured by the given options.
//
// Phase 0 minimal impl: returns an identity transformer. Session 2
// (track 2B) replaces the body with the actual recursive strip logic
// mirroring Node mux-tools.mjs:189-214.
func CompactResponse(opts ...CompactOption) ResponseTransformer {
	cfg := &compactConfig{}
	for _, o := range opts {
		o(cfg)
	}
	_ = cfg // consumed by track 2B
	return func(_ string, result any) any { return result }
}

// CompactREST is the preset matching Node's STRIP_KEYS + self-URL + top-level
// schema + top-level null behaviour (see mux-tools.mjs:178-214).
//
// Phase 0: identity; track 2B replaces with real logic.
func CompactREST() ResponseTransformer {
	return CompactResponse(
		StripFields("avatarUrls", "avatarUrl", "iconUrl", "expand"),
		StripNulls(),
	)
}
