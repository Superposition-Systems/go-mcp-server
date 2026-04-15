package mcpserver

// ValidationOption configures WithInputValidation. See §4.6.
type ValidationOption func(*validationConfig)

type validationConfig struct {
	strict bool
	coerce bool
}

// ValidationStrict makes the validator reject unknown fields (equivalent to
// additionalProperties: false).
func ValidationStrict() ValidationOption {
	return func(c *validationConfig) { c.strict = true }
}

// ValidationCoerce makes the validator coerce scalar values where the
// schema permits (e.g. string "42" → int 42).
func ValidationCoerce() ValidationOption {
	return func(c *validationConfig) { c.coerce = true }
}

// inputValidationMiddleware builds the schema-validation middleware used by
// WithInputValidation.
//
// Phase 0 minimal impl: returns an identity middleware. Session 3 (track
// 4A) replaces the body with a santhosh-tekuri/jsonschema/v6-backed
// validator that short-circuits with err != nil on validation failure,
// fires suggest.EventUnknownParam on unknown fields under strict mode, and
// coerces scalars under ValidationCoerce.
func inputValidationMiddleware(opts []ValidationOption) ToolMiddleware {
	cfg := &validationConfig{}
	for _, o := range opts {
		o(cfg)
	}
	_ = cfg
	return func(next ToolCallFunc) ToolCallFunc { return next }
}
