package mcpserver

// SkillBuilder renders the markdown content returned by <prefix>_get_skill.
// It receives the underlying registry (not the mux's 4-tool shell) so it can
// enumerate real tools. See §4.4.
type SkillBuilder func(r *Registry) string

// SkillOptions configures DefaultSkillBuilder.
type SkillOptions struct {
	Title      string     // default "<Prefix> MCP — Routing Guide"
	Intro      string     // free-form markdown prepended under the header
	Featured   []Featured // optional curated highlights
	Categorise bool       // default true; emit "## All Operations by Category"
}

// Featured is a curated section of tool names for the skill quick reference.
type Featured struct {
	Section string
	Tools   []string
}

// DefaultSkillBuilder returns a SkillBuilder that renders:
//
//  1. Header + Intro (from opts)
//  2. Quick-reference sections built from opts.Featured (signatures derived
//     from each tool's top-level InputSchema properties + required)
//  3. "All operations by category" grouped by Tool.Category
//  4. Footnote pointing at <prefix>_list_tools for full schemas
//
// Phase 0 minimal impl: emits the header and a pointer to the pending
// implementation. Session 2 (track 3B) replaces the body with the full
// renderer using internal/schema.ExtractParams.
func DefaultSkillBuilder(opts SkillOptions) SkillBuilder {
	return func(r *Registry) string {
		title := opts.Title
		if title == "" {
			title = "MCP — Routing Guide"
		}
		return "# " + title + "\n\n" + opts.Intro +
			"\n\n(skill content pending — Session 2 track 3B)\n"
	}
}
