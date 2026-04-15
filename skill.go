package mcpserver

import (
	"log"
	"sort"
	"strings"

	"github.com/Superposition-Systems/go-mcp-server/internal/schema"
)

// SkillBuilder renders the markdown content returned by <prefix>_get_skill.
// It receives the underlying registry (not the mux's 4-tool shell) so it can
// enumerate real tools. See §4.4.
type SkillBuilder func(r *Registry) string

// SkillOptions configures DefaultSkillBuilder.
//
// DefaultSkillBuilder is prefix-agnostic: it does not know the mux prefix
// that will register <prefix>_get_skill. Consumers who want the prefix in
// the heading should pass it in Title (e.g. "Atlassian MCP — Routing
// Guide"). The generated footnote uses the prefix-free phrasing
// "Call the list_tools operation for full schemas." for the same reason.
type SkillOptions struct {
	// Title is the H1 heading. Defaults to "MCP — Routing Guide".
	Title string

	// Intro is free-form markdown prepended under the header.
	Intro string

	// Featured is a list of curated sections for the skill quick reference.
	Featured []Featured

	// Categorise, when true, appends a "## All Operations by Category"
	// section grouped by Tool.Category. Matches §4.4's default semantics
	// of true; consumers who construct SkillOptions{} explicitly get the
	// zero-value false — set to true explicitly when categorised output
	// is desired.
	Categorise bool
}

// Featured is a curated section of tool names for the skill quick reference.
//
// Sections whose Tools are all absent from the registry are omitted
// entirely (no header + no body) to avoid empty sections. Rationale: §9
// risk 7 flags this as open; omitting the whole section produces cleaner
// output than a bare "## Section" header with nothing under it.
type Featured struct {
	Section string
	Tools   []string
}

// DefaultSkillBuilder returns a SkillBuilder that renders:
//
//  1. Header + optional Intro.
//  2. Featured sections (in the order passed). Each tool is rendered as
//     "- **name**(signature) — description" where signature is derived
//     from internal/schema.ExtractParams(tool.InputSchema). When
//     ExtractParams returns nil (non-flat schema, or the Phase 0 stub),
//     the signature falls back to "(...)".
//     Missing tool names are skipped with a log.Printf warning. Sections
//     whose Tools are all missing are omitted.
//  3. When opts.Categorise is true, an "## All Operations by Category"
//     section with sorted categories. Tools with empty Category are
//     grouped under a final "### Uncategorised" subsection, which is
//     itself omitted when no uncategorised tools exist.
//  4. A footnote: "Call the list_tools operation for full schemas."
//
// Parameter rendering: a ParamInfo{Name: "n", Type: "string",
// Required: true} renders as "n: string"; when Required is false it
// renders as "*n*: string" (markdown italic) so required and optional are
// visually distinguishable. Type is omitted when empty.
func DefaultSkillBuilder(opts SkillOptions) SkillBuilder {
	return func(r *Registry) string {
		var b strings.Builder

		title := opts.Title
		if title == "" {
			title = "MCP — Routing Guide"
		}
		b.WriteString("# ")
		b.WriteString(title)
		b.WriteString("\n\n")

		if strings.TrimSpace(opts.Intro) != "" {
			b.WriteString(opts.Intro)
			// Ensure a blank line after intro.
			if !strings.HasSuffix(opts.Intro, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}

		// Featured sections.
		for _, f := range opts.Featured {
			renderFeatured(&b, r, f)
		}

		// Categorised listing.
		if opts.Categorise {
			renderCategorised(&b, r)
		}

		// Footnote.
		b.WriteString("Call the list_tools operation for full schemas.\n")
		return b.String()
	}
}

// sanitiseInline strips ASCII control characters (including newline,
// carriage return, and tab) from a string destined for a single markdown
// line, replacing each with a space. Prevents a tool registered with a
// Name/Description/Category/Section containing "\n## Fake Header\n" from
// injecting new markdown blocks into the rendered skill output.
//
// Markdown metacharacters (*, _, `, [, ]) are NOT escaped — a collision
// there only affects the rendering of one line, not the document
// structure. The structural attack is newlines; that's what we block.
// A run of control chars collapses to a single space so the result
// reads cleanly.
func sanitiseInline(s string) string {
	if s == "" {
		return ""
	}
	hasCtrl := false
	for _, r := range s {
		if r < 0x20 || r == 0x7F {
			hasCtrl = true
			break
		}
	}
	if !hasCtrl {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r < 0x20 || r == 0x7F {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	return strings.TrimSpace(b.String())
}

// renderFeatured emits one Featured section. If every named tool is
// absent from the registry, the entire section (header + body) is
// skipped to avoid empty "##" headers.
//
// Tool Name, Description, and Featured.Section are passed through
// sanitiseInline to block markdown-injection via control chars in
// caller-registered strings. This matters for muxes of 3rd-party APIs
// where tool metadata is derived from upstream names.
func renderFeatured(b *strings.Builder, r *Registry, f Featured) {
	present := make([]Tool, 0, len(f.Tools))
	for _, name := range f.Tools {
		t, ok := r.Lookup(name)
		if !ok {
			log.Printf("mcpserver: skill: featured tool %q not in registry", name)
			continue
		}
		present = append(present, t)
	}
	if len(present) == 0 {
		return
	}
	b.WriteString("## ")
	b.WriteString(sanitiseInline(f.Section))
	b.WriteString("\n\n")
	for _, t := range present {
		b.WriteString("- **")
		b.WriteString(sanitiseInline(t.Name))
		b.WriteString("**(")
		b.WriteString(renderSignature(t))
		b.WriteString(")")
		if t.Description != "" {
			b.WriteString(" — ")
			b.WriteString(sanitiseInline(t.Description))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

// renderSignature builds the parenthesised parameter list for a tool.
// Falls back to "..." when the schema is non-flat or the Phase 0 stub
// returns nil.
func renderSignature(t Tool) string {
	params := schema.ExtractParams(t.InputSchema)
	if len(params) == 0 {
		return "..."
	}
	parts := make([]string, 0, len(params))
	for _, p := range params {
		name := p.Name
		if !p.Required {
			name = "*" + name + "*"
		}
		if p.Type != "" {
			parts = append(parts, name+": "+p.Type)
		} else {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, ", ")
}

// renderCategorised emits the "All Operations by Category" section.
func renderCategorised(b *strings.Builder, r *Registry) {
	all := r.All()
	if len(all) == 0 {
		return
	}
	// Group by category.
	byCategory := map[string][]Tool{}
	var uncategorised []Tool
	for _, t := range all {
		if t.Category == "" {
			uncategorised = append(uncategorised, t)
			continue
		}
		byCategory[t.Category] = append(byCategory[t.Category], t)
	}

	// Only emit the "## All Operations by Category" header if there is
	// anything to show.
	if len(byCategory) == 0 && len(uncategorised) == 0 {
		return
	}
	b.WriteString("## All Operations by Category\n\n")

	cats := r.Categories() // sorted dedup of non-empty categories
	for _, c := range cats {
		b.WriteString("### ")
		b.WriteString(sanitiseInline(c))
		b.WriteString("\n\n")
		tools := byCategory[c]
		// r.All() is sorted by name; filter above preserves that order,
		// but a belt-and-braces sort keeps the output stable if All()
		// semantics ever change.
		sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
		for _, t := range tools {
			b.WriteString("- ")
			b.WriteString(sanitiseInline(t.Name))
			if t.Description != "" {
				b.WriteString(" — ")
				b.WriteString(sanitiseInline(t.Description))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if len(uncategorised) > 0 {
		b.WriteString("### Uncategorised\n\n")
		sort.Slice(uncategorised, func(i, j int) bool { return uncategorised[i].Name < uncategorised[j].Name })
		for _, t := range uncategorised {
			b.WriteString("- ")
			b.WriteString(sanitiseInline(t.Name))
			if t.Description != "" {
				b.WriteString(" — ")
				b.WriteString(sanitiseInline(t.Description))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
}
