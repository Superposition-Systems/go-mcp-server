package mcpserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strings"
	"testing"

	mcp "github.com/Superposition-Systems/go-mcp-server"
)

// skillTool returns a tool with the minimum fields needed for skill
// rendering.
func skillTool(name, desc, category string) mcp.Tool {
	return mcp.Tool{
		Name:        name,
		Description: desc,
		Category:    category,
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return nil, nil
		},
	}
}

func TestDefaultSkillBuilder_HeaderAndIntro(t *testing.T) {
	reg := mcp.NewRegistry()
	out := mcp.DefaultSkillBuilder(mcp.SkillOptions{
		Title: "Test",
		Intro: "Hi",
	})(reg)
	if !strings.HasPrefix(out, "# Test\n") {
		t.Errorf("expected output to start with '# Test\\n', got:\n%s", out)
	}
	if !strings.Contains(out, "Hi") {
		t.Errorf("expected intro 'Hi' in output:\n%s", out)
	}
	// Footnote must always appear.
	if !strings.Contains(out, "list_tools") {
		t.Errorf("expected footnote referencing list_tools, got:\n%s", out)
	}
}

func TestDefaultSkillBuilder_DefaultTitle(t *testing.T) {
	reg := mcp.NewRegistry()
	out := mcp.DefaultSkillBuilder(mcp.SkillOptions{})(reg)
	if !strings.HasPrefix(out, "# MCP — Routing Guide\n") {
		t.Errorf("expected default title, got:\n%s", out)
	}
}

func TestDefaultSkillBuilder_FeaturedMissingToolLogsAndSkips(t *testing.T) {
	reg := mcp.NewRegistry()
	// Capture log output.
	var buf bytes.Buffer
	oldOut := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(oldOut)
		log.SetFlags(oldFlags)
	}()

	out := mcp.DefaultSkillBuilder(mcp.SkillOptions{
		Featured: []mcp.Featured{
			{Section: "Nothing Here", Tools: []string{"ghost"}},
		},
	})(reg)

	// Section should be OMITTED entirely (per documented choice).
	if strings.Contains(out, "Nothing Here") {
		t.Errorf("expected empty Featured section to be skipped, got:\n%s", out)
	}
	if !strings.Contains(buf.String(), `featured tool "ghost" not in registry`) {
		t.Errorf("expected warning log, got: %q", buf.String())
	}
}

func TestDefaultSkillBuilder_FeaturedPresentToolIncluded(t *testing.T) {
	reg := mcp.NewRegistry()
	reg.MustRegister(skillTool("foo", "Does foo", ""))
	out := mcp.DefaultSkillBuilder(mcp.SkillOptions{
		Featured: []mcp.Featured{
			{Section: "Core", Tools: []string{"foo"}},
		},
	})(reg)

	if !strings.Contains(out, "## Core") {
		t.Errorf("expected section header, got:\n%s", out)
	}
	if !strings.Contains(out, "**foo**") {
		t.Errorf("expected featured tool name, got:\n%s", out)
	}
	// Phase 0: ExtractParams returns nil, signature falls back to "...".
	// Once track 2C ships, this test auto-strengthens: a flat schema
	// will render with its real params.
	if !strings.Contains(out, "foo**(...)") && !strings.Contains(out, "foo**(") {
		t.Errorf("expected signature rendering, got:\n%s", out)
	}
	if !strings.Contains(out, "Does foo") {
		t.Errorf("expected description, got:\n%s", out)
	}
}

func TestDefaultSkillBuilder_FeaturedMixedPresentAndMissing(t *testing.T) {
	reg := mcp.NewRegistry()
	reg.MustRegister(skillTool("present", "here", ""))

	var buf bytes.Buffer
	oldOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(oldOut)

	out := mcp.DefaultSkillBuilder(mcp.SkillOptions{
		Featured: []mcp.Featured{
			{Section: "Mixed", Tools: []string{"missing", "present"}},
		},
	})(reg)
	if !strings.Contains(out, "## Mixed") {
		t.Error("section with at least one present tool should render")
	}
	if !strings.Contains(out, "**present**") {
		t.Error("present tool should appear")
	}
	if strings.Contains(out, "**missing**") {
		t.Error("missing tool should be skipped")
	}
}

func TestDefaultSkillBuilder_CategoriseTrueGroupsByCategory(t *testing.T) {
	reg := mcp.NewRegistry()
	reg.MustRegister(skillTool("a1", "", "alpha"))
	reg.MustRegister(skillTool("b1", "", "beta"))
	reg.MustRegister(skillTool("a2", "", "alpha"))

	out := mcp.DefaultSkillBuilder(mcp.SkillOptions{Categorise: true})(reg)
	if !strings.Contains(out, "## All Operations by Category") {
		t.Error("expected categorised section header")
	}
	if !strings.Contains(out, "### alpha") {
		t.Error("expected alpha category header")
	}
	if !strings.Contains(out, "### beta") {
		t.Error("expected beta category header")
	}
	// Alpha should appear before beta (Categories() is sorted).
	ia := strings.Index(out, "### alpha")
	ib := strings.Index(out, "### beta")
	if ia < 0 || ib < 0 || ia > ib {
		t.Errorf("expected alpha before beta, indexes: %d, %d", ia, ib)
	}
}

func TestDefaultSkillBuilder_CategoriseFalseOmitsCategorySection(t *testing.T) {
	reg := mcp.NewRegistry()
	reg.MustRegister(skillTool("a1", "", "alpha"))
	out := mcp.DefaultSkillBuilder(mcp.SkillOptions{Categorise: false})(reg)
	if strings.Contains(out, "### ") {
		t.Errorf("expected no category subheadings with Categorise=false, got:\n%s", out)
	}
	if strings.Contains(out, "All Operations by Category") {
		t.Error("expected no 'All Operations by Category' with Categorise=false")
	}
}

func TestDefaultSkillBuilder_CategoriseTrueWithUncategorised(t *testing.T) {
	reg := mcp.NewRegistry()
	reg.MustRegister(skillTool("cat_tool", "", "named"))
	reg.MustRegister(skillTool("uncat_tool", "", ""))

	out := mcp.DefaultSkillBuilder(mcp.SkillOptions{Categorise: true})(reg)
	if !strings.Contains(out, "### named") {
		t.Error("expected named category header")
	}
	if !strings.Contains(out, "### Uncategorised") {
		t.Error("expected Uncategorised section when some tools have empty Category")
	}
	if !strings.Contains(out, "uncat_tool") {
		t.Error("expected uncategorised tool to appear under Uncategorised")
	}
}

func TestDefaultSkillBuilder_CategoriseTrueAllCategorisedOmitsUncategorised(t *testing.T) {
	reg := mcp.NewRegistry()
	reg.MustRegister(skillTool("a", "", "cat"))
	out := mcp.DefaultSkillBuilder(mcp.SkillOptions{Categorise: true})(reg)
	if strings.Contains(out, "Uncategorised") {
		t.Error("Uncategorised should not appear when every tool has a category")
	}
}

func TestDefaultSkillBuilder_EmptyRegistry(t *testing.T) {
	reg := mcp.NewRegistry()
	out := mcp.DefaultSkillBuilder(mcp.SkillOptions{Categorise: true})(reg)
	if !strings.HasPrefix(out, "# MCP — Routing Guide") {
		t.Error("expected header on empty registry")
	}
	if !strings.Contains(out, "list_tools") {
		t.Error("expected footnote on empty registry")
	}
	// Should not panic, and no categorised section since no tools.
	if strings.Contains(out, "All Operations by Category") {
		t.Error("empty registry should not render categorised section")
	}
}

func TestDefaultSkillBuilder_FeaturedSectionOrderStable(t *testing.T) {
	reg := mcp.NewRegistry()
	reg.MustRegister(skillTool("a", "", ""))
	reg.MustRegister(skillTool("b", "", ""))
	reg.MustRegister(skillTool("c", "", ""))
	out := mcp.DefaultSkillBuilder(mcp.SkillOptions{
		Featured: []mcp.Featured{
			{Section: "Second", Tools: []string{"b"}},
			{Section: "First", Tools: []string{"a"}},
			{Section: "Third", Tools: []string{"c"}},
		},
	})(reg)
	i1 := strings.Index(out, "## Second")
	i2 := strings.Index(out, "## First")
	i3 := strings.Index(out, "## Third")
	if i1 < 0 || i2 < 0 || i3 < 0 {
		t.Fatal("missing one of the Featured sections")
	}
	if !(i1 < i2 && i2 < i3) {
		t.Errorf("sections out of order: Second=%d First=%d Third=%d", i1, i2, i3)
	}
}
