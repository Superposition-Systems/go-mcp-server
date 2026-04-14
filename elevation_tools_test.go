package mcpserver

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Superposition-Systems/go-mcp-server/auth"
)

// newTestElevation spins up a composed Elevation with a tmp SQLite file
// and a short grant TTL so test cases can verify grant lifecycle quickly.
func newTestElevation(t *testing.T) *auth.Elevation {
	t.Helper()
	dir := t.TempDir()
	pw, err := auth.NewPasswordStore(filepath.Join(dir, "elev.db"), "")
	if err != nil {
		t.Fatalf("NewPasswordStore: %v", err)
	}
	t.Cleanup(func() { _ = pw.Close() })
	return auth.NewElevation(pw, auth.NewGrantStore(), 100*time.Millisecond)
}

// stubInner is a minimal ToolHandler used by the composite wrapper tests.
type stubInner struct {
	tools []ToolDef
}

func (s *stubInner) ListTools() []ToolDef { return s.tools }
func (s *stubInner) Call(ctx context.Context, name string, args map[string]any) (any, bool) {
	return map[string]any{"tool": name}, false
}

func TestElevationTools_ListIncludesBothLibraryTools(t *testing.T) {
	et := &elevationTools{
		inner:   &stubInner{tools: []ToolDef{{Name: "user_tool"}}},
		elev:    newTestElevation(t),
		elevate: "vps_elevate",
		setPwd:  "vps_set_elevation_password",
	}
	got := et.ListTools()
	if len(got) != 3 {
		t.Fatalf("expected 3 tools (1 user + 2 library), got %d: %+v", len(got), toolNames(got))
	}
	if !hasTool(got, "user_tool") || !hasTool(got, "vps_elevate") || !hasTool(got, "vps_set_elevation_password") {
		t.Fatalf("missing expected tool in %+v", toolNames(got))
	}
}

func TestElevationTools_UserToolShadowsLibraryOnCollision(t *testing.T) {
	et := &elevationTools{
		inner:     &stubInner{tools: []ToolDef{{Name: "vps_elevate"}}}, // user registered the same name
		elev:      newTestElevation(t),
		elevate:   "vps_elevate",
		setPwd:    "vps_set_elevation_password",
		userNames: map[string]struct{}{"vps_elevate": {}},
	}
	got := et.ListTools()
	// Only one "vps_elevate" should appear (user's) and the library's set_password still shows.
	elevates := 0
	for _, tool := range got {
		if tool.Name == "vps_elevate" {
			elevates++
		}
	}
	if elevates != 1 {
		t.Fatalf("expected exactly 1 vps_elevate tool, got %d", elevates)
	}

	// And the Call path must route the collided name to the user.
	result, _ := et.Call(context.Background(), "vps_elevate", map[string]any{})
	m, _ := result.(map[string]any)
	if m["tool"] != "vps_elevate" {
		t.Fatalf("expected user handler to be called on collision, got %+v", result)
	}
}

func TestElevationTools_BootstrapElevate(t *testing.T) {
	et := &elevationTools{
		inner:   &stubInner{},
		elev:    newTestElevation(t),
		elevate: "vps_elevate",
		setPwd:  "vps_set_elevation_password",
	}
	ctx := auth.WithTokenHash(context.Background(), auth.TokenHash("t"))
	result, isErr := et.Call(ctx, "vps_elevate", map[string]any{"password": "anything"})
	if isErr {
		t.Fatalf("bootstrap elevate should not return an error result, got %+v", result)
	}
	m := result.(map[string]any)
	if m["bootstrap"] != true {
		t.Fatalf("expected bootstrap=true, got %+v", m)
	}
}

func TestElevationTools_SetInitialClosesBootstrap(t *testing.T) {
	et := &elevationTools{
		inner:   &stubInner{},
		elev:    newTestElevation(t),
		elevate: "vps_elevate",
		setPwd:  "vps_set_elevation_password",
	}
	ctx := auth.WithTokenHash(context.Background(), auth.TokenHash("t"))

	// Initially bootstrap -> HasCurrentSession is true for any authenticated session.
	if !et.elev.HasCurrentSession(ctx) {
		t.Fatal("expected bootstrap elevation before set_initial")
	}

	// Missing bootstrap_token must be rejected — a compromised client
	// should not be able to seize the elevation password.
	result, isErr := et.Call(ctx, "vps_set_elevation_password", map[string]any{"new_password": "first"})
	if !isErr {
		t.Fatalf("set_initial without bootstrap_token must fail, got %+v", result)
	}

	token := et.elev.PasswordStore().BootstrapToken()
	result, isErr = et.Call(ctx, "vps_set_elevation_password", map[string]any{
		"new_password":    "first",
		"bootstrap_token": token,
	})
	if isErr {
		t.Fatalf("set_initial with bootstrap_token should succeed, got %+v", result)
	}
	m := result.(map[string]any)
	if m["status"] != "set" {
		t.Fatalf("expected status=set, got %+v", m)
	}

	// After setting, bootstrap closes. Same session is no longer implicitly elevated.
	if et.elev.HasCurrentSession(ctx) {
		t.Fatal("bootstrap should have closed; session should not be elevated until vps_elevate")
	}

	// Wrong password rejected.
	result, isErr = et.Call(ctx, "vps_elevate", map[string]any{"password": "wrong"})
	if !isErr {
		t.Fatalf("wrong password should return error result, got %+v", result)
	}

	// Correct password grants elevation.
	result, isErr = et.Call(ctx, "vps_elevate", map[string]any{"password": "first"})
	if isErr {
		t.Fatalf("correct password should succeed, got %+v", result)
	}
	if !et.elev.HasCurrentSession(ctx) {
		t.Fatal("session should be elevated after successful elevate")
	}
}

func TestElevationTools_RotationRequiresCurrent(t *testing.T) {
	et := &elevationTools{
		inner:   &stubInner{},
		elev:    newTestElevation(t),
		elevate: "vps_elevate",
		setPwd:  "vps_set_elevation_password",
	}
	ctx := auth.WithTokenHash(context.Background(), auth.TokenHash("t"))

	// Establish initial password (requires bootstrap_token).
	token := et.elev.PasswordStore().BootstrapToken()
	_, _ = et.Call(ctx, "vps_set_elevation_password", map[string]any{
		"new_password":    "first",
		"bootstrap_token": token,
	})

	// Rotate without current_password -> error.
	result, isErr := et.Call(ctx, "vps_set_elevation_password", map[string]any{"new_password": "second"})
	if !isErr {
		t.Fatalf("rotation without current_password should fail, got %+v", result)
	}

	// Rotate with wrong current_password -> error.
	result, isErr = et.Call(ctx, "vps_set_elevation_password", map[string]any{
		"current_password": "wrong",
		"new_password":     "second",
	})
	if !isErr {
		t.Fatalf("rotation with wrong current_password should fail, got %+v", result)
	}

	// Grant something, then rotate; rotation must revoke grants.
	_, _ = et.Call(ctx, "vps_elevate", map[string]any{"password": "first"})
	if !et.elev.HasCurrentSession(ctx) {
		t.Fatal("precondition: should be elevated before rotation")
	}

	result, isErr = et.Call(ctx, "vps_set_elevation_password", map[string]any{
		"current_password": "first",
		"new_password":     "second",
	})
	if isErr {
		t.Fatalf("valid rotation should succeed, got %+v", result)
	}
	if et.elev.HasCurrentSession(ctx) {
		t.Fatal("rotation must revoke all active grants")
	}

	// Old password no longer works; new one does.
	if et.elev.PasswordStore().Verify("first") {
		t.Fatal("old password should no longer verify")
	}
	if !et.elev.PasswordStore().Verify("second") {
		t.Fatal("new password should verify")
	}
}

func TestSanitizeToolPrefix(t *testing.T) {
	cases := map[string]string{
		"":             "mcp",
		"vps-mcp":      "vps_mcp",
		"My Server":    "my_server",
		"NOTES":        "notes",
	}
	for in, want := range cases {
		if got := sanitizeToolPrefix(in); got != want {
			t.Errorf("sanitizeToolPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// -----------------------------------------------------------------------------

func toolNames(defs []ToolDef) []string {
	out := make([]string, len(defs))
	for i, d := range defs {
		out[i] = d.Name
	}
	return out
}

func hasTool(defs []ToolDef, name string) bool {
	for _, d := range defs {
		if d.Name == name {
			return true
		}
	}
	return false
}
