package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Superposition-Systems/go-mcp-server/auth"
)

// Elevation returns the server's elevation handle, initializing the
// underlying stores lazily on first call. Returns nil if WithElevation
// was not configured. Safe to call from tool construction (before
// ListenAndServe).
func (s *Server) Elevation() *auth.Elevation {
	if s.elevationConfig == nil {
		return nil
	}
	s.elevationOnce.Do(func() {
		cfg := s.elevationConfig
		dbPath := cfg.DBPath
		if dbPath == "" {
			s.elevationErr = errors.New("elevation: DBPath is required")
			log.Printf("mcpserver: elevation init failed: %v", s.elevationErr)
			return
		}
		var envPwd string
		if cfg.EnvPasswordVar != "" {
			envPwd = os.Getenv(cfg.EnvPasswordVar)
		}
		pwd, err := auth.NewPasswordStore(dbPath, envPwd)
		if err != nil {
			s.elevationErr = fmt.Errorf("elevation: password store: %w", err)
			log.Printf("mcpserver: %v", s.elevationErr)
			return
		}
		s.elevationPwd = pwd
		s.elevation = auth.NewElevation(pwd, auth.NewGrantStore(), cfg.GrantTTL)

		if pwd.IsSet() {
			log.Printf("mcpserver: elevation password configured (env_override=%v, ttl=%s)",
				envPwd != "", s.elevation.TTL())
		} else {
			log.Printf("mcpserver: elevation in bootstrap mode — no password set, all authenticated sessions are elevated until set_elevation_password is called")
		}
	})
	return s.elevation
}

// elevationToolPrefix returns the configured prefix, falling back to the
// server's name (with hyphens -> underscores) if none was set.
func (s *Server) elevationToolPrefix() string {
	if s.elevationConfig == nil {
		return ""
	}
	if s.elevationConfig.ToolNamePrefix != "" {
		return s.elevationConfig.ToolNamePrefix
	}
	return sanitizeToolPrefix(s.info.Name)
}

func sanitizeToolPrefix(name string) string {
	if name == "" {
		return "mcp"
	}
	// MCP tool names are [a-z0-9_]+ by convention.
	r := strings.ToLower(name)
	r = strings.ReplaceAll(r, "-", "_")
	r = strings.ReplaceAll(r, " ", "_")
	return r
}

// wrapToolsWithElevation returns a composite ToolHandler that adds the
// library-provided elevation tools on top of the user's handler. The
// user's tool names win in case of collision (defensive — users shouldn't
// reuse the library's prefixed names, but if they do, their tool is
// reachable while the library tool is shadowed).
func (s *Server) wrapToolsWithElevation(user ToolHandler) ToolHandler {
	if s.Elevation() == nil {
		return user
	}
	prefix := s.elevationToolPrefix()
	return &elevationTools{
		inner:    user,
		elev:     s.Elevation(),
		elevate:  prefix + "_elevate",
		setPwd:   prefix + "_set_elevation_password",
	}
}

// elevationTools composes the user's tool handler with the two elevation
// tools. List returns user_tools ++ library_tools; Call dispatches by
// name, preferring user_tools on collision.
type elevationTools struct {
	inner   ToolHandler
	elev    *auth.Elevation
	elevate string // e.g. "vps_elevate"
	setPwd  string // e.g. "vps_set_elevation_password"
}

func (e *elevationTools) ListTools() []ToolDef {
	user := e.inner.ListTools()
	userNames := make(map[string]struct{}, len(user))
	for _, t := range user {
		userNames[t.Name] = struct{}{}
	}

	out := make([]ToolDef, 0, len(user)+2)
	out = append(out, user...)

	if _, dup := userNames[e.elevate]; !dup {
		out = append(out, ToolDef{
			Name: e.elevate,
			Description: "Elevate this session to write permissions for the configured TTL " +
				"by providing the elevation password. In bootstrap mode (no password " +
				"configured) this tool is a no-op — all authenticated sessions are " +
				"already elevated.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"password": map[string]any{
						"type":        "string",
						"description": "Elevation password",
					},
				},
				"required":             []string{"password"},
				"additionalProperties": false,
			},
		})
	}
	if _, dup := userNames[e.setPwd]; !dup {
		out = append(out, ToolDef{
			Name: e.setPwd,
			Description: "Set or rotate the elevation password. When no password exists " +
				"(bootstrap mode), pass only 'new_password' to establish it. To rotate " +
				"an existing password, pass both 'current_password' and 'new_password'. " +
				"Rotation revokes all active elevations.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"new_password": map[string]any{
						"type":        "string",
						"description": "The new elevation password",
					},
					"current_password": map[string]any{
						"type":        "string",
						"description": "Required when a password is already set (rotation)",
					},
				},
				"required":             []string{"new_password"},
				"additionalProperties": false,
			},
		})
	}
	return out
}

func (e *elevationTools) Call(ctx context.Context, name string, args map[string]any) (any, bool) {
	// Prefer user handler on collision.
	for _, t := range e.inner.ListTools() {
		if t.Name == name {
			return e.inner.Call(ctx, name, args)
		}
	}
	switch name {
	case e.elevate:
		return e.handleElevate(ctx, args)
	case e.setPwd:
		return e.handleSetPassword(ctx, args)
	default:
		return e.inner.Call(ctx, name, args)
	}
}

func (e *elevationTools) handleElevate(ctx context.Context, args map[string]any) (any, bool) {
	password, _ := args["password"].(string)
	if password == "" {
		return map[string]any{"error": "password is required"}, true
	}
	exp, err := e.elev.Elevate(ctx, password)
	if err != nil {
		if errors.Is(err, auth.ErrBootstrapAlreadyElevated) {
			return map[string]any{
				"elevated":      true,
				"bootstrap":     true,
				"note":          "No elevation password set — all authenticated sessions are elevated by default. Set a password with " + e.setPwd + " to enable gating.",
			}, false
		}
		if errors.Is(err, auth.ErrIncorrectPassword) {
			return map[string]any{"error": "incorrect elevation password", "elevated": false}, true
		}
		return map[string]any{"error": err.Error(), "elevated": false}, true
	}
	return map[string]any{
		"elevated":        true,
		"elevated_until":  exp.UTC().Format(time.RFC3339),
		"ttl_seconds":     int(e.elev.TTL().Seconds()),
	}, false
}

func (e *elevationTools) handleSetPassword(ctx context.Context, args map[string]any) (any, bool) {
	newPwd, _ := args["new_password"].(string)
	curPwd, _ := args["current_password"].(string)
	if newPwd == "" {
		return map[string]any{"error": "new_password is required"}, true
	}
	pwStore := e.elev.PasswordStore()
	if pwStore == nil {
		return map[string]any{"error": "elevation store not initialized"}, true
	}

	if pwStore.IsSet() {
		if curPwd == "" {
			return map[string]any{"error": "current_password is required to rotate an existing password"}, true
		}
		if err := pwStore.Rotate(curPwd, newPwd); err != nil {
			if errors.Is(err, auth.ErrIncorrectPassword) {
				return map[string]any{"error": "incorrect current password"}, true
			}
			return map[string]any{"error": err.Error()}, true
		}
		// Rotation revokes all active elevations — whoever knew the old
		// password shouldn't retain elevated access afterwards.
		e.elev.GrantStore().RevokeAll()
		return map[string]any{
			"status":  "rotated",
			"message": "password rotated; all active elevations revoked",
		}, false
	}

	// Bootstrap path — no password yet.
	if err := pwStore.SetInitial(newPwd); err != nil {
		return map[string]any{"error": err.Error()}, true
	}
	return map[string]any{
		"status":  "set",
		"message": "elevation password established; bootstrap mode closed",
	}, false
}
