package mcpserver

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
)

// Tool is a self-describing unit of functionality registered with a Registry.
// See docs/plans/v0.8.0-middleware-and-registry.md §4.1.
//
// Phase 0 scaffold: fields are defined and wired; Session 1 (track 1A)
// adds stable-sort, duplicate-name detection, MustRegister panic variant,
// and a registration-after-ListenAndServe guard.
type Tool struct {
	Name         string
	Description  string
	InputSchema  json.RawMessage
	Category     string
	Tags         []string
	ParamAliases map[string]string
	Handler      func(ctx context.Context, args map[string]any) (any, error)
}

// Registry is an ergonomic alternative to implementing ToolHandler directly.
// A Registry implements ToolHandler via AsToolHandler.
//
// Phase 0 minimal impl: mutex-protected map with the basic operations.
type Registry struct {
	mu    sync.Mutex
	tools map[string]Tool
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{tools: map[string]Tool{}}
}

// Register adds a tool. Phase 0: last write wins; track 1A changes this to
// return an error on duplicate name.
func (r *Registry) Register(t Tool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name] = t
	return nil
}

// MustRegister panics if Register returns an error. Convenience for init().
func (r *Registry) MustRegister(t Tool) {
	if err := r.Register(t); err != nil {
		panic(err)
	}
}

// Lookup returns the tool with the given name.
func (r *Registry) Lookup(name string) (Tool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tools[name]
	return t, ok
}

// All returns every registered tool, sorted by Name.
func (r *Registry) All() []Tool {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Categories returns the deduplicated, sorted set of Tool.Category values.
func (r *Registry) Categories() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[string]struct{}{}
	for _, t := range r.tools {
		if t.Category != "" {
			seen[t.Category] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// AsToolHandler adapts the Registry to the existing ToolHandler interface so
// it can be passed to Server.RegisterTools. Handler errors are formatted as
// tool-level errors (isError=true) per §3.3.
func (r *Registry) AsToolHandler() ToolHandler {
	return &registryHandler{r: r}
}

type registryHandler struct{ r *Registry }

func (h *registryHandler) ListTools() []ToolDef {
	tools := h.r.All()
	out := make([]ToolDef, 0, len(tools))
	for _, t := range tools {
		out = append(out, ToolDef{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	return out
}

func (h *registryHandler) Call(ctx context.Context, name string, args map[string]any) (any, bool) {
	t, ok := h.r.Lookup(name)
	if !ok {
		return map[string]any{
			"content": []map[string]any{{"type": "text", "text": "unknown tool: " + name}},
		}, true
	}
	result, err := t.Handler(ctx, args)
	if err != nil {
		return map[string]any{
			"content": []map[string]any{{"type": "text", "text": err.Error()}},
		}, true
	}
	return result, false
}
