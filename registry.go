package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
)

// Tool is a self-describing unit of functionality registered with a Registry.
// See docs/plans/v0.8.0-middleware-and-registry.md §4.1.
//
// Name is required and must be unique within a Registry. Handler is required.
// InputSchema is opaque here — the JSON-schema validator middleware (§4.6) and
// the DefaultSkillBuilder (§4.4) parse its top-level properties/required
// shape; no other component peeks inside. Category, Tags, and ParamAliases
// are optional metadata consumed by downstream tracks (mux grouping, param
// alias rewrite middleware, etc.).
type Tool struct {
	Name         string
	Description  string
	InputSchema  json.RawMessage
	Category     string
	Tags         []string
	ParamAliases map[string]string
	Annotations  *ToolAnnotations
	Handler      func(ctx context.Context, args map[string]any) (any, error)
}

// Registry is an ergonomic alternative to implementing ToolHandler directly.
// A Registry implements ToolHandler via AsToolHandler; pass the result to
// Server.RegisterTools.
//
// Registry is safe for concurrent use by multiple goroutines. Register calls
// after the owning Server has begun serving return an error (see
// markStarted); this prevents races between live tool dispatch and
// registration mutations.
type Registry struct {
	mu      sync.Mutex
	tools   map[string]Tool
	started atomic.Bool
	// parent, when non-nil, is another Registry that markStarted should
	// also seal. Set by NewMux so sealing the mux-facing registry (the
	// one bound to the Server) cascades to the underlying registry whose
	// tools are captured in mux handler closures. Unexported — only
	// library-internal constructors set this.
	parent *Registry
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{tools: map[string]Tool{}}
}

// Register adds a tool to the registry.
//
// Register returns a non-nil error in any of the following cases:
//   - t.Name is empty
//   - t.Handler is nil
//   - a tool with the same Name is already registered
//   - the registry has been sealed via markStarted (i.e. the owning Server
//     has begun serving).
//
// The registry is not mutated when an error is returned.
func (r *Registry) Register(t Tool) error {
	if t.Name == "" {
		return fmt.Errorf("tool name must not be empty")
	}
	if t.Handler == nil {
		return fmt.Errorf("tool %q has nil Handler", t.Name)
	}
	if r.started.Load() {
		return fmt.Errorf("tool %q: cannot register after server has started", t.Name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Re-check after acquiring the lock so a concurrent markStarted that
	// fires between the atomic load above and the lock acquisition is
	// honoured. markStarted does not take the lock, but the started flag
	// may have flipped while we were blocked on mu — recheck and bail.
	if r.started.Load() {
		return fmt.Errorf("tool %q: cannot register after server has started", t.Name)
	}
	if _, dup := r.tools[t.Name]; dup {
		return fmt.Errorf("tool %q already registered", t.Name)
	}
	r.tools[t.Name] = t
	return nil
}

// MustRegister calls Register and panics if it returns an error. It is
// intended for init() blocks and other program-startup code paths where a
// registration failure is a programmer error, not a runtime condition.
func (r *Registry) MustRegister(t Tool) {
	if err := r.Register(t); err != nil {
		panic(err)
	}
}

// Lookup returns the tool with the given name and true if present, or the
// zero Tool and false if not.
func (r *Registry) Lookup(name string) (Tool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tools[name]
	return t, ok
}

// All returns every registered tool, stable-sorted by Name. The returned
// slice is freshly allocated on every call; callers may mutate it freely.
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

// Categories returns the deduplicated, sorted set of non-empty Tool.Category
// values across every registered tool. Tools without a category are skipped.
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
// it can be passed to Server.RegisterTools. This preserves backward
// compatibility with consumers that already consume ToolHandler directly.
//
// The adapter maps a registered handler's return value into the MCP
// (any, isError bool) shape per §3.3:
//   - (result, nil)        → (result, false)
//   - (_,      err != nil) → ({"content":[{"type":"text","text":err.Error()}]}, true)
//   - name not registered  → ({"content":[{"type":"text","text":"unknown tool: "+name}]}, true)
//
// Note: AsToolHandler deliberately does not expose the error-category
// distinction from §3.3's ToolCallFunc — that lives at the middleware chain
// layer (Session 2 / track 1B). This adapter keeps the legacy two-value
// contract and folds library-level handler errors into isError:true.
func (r *Registry) AsToolHandler() ToolHandler {
	return &registryHandler{r: r}
}

// markStarted seals the registry against further Register / MustRegister
// calls. It is intended to be called by Server.ListenAndServe exactly once
// when the server transitions to the serving state, so that tool dispatch
// during request handling never races with registration.
//
// When r has a parent (set by NewMux), markStarted walks the chain so
// sealing a mux-facing registry also seals the underlying registry whose
// tools the mux dispatches to. Without this, a caller holding the
// underlying pointer could Register new tools after serving began —
// violating the §2 "no runtime tool registration" non-goal.
//
// This method is unexported on purpose: only the Server (same package) may
// flip the flag, and only as part of its start-up transition.
func (r *Registry) markStarted() {
	for cur := r; cur != nil; cur = cur.parent {
		cur.started.Store(true)
	}
}

// registryHandler is the internal ToolHandler adapter returned by
// Registry.AsToolHandler.
type registryHandler struct{ r *Registry }

// ListTools returns the registered tools in stable-sort order as a slice of
// ToolDef values suitable for the MCP tools/list response.
func (h *registryHandler) ListTools() []ToolDef {
	tools := h.r.All()
	out := make([]ToolDef, 0, len(tools))
	for _, t := range tools {
		out = append(out, ToolDef{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
			Annotations: t.Annotations,
		})
	}
	return out
}

// Call dispatches the named tool via its registered Handler. An unknown
// name and a non-nil handler error are both folded into an MCP error
// content envelope with isError=true. See AsToolHandler's doc comment for
// the mapping rationale.
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
