package suggest

import "time"

// EventKind discriminates the three event types. See §4.11.
type EventKind string

const (
	// EventUnknownTool fires when the mux dispatch sees a tool name not in
	// the registry.
	EventUnknownTool EventKind = "tool"

	// EventUnknownParam fires when the validator or alias middleware sees a
	// property name not declared in the tool's schema.
	EventUnknownParam EventKind = "param"

	// EventAliasCollision fires when the alias middleware sees both the
	// alias and the canonical name in the same payload; the alias is dropped
	// and this event records the drop.
	EventAliasCollision EventKind = "alias_collision"
)

// Event is fired once per unknown-name or alias-collision occurrence.
//
// For EventUnknownTool, Tool is empty.
// For EventUnknownParam and EventAliasCollision, Tool is the parent tool.
// For EventAliasCollision, Requested is the dropped alias and Suggested is
// the canonical that won (never empty in this case).
type Event struct {
	Kind      EventKind
	Tool      string
	Requested string
	Suggested string
	Timestamp time.Time
}

// Hook consumes suggestion events. Must be safe for concurrent use and must
// not block the caller (the caller is on the request path).
type Hook func(Event)

// JSONLFile returns a Hook that appends each event as a single JSON line
// to path. The file and its parent directory are created on first write.
// Writes are serialised through an internal mutex so concurrent calls do
// not interleave. File-system errors are silently dropped after a one-shot
// log.Printf warning on the first failure.
//
// Phase 0 minimal impl: returns a no-op Hook so consumers can wire it in.
// Session 3 (track 2A) replaces the body with the real JSONL appender.
func JSONLFile(path string) Hook {
	_ = path
	return func(Event) {}
}

// Multi returns a Hook that fans out to every h in hooks in order. A hook
// that panics is recovered; subsequent hooks still run.
//
// Phase 0: simple fan-out without panic recovery. Track 2A adds recovery.
func Multi(hooks ...Hook) Hook {
	return func(e Event) {
		for _, h := range hooks {
			if h != nil {
				h(e)
			}
		}
	}
}
