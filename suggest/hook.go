package suggest

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

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
	Kind      EventKind `json:"kind"`
	Tool      string    `json:"tool,omitempty"`
	Requested string    `json:"requested,omitempty"`
	Suggested string    `json:"suggested,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Hook consumes suggestion events. Must be safe for concurrent use and must
// not block the caller (the caller is on the request path).
type Hook func(Event)

// JSONLFile returns a Hook that appends each event as a single JSON line
// to path. The file and its parent directory are created on first write.
// Writes are serialised through an internal mutex so concurrent calls do
// not interleave. File-system errors are silently dropped after a one-shot
// log.Printf warning on the first failure — telemetry must never break
// request flow.
//
// If Event.Timestamp is zero at write time, time.Now() is stamped in.
func JSONLFile(path string) Hook {
	var (
		mu          sync.Mutex
		dirReady    bool
		warnOnce    sync.Once
	)
	warn := func(err error) {
		warnOnce.Do(func() {
			log.Printf("suggest.JSONLFile: %v (suppressing further errors)", err)
		})
	}
	return func(e Event) {
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now()
		}
		buf, err := json.Marshal(e)
		if err != nil {
			warn(err)
			return
		}
		buf = append(buf, '\n')

		mu.Lock()
		defer mu.Unlock()

		if !dirReady {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				warn(err)
				return
			}
			dirReady = true
		}

		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			warn(err)
			return
		}
		if _, err := f.Write(buf); err != nil {
			warn(err)
			_ = f.Close()
			return
		}
		if err := f.Close(); err != nil {
			warn(err)
		}
	}
}

// Multi returns a Hook that fans out to every h in hooks in order. Nil
// entries are skipped. A hook that panics is recovered (logged via
// log.Printf) so subsequent hooks still run.
func Multi(hooks ...Hook) Hook {
	return func(e Event) {
		for _, h := range hooks {
			if h == nil {
				continue
			}
			callOne(h, e)
		}
	}
}

// callOne invokes h with panic recovery.
func callOne(h Hook, e Event) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("suggest.Multi: hook panic: %v", rec)
		}
	}()
	h(e)
}
