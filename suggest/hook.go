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

	// EventEnvelopeAlias fires when the mux's <prefix>_execute dispatcher
	// received the inner payload under an alias key ("params", "arguments",
	// "input") rather than the canonical "args". The dispatch succeeds; the
	// event exists so operators can see which clients/proxies drift from
	// spec and decide whether to push a fix upstream.
	EventEnvelopeAlias EventKind = "envelope_alias"
)

// Event is fired once per unknown-name or alias-collision occurrence.
//
// For EventUnknownTool, Tool is empty.
// For EventUnknownParam and EventAliasCollision, Tool is the parent tool.
// For EventAliasCollision, Requested is the dropped alias and Suggested is
// the canonical that won (never empty in this case).
// For EventEnvelopeAlias, Tool is the underlying tool the envelope targeted
// (from the outer "tool" field), Requested is the alias the client used,
// and Suggested is always "args".
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
// The file descriptor is opened lazily on the first event and held for
// the process lifetime. A per-event open+close would serialise the
// request pipeline through a pair of syscalls under the mutex, giving
// an adversarial unknown-tool flood a trivial DoS amplification vector.
// On a transient open failure the hook keeps trying on subsequent events
// (one line of warn-log is still suppressed by warnOnce).
//
// If Event.Timestamp is zero at write time, time.Now() is stamped in.
func JSONLFile(path string) Hook {
	var (
		mu       sync.Mutex
		f        *os.File
		warnOnce sync.Once
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

		if f == nil {
			// 0700/0600 matches the auth/config/diag convention: telemetry
			// events are not secret but may include raw unknown-tool /
			// unknown-param names that reflect caller-supplied strings, and
			// uniform tight perms avoid "one of these sinks is the leak"
			// diagnostic surprises later.
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				warn(err)
				return
			}
			opened, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				warn(err)
				return
			}
			f = opened
		}

		if _, err := f.Write(buf); err != nil {
			warn(err)
			// Drop the handle so a transient failure (e.g. file rotated
			// or volume remounted) does not poison every future write.
			_ = f.Close()
			f = nil
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
