package suggest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	var lines []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return lines
}

func TestJSONLFile_AppendsLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	h := JSONLFile(path)
	h(Event{Kind: EventUnknownTool, Requested: "jiraFoo"})
	h(Event{Kind: EventUnknownParam, Tool: "jiraGetIssue", Requested: "isue", Suggested: "issueKey"})
	h(Event{Kind: EventAliasCollision, Tool: "jiraGetIssue", Requested: "key", Suggested: "issueKey"})

	lines := readLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3; contents=%v", len(lines), lines)
	}
	var got []Event
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %d unmarshal: %v (%q)", i, err, line)
		}
		got = append(got, e)
	}
	if got[0].Kind != EventUnknownTool || got[0].Requested != "jiraFoo" {
		t.Errorf("line 0 = %+v", got[0])
	}
	if got[1].Kind != EventUnknownParam || got[1].Tool != "jiraGetIssue" {
		t.Errorf("line 1 = %+v", got[1])
	}
	if got[2].Kind != EventAliasCollision || got[2].Suggested != "issueKey" {
		t.Errorf("line 2 = %+v", got[2])
	}
}

func TestJSONLFile_AutoCreatesParentDir(t *testing.T) {
	root := t.TempDir()
	// Nested path: root/a/b/c/events.jsonl — none of a,b,c exist yet.
	path := filepath.Join(root, "a", "b", "c", "events.jsonl")
	h := JSONLFile(path)
	h(Event{Kind: EventUnknownTool, Requested: "x"})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected file at %s, got error %v", path, err)
	}
	if info.Size() == 0 {
		t.Errorf("file exists but is empty")
	}
}

func TestJSONLFile_ConcurrentWritesDoNotInterleave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	h := JSONLFile(path)

	const goroutines = 50
	const perG = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	kinds := []EventKind{EventUnknownTool, EventUnknownParam, EventAliasCollision}
	for g := 0; g < goroutines; g++ {
		go func(gi int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				h(Event{
					Kind:      kinds[(gi+i)%3],
					Tool:      "tool",
					Requested: "r",
					Suggested: "s",
				})
			}
		}(g)
	}
	wg.Wait()

	lines := readLines(t, path)
	if len(lines) != goroutines*perG {
		t.Fatalf("got %d lines, want %d", len(lines), goroutines*perG)
	}
	counts := map[EventKind]int{}
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %d not valid JSON: %v (%q)", i, err, line)
		}
		counts[e.Kind]++
	}
	total := counts[EventUnknownTool] + counts[EventUnknownParam] + counts[EventAliasCollision]
	if total != goroutines*perG {
		t.Errorf("sum of kinds = %d, want %d (%+v)", total, goroutines*perG, counts)
	}
}

func TestJSONLFile_ReadOnlyFSSilent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod read-only does not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	root := t.TempDir()
	subdir := filepath.Join(root, "locked")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Make the subdir non-writable so the file cannot be created.
	if err := os.Chmod(subdir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(subdir, 0o755) // restore for TempDir cleanup

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

	path := filepath.Join(subdir, "events.jsonl")
	h := JSONLFile(path)

	// Many invocations — the warning must still only appear once.
	for i := 0; i < 10; i++ {
		// Must not panic or block.
		h(Event{Kind: EventUnknownTool, Requested: "x"})
	}

	out := buf.String()
	warnCount := strings.Count(out, "suggest.JSONLFile:")
	if warnCount != 1 {
		t.Errorf("warning emitted %d times, want 1. Output:\n%s", warnCount, out)
	}
	if !strings.Contains(out, "suppressing further errors") {
		t.Errorf("expected 'suppressing further errors' marker in log; got:\n%s", out)
	}
}

func TestJSONLFile_StampsZeroTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	h := JSONLFile(path)

	before := time.Now()
	h(Event{Kind: EventUnknownTool, Requested: "x"}) // Timestamp is zero
	after := time.Now()

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	var e Event
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.Timestamp.IsZero() {
		t.Fatalf("timestamp is zero, want populated")
	}
	// Allow a second of slack either side.
	if e.Timestamp.Before(before.Add(-time.Second)) || e.Timestamp.After(after.Add(time.Second)) {
		t.Errorf("timestamp %v outside expected window [%v, %v]", e.Timestamp, before, after)
	}
}

func TestJSONLFile_PreservesCallerTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	h := JSONLFile(path)

	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	h(Event{Kind: EventUnknownTool, Requested: "x", Timestamp: fixed})

	lines := readLines(t, path)
	var e Event
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !e.Timestamp.Equal(fixed) {
		t.Errorf("timestamp = %v, want %v", e.Timestamp, fixed)
	}
}

func TestMulti_FanOut(t *testing.T) {
	var order []int
	var mu sync.Mutex
	mk := func(id int) Hook {
		return func(Event) {
			mu.Lock()
			order = append(order, id)
			mu.Unlock()
		}
	}
	h := Multi(mk(1), mk(2), mk(3))
	h(Event{Kind: EventUnknownTool})

	if len(order) != 3 {
		t.Fatalf("got %d calls, want 3", len(order))
	}
	for i, id := range []int{1, 2, 3} {
		if order[i] != id {
			t.Errorf("order[%d] = %d, want %d", i, order[i], id)
		}
	}
}

func TestMulti_PanicIsolation(t *testing.T) {
	// Silence the log.Printf("suggest.Multi: hook panic: ...").
	oldOut := log.Writer()
	log.SetOutput(&bytes.Buffer{})
	defer log.SetOutput(oldOut)

	var aCalls, cCalls int32
	a := func(Event) { atomic.AddInt32(&aCalls, 1) }
	b := func(Event) { panic("boom") }
	c := func(Event) { atomic.AddInt32(&cCalls, 1) }

	h := Multi(a, b, c)
	// Must not propagate the panic.
	h(Event{Kind: EventUnknownTool})

	if atomic.LoadInt32(&aCalls) != 1 {
		t.Errorf("hook A called %d times, want 1", aCalls)
	}
	if atomic.LoadInt32(&cCalls) != 1 {
		t.Errorf("hook C called %d times, want 1 (panic isolation broken)", cCalls)
	}
}

func TestMulti_NilHookSkipped(t *testing.T) {
	var calls int32
	rec := func(Event) { atomic.AddInt32(&calls, 1) }
	h := Multi(nil, rec, nil)
	// Must not panic on nil.
	h(Event{Kind: EventUnknownTool})
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("recorder called %d times, want 1", calls)
	}
}

func TestMulti_EmptyHooks(t *testing.T) {
	h := Multi()
	// Should not panic or do anything.
	h(Event{Kind: EventUnknownTool})
}

func TestMulti_LogsPanic(t *testing.T) {
	var buf bytes.Buffer
	oldOut := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(oldOut)
		log.SetFlags(oldFlags)
	}()

	h := Multi(func(Event) { panic("kaboom") })
	h(Event{Kind: EventUnknownTool})

	out := buf.String()
	if !strings.Contains(out, "suggest.Multi: hook panic") {
		t.Errorf("log did not contain panic marker; got %q", out)
	}
	if !strings.Contains(out, "kaboom") {
		t.Errorf("log did not contain panic value; got %q", out)
	}
}
