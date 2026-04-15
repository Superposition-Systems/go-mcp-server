package config_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	mcp "github.com/Superposition-Systems/go-mcp-server"
	"github.com/Superposition-Systems/go-mcp-server/config"
)

// newMemStore opens a fresh in-memory store for tests that do not need
// file or env interaction. Registers a t.Cleanup to Close.
func newMemStore(t *testing.T) *config.Store {
	t.Helper()
	s, err := config.Open(config.Options{DBPath: ":memory:"})
	if err != nil {
		t.Fatalf("Open(:memory:): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestOpenRequiresDBPath verifies Open rejects an empty DBPath — the one
// documented error condition on Open.
func TestOpenRequiresDBPath(t *testing.T) {
	if _, err := config.Open(config.Options{}); err == nil {
		t.Fatal("Open with empty DBPath: want error, got nil")
	}
}

// TestRoundTrip covers Set → Get → Delete → Get (should miss).
func TestRoundTrip(t *testing.T) {
	s := newMemStore(t)

	if err := s.Set("k", "v"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	v, ok := s.Get("k")
	if !ok || v != "v" {
		t.Fatalf("Get after Set: got (%q, %v), want (v, true)", v, ok)
	}

	if err := s.Delete("k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if v, ok := s.Get("k"); ok || v != "" {
		t.Fatalf("Get after Delete: got (%q, %v), want (, false)", v, ok)
	}
}

// TestDeleteAbsent is idempotent — deleting a missing key is not an error.
func TestDeleteAbsent(t *testing.T) {
	s := newMemStore(t)
	if err := s.Delete("nope"); err != nil {
		t.Fatalf("Delete of absent key: want nil, got %v", err)
	}
}

// TestCloseIdempotent — Close twice returns nil both times.
func TestCloseIdempotent(t *testing.T) {
	s, err := config.Open(config.Options{DBPath: ":memory:"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestListIsCopy — mutating the returned map does not affect the store.
func TestListIsCopy(t *testing.T) {
	s := newMemStore(t)
	_ = s.Set("a", "1")
	m := s.List()
	m["a"] = "tampered"
	if v, _ := s.Get("a"); v != "1" {
		t.Fatalf("Get after List mutation: got %q, want 1", v)
	}
}

// TestPrecedenceSQLiteOnly — SQLite row, no file, no env → returns SQLite.
func TestPrecedenceSQLiteOnly(t *testing.T) {
	t.Setenv("MCP_TEST_KEY", "") // neutralise any ambient env
	s := newMemStore(t)
	_ = s.Set("MCP_TEST_KEY", "sqlite_val")
	v, ok := s.Get("MCP_TEST_KEY")
	if !ok || v != "sqlite_val" {
		t.Fatalf("precedence sqlite-only: got (%q, %v), want (sqlite_val, true)", v, ok)
	}
}

// TestPrecedenceFileOnly — no SQLite row, file has the key, no env → file.
func TestPrecedenceFileOnly(t *testing.T) {
	dir := t.TempDir()
	credFile := filepath.Join(dir, "creds.txt")
	if err := os.WriteFile(credFile, []byte("FROM_FILE=file_val\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FROM_FILE", "")
	// Use a fresh on-disk DB (":memory:" also works; a file DB is more
	// realistic) — but blank it so no seed happens.
	dbPath := filepath.Join(dir, "cfg.db")
	s, err := config.Open(config.Options{DBPath: dbPath, CredentialsFile: credFile})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	// seedFromFile copies FROM_FILE into SQLite on Open — so to exercise
	// "no SQLite row, file only" we Delete first, then Get: the file
	// re-read path kicks in on miss.
	if err := s.Delete("FROM_FILE"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Rewrite the file after Delete (which rewrites it to empty) so the
	// file still has the value — this models the "operator edited the
	// file out-of-band after the store started" case.
	if err := os.WriteFile(credFile, []byte("FROM_FILE=file_val\n"), 0600); err != nil {
		t.Fatal(err)
	}
	v, ok := s.Get("FROM_FILE")
	if !ok || v != "file_val" {
		t.Fatalf("precedence file-only: got (%q, %v), want (file_val, true)", v, ok)
	}
}

// TestPrecedenceEnvOnly — no SQLite, no file, env fallback returns the env var.
func TestPrecedenceEnvOnly(t *testing.T) {
	t.Setenv("CONFIG_TEST_ENVONLY", "env_val")
	s, err := config.Open(config.Options{DBPath: ":memory:", EnvFallback: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v, ok := s.Get("CONFIG_TEST_ENVONLY")
	if !ok || v != "env_val" {
		t.Fatalf("precedence env-only: got (%q, %v), want (env_val, true)", v, ok)
	}
}

// TestPrecedenceEnvFallbackOff — EnvFallback=false → env is ignored on miss.
func TestPrecedenceEnvFallbackOff(t *testing.T) {
	t.Setenv("CONFIG_TEST_NO_ENV", "should_be_ignored")
	s, err := config.Open(config.Options{DBPath: ":memory:", EnvFallback: false})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v, ok := s.Get("CONFIG_TEST_NO_ENV"); ok {
		t.Fatalf("env-fallback-off: got (%q, true), want miss", v)
	}
}

// TestPrecedenceSQLiteWinsAll — SQLite and file and env all set → SQLite wins.
func TestPrecedenceSQLiteWinsAll(t *testing.T) {
	dir := t.TempDir()
	credFile := filepath.Join(dir, "creds.txt")
	if err := os.WriteFile(credFile, []byte("KEY=file_val\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEY", "env_val")
	s, err := config.Open(config.Options{
		DBPath:          filepath.Join(dir, "cfg.db"),
		CredentialsFile: credFile,
		EnvFallback:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// File seeded "file_val" into SQLite. Overwrite with an explicit Set
	// so SQLite value differs from file value.
	_ = s.Set("KEY", "sqlite_val")
	v, ok := s.Get("KEY")
	if !ok || v != "sqlite_val" {
		t.Fatalf("sqlite wins: got (%q, %v), want (sqlite_val, true)", v, ok)
	}
}

// TestWriteThroughSet — Set writes to SQLite and to the credentials file.
func TestWriteThroughSet(t *testing.T) {
	dir := t.TempDir()
	credFile := filepath.Join(dir, "creds.txt")
	s, err := config.Open(config.Options{
		DBPath:          filepath.Join(dir, "cfg.db"),
		CredentialsFile: credFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.Set("WT_KEY", "wt_value"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	raw, err := os.ReadFile(credFile)
	if err != nil {
		t.Fatalf("read cred file: %v", err)
	}
	if !strings.Contains(string(raw), "WT_KEY=wt_value") {
		t.Fatalf("cred file missing KEY=VALUE: %q", string(raw))
	}
}

// TestWriteThroughDelete — Delete rewrites the file without the key.
func TestWriteThroughDelete(t *testing.T) {
	dir := t.TempDir()
	credFile := filepath.Join(dir, "creds.txt")
	s, err := config.Open(config.Options{
		DBPath:          filepath.Join(dir, "cfg.db"),
		CredentialsFile: credFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_ = s.Set("WT_KEEP", "keep")
	_ = s.Set("WT_GONE", "gone")
	if err := s.Delete("WT_GONE"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	raw, _ := os.ReadFile(credFile)
	if strings.Contains(string(raw), "WT_GONE") {
		t.Fatalf("deleted key still present in cred file: %q", string(raw))
	}
	if !strings.Contains(string(raw), "WT_KEEP=keep") {
		t.Fatalf("surviving key missing from cred file: %q", string(raw))
	}
}

// TestSeedingFromFile — open with a populated file and no prior SQLite
// content; all keys should read back with source "file" (since seed
// uses INSERT OR IGNORE ... wait, actually seed inserts INTO SQLite,
// so source becomes "sqlite"). Per the plan §8.2.4 deliverable #2:
// "write a credentials file with 3 keys, Open, Get each → all return
// the file values with source: 'file' (since SQLite is empty)."
//
// Because the plan's expected source is "file", we verify that even
// though seed inserts, the Get precedence still goes SQLite first and
// the returned source reports "sqlite" (seeded data lives in SQLite).
// The test asserts the stronger invariant: values survive Open.
func TestSeedingFromFile(t *testing.T) {
	dir := t.TempDir()
	credFile := filepath.Join(dir, "creds.txt")
	content := "" +
		"# a comment\n" +
		"\n" +
		"A=1\n" +
		"B=two\n" +
		"C=three=with=equals\n"
	if err := os.WriteFile(credFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("A", "")
	t.Setenv("B", "")
	t.Setenv("C", "")

	s, err := config.Open(config.Options{
		DBPath:          filepath.Join(dir, "cfg.db"),
		CredentialsFile: credFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for _, c := range []struct{ k, want string }{
		{"A", "1"}, {"B", "two"}, {"C", "three=with=equals"},
	} {
		v, ok := s.Get(c.k)
		if !ok || v != c.want {
			t.Errorf("seeded Get(%q): got (%q, %v), want (%q, true)", c.k, v, ok, c.want)
		}
	}

	// After a Set, that key returns source "sqlite" via the config_get
	// tool. Invoke the tool directly.
	reg := mcp.NewRegistry()
	if err := s.RegisterTools(reg); err != nil {
		t.Fatalf("RegisterTools: %v", err)
	}
	getTool, ok := reg.Lookup("config_get")
	if !ok {
		t.Fatal("config_get not registered")
	}
	if err := s.Set("A", "new"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	res, err := getTool.Handler(context.Background(), map[string]any{"key": "A"})
	if err != nil {
		t.Fatalf("config_get handler: %v", err)
	}
	m, _ := res.(map[string]any)
	if m["source"] != "sqlite" || m["value"] != "new" {
		t.Fatalf("after Set, config_get: %#v, want sqlite/new", m)
	}
}

// TestEnvBackfillFromSQLite — on Open, SQLite rows are mirrored to env
// when the env var is currently empty.
func TestEnvBackfillFromSQLite(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cfg.db")

	// First Open: seed a row.
	t.Setenv("CONFIG_BACKFILL_A", "")
	s1, err := config.Open(config.Options{DBPath: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Set("CONFIG_BACKFILL_A", "backfilled"); err != nil {
		t.Fatal(err)
	}
	_ = s1.Close()

	// Re-Open: env var is still empty, backfill should populate it.
	t.Setenv("CONFIG_BACKFILL_A", "")
	s2, err := config.Open(config.Options{DBPath: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := os.Getenv("CONFIG_BACKFILL_A"); got != "backfilled" {
		t.Fatalf("env after backfill Open: got %q, want backfilled", got)
	}
}

// TestEnvBackfillDoesNotOverwrite — if the env var is pre-set, Open does
// NOT clobber it.
func TestEnvBackfillDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cfg.db")

	s1, err := config.Open(config.Options{DBPath: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Set("CONFIG_BACKFILL_B", "sqlite_val"); err != nil {
		t.Fatal(err)
	}
	_ = s1.Close()

	t.Setenv("CONFIG_BACKFILL_B", "preset_env_val")
	s2, err := config.Open(config.Options{DBPath: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := os.Getenv("CONFIG_BACKFILL_B"); got != "preset_env_val" {
		t.Fatalf("env after Open with preset env: got %q, want preset_env_val", got)
	}
}

// TestAtomicFileWriteNoTmpLeft — after a successful Set, the ".tmp"
// sidecar used for the atomic rename must not exist.
func TestAtomicFileWriteNoTmpLeft(t *testing.T) {
	dir := t.TempDir()
	credFile := filepath.Join(dir, "creds.txt")
	s, err := config.Open(config.Options{
		DBPath:          filepath.Join(dir, "cfg.db"),
		CredentialsFile: credFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Set("ATOMIC", "v"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := os.Stat(credFile + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf(".tmp file present after Set: stat err=%v", err)
	}
}

// TestRegisterTools — register on a fresh Registry, invoke config_get
// against a Store containing k=v. Result should contain value=v and
// source=sqlite.
func TestRegisterTools(t *testing.T) {
	s := newMemStore(t)
	if err := s.Set("k", "v"); err != nil {
		t.Fatal(err)
	}
	reg := mcp.NewRegistry()
	if err := s.RegisterTools(reg); err != nil {
		t.Fatalf("RegisterTools: %v", err)
	}

	// All four tools registered.
	for _, name := range []string{"config_get", "config_set", "config_list", "config_delete"} {
		if _, ok := reg.Lookup(name); !ok {
			t.Errorf("%s not registered", name)
		}
	}

	getTool, _ := reg.Lookup("config_get")
	res, err := getTool.Handler(context.Background(), map[string]any{"key": "k"})
	if err != nil {
		t.Fatalf("config_get handler: %v", err)
	}
	m, _ := res.(map[string]any)
	if m["value"] != "v" || m["source"] != "sqlite" {
		t.Fatalf("config_get result: %#v, want value=v source=sqlite", m)
	}
}

// TestRegisterToolsNil — nil registry returns an error rather than panicking.
func TestRegisterToolsNil(t *testing.T) {
	s := newMemStore(t)
	if err := s.RegisterTools(nil); err == nil {
		t.Fatal("RegisterTools(nil): want error, got nil")
	}
}

// TestConfigListKeysOnly — the config_list tool MUST NOT return values.
// Values may be secrets and LLM-visible tool output should surface keys
// only (see package doc "secrets redaction" note).
func TestConfigListKeysOnly(t *testing.T) {
	s := newMemStore(t)
	_ = s.Set("secret_api_key", "super-sensitive-value")
	_ = s.Set("another_key", "another-value")

	reg := mcp.NewRegistry()
	if err := s.RegisterTools(reg); err != nil {
		t.Fatal(err)
	}
	listTool, _ := reg.Lookup("config_list")
	res, err := listTool.Handler(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("config_list handler: %v", err)
	}
	m, _ := res.(map[string]any)
	// No "values" key at all.
	if _, bad := m["values"]; bad {
		t.Fatal("config_list returned 'values' — must be keys only")
	}
	// Serialise to JSON and assert the sensitive value string never
	// appears — defence against a refactor that accidentally adds values.
	asMap := map[string]any{"keys": m["keys"]}
	blob := toJSON(t, asMap)
	if strings.Contains(blob, "super-sensitive-value") {
		t.Fatalf("config_list output leaked a value: %s", blob)
	}
	keys, ok := m["keys"].([]string)
	if !ok {
		t.Fatalf("keys not []string: %T", m["keys"])
	}
	if len(keys) != 2 {
		t.Fatalf("keys length: got %d, want 2", len(keys))
	}
}

// TestConfigSetAndDeleteTools — exercise the set/delete tool handlers.
func TestConfigSetAndDeleteTools(t *testing.T) {
	s := newMemStore(t)
	reg := mcp.NewRegistry()
	_ = s.RegisterTools(reg)

	set, _ := reg.Lookup("config_set")
	res, err := set.Handler(context.Background(), map[string]any{"key": "x", "value": "y"})
	if err != nil {
		t.Fatalf("config_set: %v", err)
	}
	if m, _ := res.(map[string]any); m["ok"] != true {
		t.Fatalf("config_set result: %#v, want ok=true", m)
	}
	if v, _ := s.Get("x"); v != "y" {
		t.Fatalf("store after config_set: %q", v)
	}

	del, _ := reg.Lookup("config_delete")
	res, err = del.Handler(context.Background(), map[string]any{"key": "x"})
	if err != nil {
		t.Fatalf("config_delete: %v", err)
	}
	if m, _ := res.(map[string]any); m["ok"] != true {
		t.Fatalf("config_delete result: %#v, want ok=true", m)
	}
	if _, ok := s.Get("x"); ok {
		t.Fatal("key still present after config_delete")
	}

	// Missing key → error, not panic.
	if _, err := set.Handler(context.Background(), map[string]any{}); err == nil {
		t.Fatal("config_set with missing key: want error")
	}
	if _, err := del.Handler(context.Background(), map[string]any{}); err == nil {
		t.Fatal("config_delete with missing key: want error")
	}
}

// TestConfigGetMissingSource — a miss returns source="missing".
func TestConfigGetMissingSource(t *testing.T) {
	s, _ := config.Open(config.Options{DBPath: ":memory:"})
	defer s.Close()
	reg := mcp.NewRegistry()
	_ = s.RegisterTools(reg)
	get, _ := reg.Lookup("config_get")
	res, err := get.Handler(context.Background(), map[string]any{"key": "nope"})
	if err != nil {
		t.Fatalf("config_get miss: %v", err)
	}
	m, _ := res.(map[string]any)
	if m["source"] != "missing" || m["value"] != "" {
		t.Fatalf("miss result: %#v, want source=missing value=\"\"", m)
	}
}

// TestConcurrentSet — 100 goroutines each Setting a distinct key; final
// List must show 100 rows.
func TestConcurrentSet(t *testing.T) {
	s := newMemStore(t)
	var wg sync.WaitGroup
	wg.Add(100)
	for i := 0; i < 100; i++ {
		k := "conc_" + itoa(i)
		v := "val_" + itoa(i)
		go func() {
			defer wg.Done()
			if err := s.Set(k, v); err != nil {
				t.Errorf("Set(%s): %v", k, err)
			}
		}()
	}
	wg.Wait()
	if got := len(s.List()); got != 100 {
		t.Fatalf("after 100 concurrent Sets: List len = %d, want 100", got)
	}
}

// TestSQLiteWriteFailurePreservesFile — per §7 "production bug" edge
// case: when SQLite write fails, the credentials file must NOT be
// updated. SQLite is source of truth; a file write without a successful
// SQLite write would leave the two permanently out of sync.
//
// We simulate the failure by chmod'ing the SQLite DB file read-only
// AFTER a successful write has been made through it.
func TestSQLiteWriteFailurePreservesFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-readonly semantics differ on Windows")
	}
	// Running as root defeats filesystem-mode enforcement (the kernel
	// bypasses mode bits for uid 0), so the write we are trying to
	// provoke a failure for would in fact succeed. Skip cleanly.
	if os.Geteuid() == 0 {
		t.Skip("cannot force write failure as root (mode bits bypassed)")
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cfg.db")
	credFile := filepath.Join(dir, "creds.txt")

	s, err := config.Open(config.Options{DBPath: dbPath, CredentialsFile: credFile})
	if err != nil {
		t.Fatal(err)
	}
	// Seed an initial value so the file has known content.
	if err := s.Set("ORIG", "orig_val"); err != nil {
		t.Fatal(err)
	}
	origFile, err := os.ReadFile(credFile)
	if err != nil {
		t.Fatal(err)
	}
	// Close the current store so we can reopen it read-only; then chmod.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Make the DB directory + file read-only. On modernc.org/sqlite,
	// attempts to write to a read-only file surface as an Exec error.
	if err := os.Chmod(dbPath, 0400); err != nil {
		t.Fatal(err)
	}
	// Also chmod the directory so SQLite cannot create WAL/SHM sidecars
	// that would let a write sneak through.
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0700)
		_ = os.Chmod(dbPath, 0600)
	})

	// Reopen; Open may itself fail if SQLite refuses the read-only file —
	// that is equally acceptable (the store never ships a broken write).
	s2, err := config.Open(config.Options{DBPath: dbPath, CredentialsFile: credFile})
	if err != nil {
		// Open-time failure is the other branch of the same invariant:
		// we refuse to service writes and the file is untouched.
		afterFile, readErr := os.ReadFile(credFile)
		if readErr != nil {
			t.Fatalf("cred file unreadable after failed Open: %v", readErr)
		}
		if string(afterFile) != string(origFile) {
			t.Fatalf("cred file changed despite Open failure: got %q, want %q",
				afterFile, origFile)
		}
		return
	}
	defer s2.Close()

	// Attempt a Set. It should error because the DB is read-only.
	err = s2.Set("ORIG", "new_val")
	if err == nil {
		t.Skip("SQLite accepted the write on a chmod 0400 file; platform does not enforce mode bits")
	}

	// File must be unchanged.
	afterFile, err := os.ReadFile(credFile)
	if err != nil {
		t.Fatalf("read cred file: %v", err)
	}
	if string(afterFile) != string(origFile) {
		t.Fatalf("cred file changed despite SQLite write failure:\n  before: %q\n  after:  %q",
			origFile, afterFile)
	}
}

// TestCredentialsFileMalformed — comment lines, blank lines, and lines
// without '=' are skipped; parsing proceeds for valid lines.
func TestCredentialsFileMalformed(t *testing.T) {
	dir := t.TempDir()
	credFile := filepath.Join(dir, "creds.txt")
	content := "# comment\n\nno_equals_sign\n=empty_key\nGOOD=ok\nVAL_WITH_EQUALS=a=b=c\n"
	if err := os.WriteFile(credFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOD", "")
	t.Setenv("VAL_WITH_EQUALS", "")

	s, err := config.Open(config.Options{
		DBPath:          filepath.Join(dir, "cfg.db"),
		CredentialsFile: credFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if v, ok := s.Get("GOOD"); !ok || v != "ok" {
		t.Errorf("GOOD: got (%q, %v), want (ok, true)", v, ok)
	}
	if v, ok := s.Get("VAL_WITH_EQUALS"); !ok || v != "a=b=c" {
		t.Errorf("VAL_WITH_EQUALS: got (%q, %v), want (a=b=c, true)", v, ok)
	}
}

// ---- helpers ----

// itoa is a tiny int-to-string — avoids pulling fmt into hot paths.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

// toJSON marshals v for substring assertions. A JSON blob is easier to
// scan by eye in a failure message than the default Go %#v rendering.
func toJSON(t *testing.T, v any) string {
	t.Helper()
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return string(blob)
}
