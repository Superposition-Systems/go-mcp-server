// Package config provides a SQLite-backed key-value store with a precedence
// chain (SQLite → credentials file → env) and write-through to an optional
// credentials file, plus auto-registered config tools. See §4.8 + §3.8.
package config

import (
	"sync"

	mcp "github.com/Superposition-Systems/go-mcp-server"
)

// Options configures a Store.
type Options struct {
	DBPath          string // SQLite path; required
	CredentialsFile string // optional write-through file
	EnvFallback     bool   // default true
}

// Store is the configuration key-value handle.
//
// Phase 0 minimal impl: in-memory map protected by a mutex; Session 4
// (track 2E) replaces the body with the real SQLite + file + env
// precedence chain, write-through, and env-backfill.
type Store struct {
	mu   sync.Mutex
	kv   map[string]string
	opts Options
}

// Open opens a Store at the configured DBPath.
//
// Phase 0: returns an empty in-memory store regardless of DBPath so
// dependent code compiles and basic round-tripping works in tests.
func Open(opts Options) (*Store, error) {
	return &Store{kv: map[string]string{}, opts: opts}, nil
}

// Get returns the value for key and whether it was found.
func (s *Store) Get(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.kv[key]
	return v, ok
}

// Set stores key=value.
func (s *Store) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kv[key] = value
	return nil
}

// Delete removes key if present.
func (s *Store) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.kv, key)
	return nil
}

// List returns a copy of every key/value pair.
func (s *Store) List() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.kv))
	for k, v := range s.kv {
		out[k] = v
	}
	return out
}

// RegisterTools registers config_get / config_set / config_list /
// config_delete on the given Registry.
//
// Phase 0: no-op. Session 4 (track 2E) registers the real tools.
func (s *Store) RegisterTools(r *mcp.Registry) error {
	_ = r
	return nil
}

// Close releases the backing store.
//
// Phase 0: no-op.
func (s *Store) Close() error { return nil }
