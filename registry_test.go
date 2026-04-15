package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// okHandler returns (result, nil) for use in tests that don't care about the
// handler body.
func okHandler(result any) func(ctx context.Context, args map[string]any) (any, error) {
	return func(ctx context.Context, args map[string]any) (any, error) { return result, nil }
}

// errHandler returns (nil, err) for use in AsToolHandler error-path tests.
func errHandler(err error) func(ctx context.Context, args map[string]any) (any, error) {
	return func(ctx context.Context, args map[string]any) (any, error) { return nil, err }
}

func TestRegistry(t *testing.T) {
	t.Run("HappyPath", func(t *testing.T) {
		r := NewRegistry()
		if err := r.Register(Tool{Name: "beta", Handler: okHandler("b")}); err != nil {
			t.Fatalf("Register beta: %v", err)
		}
		if err := r.Register(Tool{Name: "alpha", Handler: okHandler("a")}); err != nil {
			t.Fatalf("Register alpha: %v", err)
		}
		if _, ok := r.Lookup("alpha"); !ok {
			t.Errorf("Lookup alpha missing")
		}
		if _, ok := r.Lookup("beta"); !ok {
			t.Errorf("Lookup beta missing")
		}
		all := r.All()
		if len(all) != 2 {
			t.Fatalf("All len: got %d, want 2", len(all))
		}
		if all[0].Name != "alpha" || all[1].Name != "beta" {
			t.Errorf("All sort: got %q/%q, want alpha/beta", all[0].Name, all[1].Name)
		}
	})

	t.Run("DuplicateName", func(t *testing.T) {
		r := NewRegistry()
		if err := r.Register(Tool{Name: "dup", Handler: okHandler(nil)}); err != nil {
			t.Fatalf("first Register: %v", err)
		}
		err := r.Register(Tool{Name: "dup", Handler: okHandler(nil)})
		if err == nil {
			t.Fatal("second Register returned nil, want error")
		}
		if !strings.Contains(err.Error(), "dup") {
			t.Errorf("error message %q does not mention duplicate name", err.Error())
		}
		if !strings.Contains(err.Error(), "already registered") {
			t.Errorf("error message %q does not say 'already registered'", err.Error())
		}
	})

	t.Run("MustRegisterPanic", func(t *testing.T) {
		r := NewRegistry()
		r.MustRegister(Tool{Name: "x", Handler: okHandler(nil)})
		defer func() {
			rec := recover()
			if rec == nil {
				t.Fatal("MustRegister on duplicate did not panic")
			}
			err, ok := rec.(error)
			if !ok {
				t.Fatalf("panic value is not error: %T %v", rec, rec)
			}
			if !strings.Contains(err.Error(), "already registered") {
				t.Errorf("panic error %q missing 'already registered'", err.Error())
			}
		}()
		r.MustRegister(Tool{Name: "x", Handler: okHandler(nil)})
	})

	t.Run("EmptyName", func(t *testing.T) {
		r := NewRegistry()
		err := r.Register(Tool{Name: "", Handler: okHandler(nil)})
		if err == nil {
			t.Fatal("expected error for empty name, got nil")
		}
		if !strings.Contains(err.Error(), "name") {
			t.Errorf("error %q does not mention 'name'", err.Error())
		}
	})

	t.Run("NilHandler", func(t *testing.T) {
		r := NewRegistry()
		err := r.Register(Tool{Name: "x", Handler: nil})
		if err == nil {
			t.Fatal("expected error for nil Handler, got nil")
		}
		if !strings.Contains(err.Error(), "Handler") && !strings.Contains(err.Error(), "handler") {
			t.Errorf("error %q does not mention Handler", err.Error())
		}
	})

	t.Run("CategoriesDedupSort", func(t *testing.T) {
		r := NewRegistry()
		r.MustRegister(Tool{Name: "t1", Category: "b", Handler: okHandler(nil)})
		r.MustRegister(Tool{Name: "t2", Category: "a", Handler: okHandler(nil)})
		r.MustRegister(Tool{Name: "t3", Category: "a", Handler: okHandler(nil)})
		r.MustRegister(Tool{Name: "t4", Category: "", Handler: okHandler(nil)})
		got := r.Categories()
		want := []string{"a", "b"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Categories: got %v, want %v", got, want)
		}
	})

	t.Run("RegistrationAfterStartGuard", func(t *testing.T) {
		r := NewRegistry()
		if err := r.Register(Tool{Name: "first", Handler: okHandler(nil)}); err != nil {
			t.Fatalf("first Register: %v", err)
		}
		r.markStarted()
		err := r.Register(Tool{Name: "second", Handler: okHandler(nil)})
		if err == nil {
			t.Fatal("Register after markStarted returned nil, want error")
		}
		if !strings.Contains(err.Error(), "started") {
			t.Errorf("error %q does not mention 'started'", err.Error())
		}

		defer func() {
			if rec := recover(); rec == nil {
				t.Fatal("MustRegister after start did not panic")
			}
		}()
		r.MustRegister(Tool{Name: "third", Handler: okHandler(nil)})
	})

	t.Run("AsToolHandlerSuccess", func(t *testing.T) {
		r := NewRegistry()
		want := map[string]any{"content": []map[string]any{{"type": "text", "text": "ok"}}}
		r.MustRegister(Tool{Name: "echo", Handler: okHandler(want)})
		h := r.AsToolHandler()
		got, isErr := h.Call(context.Background(), "echo", nil)
		if isErr {
			t.Fatalf("isError = true for success, want false")
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("result mismatch: got %v, want %v", got, want)
		}
	})

	t.Run("AsToolHandlerError", func(t *testing.T) {
		r := NewRegistry()
		r.MustRegister(Tool{Name: "boom", Handler: errHandler(errors.New("kaboom"))})
		h := r.AsToolHandler()
		got, isErr := h.Call(context.Background(), "boom", nil)
		if !isErr {
			t.Fatal("isError = false, want true")
		}
		want := map[string]any{"content": []map[string]any{{"type": "text", "text": "kaboom"}}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("error shape mismatch: got %#v, want %#v", got, want)
		}
	})

	t.Run("AsToolHandlerUnknownName", func(t *testing.T) {
		r := NewRegistry()
		h := r.AsToolHandler()
		got, isErr := h.Call(context.Background(), "nope", nil)
		if !isErr {
			t.Fatal("isError = false for unknown name, want true")
		}
		m, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("result not map: %T", got)
		}
		content, ok := m["content"].([]map[string]any)
		if !ok || len(content) != 1 {
			t.Fatalf("content shape wrong: %#v", m["content"])
		}
		text, _ := content[0]["text"].(string)
		if !strings.Contains(text, "nope") {
			t.Errorf("error text %q does not mention unknown name 'nope'", text)
		}
	})

	t.Run("ListToolsMatchesAll", func(t *testing.T) {
		r := NewRegistry()
		r.MustRegister(Tool{Name: "b", Description: "B", Handler: okHandler(nil)})
		r.MustRegister(Tool{Name: "a", Description: "A", Handler: okHandler(nil)})
		h := r.AsToolHandler()
		defs := h.ListTools()
		if len(defs) != 2 {
			t.Fatalf("ListTools len: got %d, want 2", len(defs))
		}
		if defs[0].Name != "a" || defs[1].Name != "b" {
			t.Errorf("ListTools order: got %q/%q, want a/b", defs[0].Name, defs[1].Name)
		}
		if defs[0].Description != "A" {
			t.Errorf("defs[0].Description: got %q want A", defs[0].Description)
		}
	})

	t.Run("ConcurrentRegisterLookup", func(t *testing.T) {
		r := NewRegistry()
		const n = 100
		var wg sync.WaitGroup
		wg.Add(n * 2)
		for i := 0; i < n; i++ {
			i := i
			go func() {
				defer wg.Done()
				// Ignore the error on the rare duplicate (i uniqueness
				// makes this impossible here, but keep the contract).
				_ = r.Register(Tool{
					Name:    fmt.Sprintf("tool-%03d", i),
					Handler: okHandler(i),
				})
			}()
			go func() {
				defer wg.Done()
				// Lookup may or may not find the tool depending on
				// goroutine interleaving; we only care that it does not
				// race or crash.
				_, _ = r.Lookup(fmt.Sprintf("tool-%03d", i))
			}()
		}
		wg.Wait()
		all := r.All()
		if len(all) != n {
			t.Fatalf("All len after concurrent Register: got %d, want %d", len(all), n)
		}
		// Assert stable-sort held under concurrent writes.
		for i := 1; i < len(all); i++ {
			if all[i-1].Name >= all[i].Name {
				t.Fatalf("All not sorted: %q before %q", all[i-1].Name, all[i].Name)
			}
		}
	})

	t.Run("StableSortDeterminism", func(t *testing.T) {
		names := []string{"zeta", "alpha", "mike", "charlie", "bravo", "yankee", "delta", "echo"}
		order1 := append([]string(nil), names...)
		order2 := append([]string(nil), names...)
		rng1 := rand.New(rand.NewSource(1))
		rng2 := rand.New(rand.NewSource(2))
		rng1.Shuffle(len(order1), func(i, j int) { order1[i], order1[j] = order1[j], order1[i] })
		rng2.Shuffle(len(order2), func(i, j int) { order2[i], order2[j] = order2[j], order2[i] })

		r1 := NewRegistry()
		for _, n := range order1 {
			r1.MustRegister(Tool{Name: n, Handler: okHandler(nil)})
		}
		r2 := NewRegistry()
		for _, n := range order2 {
			r2.MustRegister(Tool{Name: n, Handler: okHandler(nil)})
		}

		all1 := r1.All()
		all2 := r2.All()
		if len(all1) != len(all2) {
			t.Fatalf("size mismatch: %d vs %d", len(all1), len(all2))
		}
		for i := range all1 {
			if all1[i].Name != all2[i].Name {
				t.Fatalf("order diverges at %d: %q vs %q", i, all1[i].Name, all2[i].Name)
			}
		}
		// And the sequence is actually sorted.
		for i := 1; i < len(all1); i++ {
			if all1[i-1].Name >= all1[i].Name {
				t.Fatalf("All not sorted at %d: %q then %q", i, all1[i-1].Name, all1[i].Name)
			}
		}
	})

	t.Run("NoMutationOnError", func(t *testing.T) {
		// An error return from Register must not leave partial state.
		r := NewRegistry()
		r.MustRegister(Tool{Name: "keep", Handler: okHandler(nil)})
		_ = r.Register(Tool{Name: "", Handler: okHandler(nil)})
		_ = r.Register(Tool{Name: "nilh", Handler: nil})
		_ = r.Register(Tool{Name: "keep", Handler: okHandler(nil)})
		if len(r.All()) != 1 {
			t.Fatalf("registry size after errored Registers: got %d, want 1", len(r.All()))
		}
	})
}
