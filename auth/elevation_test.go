package auth

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// GrantStore
// -----------------------------------------------------------------------------

func TestGrantStore_GrantAndHas(t *testing.T) {
	g := NewGrantStore()
	g.Grant("abc", time.Minute)
	if !g.Has("abc") {
		t.Fatal("expected grant to be active")
	}
	if g.Has("other") {
		t.Fatal("unknown key should not be active")
	}
}

func TestGrantStore_Expiry(t *testing.T) {
	g := NewGrantStore()
	g.Grant("abc", 10*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if g.Has("abc") {
		t.Fatal("grant should have expired")
	}
	if g.ActiveCount() != 0 {
		t.Fatal("expired entries should be pruned")
	}
}

func TestGrantStore_RevokeAll(t *testing.T) {
	g := NewGrantStore()
	g.Grant("a", time.Minute)
	g.Grant("b", time.Minute)
	if g.ActiveCount() != 2 {
		t.Fatalf("expected 2 active grants, got %d", g.ActiveCount())
	}
	g.RevokeAll()
	if g.ActiveCount() != 0 {
		t.Fatalf("expected 0 after RevokeAll, got %d", g.ActiveCount())
	}
}

func TestGrantStore_ExpiresAt(t *testing.T) {
	g := NewGrantStore()
	g.Grant("abc", time.Minute)
	exp, ok := g.ExpiresAt("abc")
	if !ok {
		t.Fatal("expected grant")
	}
	if !exp.After(time.Now()) {
		t.Fatal("expiry should be in the future")
	}
	if _, ok := g.ExpiresAt("missing"); ok {
		t.Fatal("missing key should return false")
	}
}

// -----------------------------------------------------------------------------
// PasswordStore — bootstrap, set-first-time, rotation
// -----------------------------------------------------------------------------

func newTempPasswordStore(t *testing.T, envOverride string) *PasswordStore {
	t.Helper()
	dir := t.TempDir()
	ps, err := NewPasswordStore(filepath.Join(dir, "elevation.db"), envOverride)
	if err != nil {
		t.Fatalf("NewPasswordStore: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	return ps
}

func TestPasswordStore_BootstrapUnset(t *testing.T) {
	ps := newTempPasswordStore(t, "")
	if ps.IsSet() {
		t.Fatal("fresh store should not be set")
	}
	if ps.Status() != nil {
		t.Fatal("Status should be nil in bootstrap mode")
	}
	if ps.Verify("anything") {
		t.Fatal("Verify should fail with no password set")
	}
}

func TestPasswordStore_SetInitial(t *testing.T) {
	ps := newTempPasswordStore(t, "")
	if err := ps.SetInitial("correct-horse-battery-staple"); err != nil {
		t.Fatalf("SetInitial: %v", err)
	}
	if !ps.IsSet() {
		t.Fatal("should be set after SetInitial")
	}
	if !ps.Verify("correct-horse-battery-staple") {
		t.Fatal("Verify should succeed with matching password")
	}
	if ps.Verify("wrong") {
		t.Fatal("Verify should fail with wrong password")
	}
	status := ps.Status()
	if status == nil {
		t.Fatal("Status should be non-nil once set")
	}
	if status.PasswordSetAt.IsZero() || status.LastRotatedAt.IsZero() {
		t.Fatal("timestamps should be populated")
	}
}

func TestPasswordStore_SetInitialEmpty(t *testing.T) {
	ps := newTempPasswordStore(t, "")
	if err := ps.SetInitial(""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("expected ErrEmptyPassword, got %v", err)
	}
}

func TestPasswordStore_SetInitialTwiceFails(t *testing.T) {
	ps := newTempPasswordStore(t, "")
	if err := ps.SetInitial("first"); err != nil {
		t.Fatal(err)
	}
	if err := ps.SetInitial("second"); !errors.Is(err, ErrPasswordAlreadySet) {
		t.Fatalf("expected ErrPasswordAlreadySet, got %v", err)
	}
}

func TestPasswordStore_Rotate(t *testing.T) {
	ps := newTempPasswordStore(t, "")
	if err := ps.SetInitial("old"); err != nil {
		t.Fatal(err)
	}
	firstStatus := ps.Status()

	// Ensure rotation timestamp advances.
	time.Sleep(1100 * time.Millisecond)

	if err := ps.Rotate("wrong", "new"); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("expected ErrIncorrectPassword, got %v", err)
	}
	if err := ps.Rotate("old", "new"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if ps.Verify("old") {
		t.Fatal("old password should no longer verify")
	}
	if !ps.Verify("new") {
		t.Fatal("new password should verify")
	}

	status := ps.Status()
	if !status.LastRotatedAt.After(firstStatus.LastRotatedAt) {
		t.Fatalf("expected last_rotated_at to advance: %v !> %v",
			status.LastRotatedAt, firstStatus.LastRotatedAt)
	}
	if !status.PasswordSetAt.Equal(firstStatus.PasswordSetAt) {
		t.Fatal("password_set_at must not change on rotation")
	}
}

func TestPasswordStore_RotateBeforeSetFails(t *testing.T) {
	ps := newTempPasswordStore(t, "")
	if err := ps.Rotate("any", "new"); !errors.Is(err, ErrPasswordNotSet) {
		t.Fatalf("expected ErrPasswordNotSet, got %v", err)
	}
}

func TestPasswordStore_EnvOverride(t *testing.T) {
	ps := newTempPasswordStore(t, "env-secret")
	if !ps.IsSet() {
		t.Fatal("env override should satisfy IsSet")
	}
	if !ps.Verify("env-secret") {
		t.Fatal("env override should verify")
	}
	if ps.Verify("other") {
		t.Fatal("env override should reject mismatches")
	}
	if err := ps.SetInitial("anything"); !errors.Is(err, ErrPasswordAlreadySet) {
		t.Fatalf("SetInitial under env override should fail with ErrPasswordAlreadySet, got %v", err)
	}
	if err := ps.Rotate("env-secret", "new"); !errors.Is(err, ErrPasswordAlreadySet) {
		t.Fatalf("Rotate under env override should fail with ErrPasswordAlreadySet, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Elevation composition — bootstrap, grant, rotation-revokes
// -----------------------------------------------------------------------------

func newElevation(t *testing.T, envOverride string) *Elevation {
	t.Helper()
	ps := newTempPasswordStore(t, envOverride)
	return NewElevation(ps, NewGrantStore(), 100*time.Millisecond)
}

func ctxWithToken(token string) context.Context {
	return WithTokenHash(context.Background(), TokenHash(token))
}

func TestElevation_BootstrapMode(t *testing.T) {
	e := newElevation(t, "")
	if !e.IsBootstrap() {
		t.Fatal("should be in bootstrap mode with no password")
	}
	ctx := ctxWithToken("user-A")
	if !e.HasCurrentSession(ctx) {
		t.Fatal("bootstrap mode should elevate every authenticated session")
	}
	if _, err := e.Elevate(ctx, "anything"); !errors.Is(err, ErrBootstrapAlreadyElevated) {
		t.Fatalf("Elevate in bootstrap mode should return ErrBootstrapAlreadyElevated, got %v", err)
	}
}

func TestElevation_GrantLifecycle(t *testing.T) {
	e := newElevation(t, "")
	if err := e.PasswordStore().SetInitial("pw"); err != nil {
		t.Fatal(err)
	}

	ctxA := ctxWithToken("token-A")
	ctxB := ctxWithToken("token-B")

	// Before elevating, neither session is elevated.
	if e.HasCurrentSession(ctxA) || e.HasCurrentSession(ctxB) {
		t.Fatal("sessions should not be elevated before Elevate call")
	}

	if _, err := e.Elevate(ctxA, "wrong"); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("wrong password should return ErrIncorrectPassword, got %v", err)
	}
	if e.HasCurrentSession(ctxA) {
		t.Fatal("failed elevate must not grant")
	}

	if _, err := e.Elevate(ctxA, "pw"); err != nil {
		t.Fatalf("Elevate: %v", err)
	}
	if !e.HasCurrentSession(ctxA) {
		t.Fatal("session A should be elevated")
	}
	if e.HasCurrentSession(ctxB) {
		t.Fatal("session B must not be elevated — elevation is per-token")
	}
}

func TestElevation_RotationRevokesGrants(t *testing.T) {
	e := newElevation(t, "")
	if err := e.PasswordStore().SetInitial("pw"); err != nil {
		t.Fatal(err)
	}
	ctxA := ctxWithToken("token-A")
	if _, err := e.Elevate(ctxA, "pw"); err != nil {
		t.Fatal(err)
	}
	if !e.HasCurrentSession(ctxA) {
		t.Fatal("should be elevated before rotation")
	}

	// Rotation revokes grants — verified by the tool layer, but exercised
	// here directly against the composed store.
	if err := e.PasswordStore().Rotate("pw", "new-pw"); err != nil {
		t.Fatal(err)
	}
	e.GrantStore().RevokeAll()

	if e.HasCurrentSession(ctxA) {
		t.Fatal("rotation + RevokeAll must drop existing grants")
	}
}

func TestElevation_GrantExpiry(t *testing.T) {
	e := newElevation(t, "")
	if err := e.PasswordStore().SetInitial("pw"); err != nil {
		t.Fatal(err)
	}
	ctxA := ctxWithToken("token-A")
	if _, err := e.Elevate(ctxA, "pw"); err != nil {
		t.Fatal(err)
	}
	// TTL is 100ms in test stores.
	time.Sleep(200 * time.Millisecond)
	if e.HasCurrentSession(ctxA) {
		t.Fatal("grant should have expired")
	}
}

// -----------------------------------------------------------------------------
// TokenHash / context plumbing
// -----------------------------------------------------------------------------

func TestTokenHash_DeterministicAndOpaque(t *testing.T) {
	a := TokenHash("hello")
	b := TokenHash("hello")
	c := TokenHash("world")
	if a != b {
		t.Fatal("TokenHash should be deterministic")
	}
	if a == c {
		t.Fatal("different inputs must produce different hashes")
	}
	if len(a) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(a))
	}
}

func TestContext_WithTokenHash(t *testing.T) {
	ctx := WithTokenHash(context.Background(), "abc")
	if got := GetTokenHash(ctx); got != "abc" {
		t.Fatalf("expected 'abc', got %q", got)
	}
	if got := GetTokenHash(context.Background()); got != "" {
		t.Fatalf("empty ctx should return empty string, got %q", got)
	}
}

func TestContext_WithElevated(t *testing.T) {
	ctx := WithElevated(context.Background(), true)
	if !IsElevated(ctx) {
		t.Fatal("expected IsElevated true")
	}
	if IsElevated(context.Background()) {
		t.Fatal("unset ctx should be false")
	}
}
