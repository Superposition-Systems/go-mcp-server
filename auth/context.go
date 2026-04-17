package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// Context key types are unexported to prevent collisions across packages.
type tokenHashKeyType struct{}
type elevatedKeyType struct{}
type authPathKeyType struct{}

var (
	tokenHashKey = tokenHashKeyType{}
	elevatedKey  = elevatedKeyType{}
	authPathKey  = authPathKeyType{}
)

// AuthPath labels which branch of BearerMiddleware accepted the token
// on this request. Exposed so downstream middleware / handlers can
// reason about the auth source without having to rerun validation.
type AuthPath string

const (
	AuthPathCustomValidator AuthPath = "custom-validator"
	AuthPathStaticBearer    AuthPath = "static-bearer"
	AuthPathOAuth           AuthPath = "oauth"
)

// TokenHash computes a hex-encoded SHA-256 hash of a bearer token, suitable
// for use as a session identifier without exposing the raw secret.
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// WithTokenHash attaches a token hash to the context. Called by
// BearerMiddleware on successful authentication.
func WithTokenHash(ctx context.Context, hash string) context.Context {
	return context.WithValue(ctx, tokenHashKey, hash)
}

// GetTokenHash returns the token hash stored on the context by
// BearerMiddleware, or "" if the request was not authenticated (or the
// middleware was bypassed).
func GetTokenHash(ctx context.Context) string {
	if v, ok := ctx.Value(tokenHashKey).(string); ok {
		return v
	}
	return ""
}

// WithAuthPath stamps the context with the branch that accepted the
// request. Called by BearerMiddleware on the success path.
func WithAuthPath(ctx context.Context, p AuthPath) context.Context {
	return context.WithValue(ctx, authPathKey, p)
}

// GetAuthPath returns the AuthPath recorded by BearerMiddleware, or
// "" if the request did not pass through a middleware that stamped it.
func GetAuthPath(ctx context.Context) AuthPath {
	if v, ok := ctx.Value(authPathKey).(AuthPath); ok {
		return v
	}
	return ""
}

// WithElevated marks the context as currently holding an active elevation
// grant (or as being in bootstrap mode when no password is configured).
// Called by the elevation-aware middleware wired up by WithElevation.
func WithElevated(ctx context.Context, elevated bool) context.Context {
	return context.WithValue(ctx, elevatedKey, elevated)
}

// IsElevated returns true if the context was tagged by elevation middleware
// as representing an elevated session — either by an active grant or by
// bootstrap mode (no password configured). Returns false when elevation is
// not wired up, so callers combining this with a static-token scope check
// get the safe default.
func IsElevated(ctx context.Context) bool {
	if v, ok := ctx.Value(elevatedKey).(bool); ok {
		return v
	}
	return false
}
