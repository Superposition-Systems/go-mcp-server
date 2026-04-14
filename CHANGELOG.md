# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.6.0] — 2026-04-14

### Added
- **Elevation (step-up auth)**: New `WithElevation(ElevationConfig)` option enables a session-scoped elevation feature. Registers two tools automatically (`<prefix>_elevate` and `<prefix>_set_elevation_password`) and exposes `Server.Elevation()` for apps to fold into their own health / write-gate logic.
- **Bootstrap mode**: When no password is configured, every authenticated session is treated as elevated until the first `set_elevation_password` call closes the window. Intended for first-install convenience. Strict-mode deployments can set `EnvPasswordVar` to bypass bootstrap entirely.
- **`auth.PasswordStore`**: SQLite-backed hashed-password store using stdlib `crypto/pbkdf2` (SHA-256, 600k iterations). Tracks `set_at` and `last_rotated_at`. Rotation requires the current password.
- **`auth.GrantStore`**: In-memory TTL-keyed "this key is currently elevated" primitive, reusable for any time-bounded permission feature (not just elevation).
- **`auth.Elevation`**: Composes the two stores with a configurable TTL. Provides `HasCurrentSession(ctx)`, `Elevate(ctx, password)`, `IsBootstrap()`.
- **Token hash on context**: `BearerMiddleware` now stashes `auth.TokenHash(token)` on the request context on every successful auth. Retrievable via `auth.GetTokenHash(ctx)` as a stable session identifier that never exposes the raw token.
- **`auth.WithElevated` / `auth.IsElevated`**: Forward-compatible context helpers for middleware-tagged elevation state.

### Changed
- `BearerMiddleware` now calls `WithTokenHash` on success paths — non-breaking, adds data to ctx without affecting existing handlers.

## [v0.5.0] — 2026-04-13

### Added
- **Scope enforcement**: `VerifyAccessToken` now checks the token's `scope` against a required scope. `BearerMiddleware` passes the server's configured scope, so OAuth tokens with mismatched scopes are rejected.
- **Resource caps**: Auth requests capped at 10,000 rows, access tokens and refresh tokens each capped at 50,000 rows. Prevents disk exhaustion from unauthenticated or compromised callers.
- **Rate limiter IP cap**: Rate limiter map bounded at 100,000 distinct IPs; empty entries pruned on access. Prevents memory exhaustion from IP-spray attacks.
- **Body limits on OAuth endpoints**: `POST /authorize` and `POST /token` now enforce 64 KB max request body via `http.MaxBytesReader`.
- **Redirect URI validation at consent**: `GET /authorize` validates `redirect_uri` against client's registered URIs before rendering the consent page (RFC 6749 §3.1.2.4).
- **Redirect URI verification at token exchange**: `POST /token` verifies `redirect_uri` matches the original authorization request (RFC 6749 §4.1.3), preventing authorization code interception.

### Fixed
- **Missing mutex in `VerifyAccessToken`**: Race condition on lazy-delete of expired tokens. Now acquires `s.mu.Lock()` like all other store methods.
- **Non-atomic token consumption**: `ConsumeAuthCode`, `ConsumeRefreshToken`, and `GetAuthRequest` SELECT+DELETE pairs were not in database transactions. Replaced raw `db.Exec("BEGIN IMMEDIATE")` (which was non-functional with `database/sql` connection pool) with proper `db.Begin()` / `*sql.Tx`.
- **SQLite connection safety**: Set `db.SetMaxOpenConns(1)` to match SQLite's single-writer model and ensure transactions are not split across pool connections.
- **Nil dereference in `BearerMiddleware`**: Library consumers passing `nil` as the OAuth store would panic when falling through to `VerifyAccessToken`. Now guarded with a nil check.
- **`baseURLFromConfig` localhost restriction**: Dev-only fallback now rejects non-localhost `Host` headers entirely (returns `http://localhost` with a warning log) instead of trusting attacker-controlled headers.
- **Reflected method name in SSE error**: Attacker-controlled `req.Method` (up to 10 MB) was echoed verbatim in error responses. Now truncated to 64 characters.
- **`GetAuthRequest` expired-path error swallowed**: Delete error on the expiry branch was silently ignored. Now handled within a transaction.
- **Example app default credential**: Removed hardcoded `"test-token"` fallback. Example now requires `BEARER_TOKEN` or `AUTH_PIN` to be set.

### Breaking Changes
- `BearerMiddleware` signature changed: added `requiredScope string` parameter after `store`. Callers must pass a scope string (or `""` to skip enforcement).
- `VerifyAccessToken` signature changed: added `requiredScope string` parameter. Callers must pass a scope string (or `""` to skip enforcement).

## [v0.4.0] — 2026-04-13

### Added
- `WithExternalURL` option — sets a canonical public URL for OAuth metadata, preventing Host header injection. Required for production.
- `README.md` with full API documentation, architecture diagram, OAuth flow, security details, and deployment guide.
- Request body size limits: 10 MB on MCP endpoint, 1 MB on `/register`.
- HTTP server timeouts: `ReadHeaderTimeout` (10s), `ReadTimeout` (30s), `WriteTimeout` (request timeout + 10s), `IdleTimeout` (120s).
- Redirect URI validation at `/register` — rejects non-HTTPS URIs (except `http://localhost`, `127.0.0.1`, `::1`).

### Fixed
- Registration rate limiter was a no-op — `RecordFailure` was never called, so `IsRateLimited` always returned false. Now counts every registration attempt.
- Auth code expiry checked after delete in `ConsumeAuthCode` — now checks expiry before deleting the row.
- `baseURL()` trusted `X-Forwarded-Proto` and `r.Host` unconditionally, allowing OAuth metadata poisoning. Replaced with `baseURLFromConfig()` that uses `ExternalURL` when set and validates the protocol fallback.

### Breaking Changes
- `/register` now rejects redirect URIs that don't use `https://` (except localhost variants for development). Existing clients already registered with `http://` URIs are unaffected, but re-registration will fail.
- Registration rate limiter now enforces the 10-per-hour-per-IP limit. Previously unlimited.

## [v0.3.0] — 2026-04-13

### Added
- `WithTokenValidator(func(string) bool)` option for custom token validation (e.g. multiple tokens, scoped auth, external auth services). Checked before static bearer token and OAuth.
- `WithMiddleware(func(http.Handler) http.Handler)` option for outer middleware that wraps the entire handler chain including bearer auth. Enables tagging request context with scope metadata before validation.

## [v0.2.0] — 2026-04-13

### Added
- Test suite: 35 tests covering JSON-RPC transport (13), BearerMiddleware (6), SafeEqual (5), OAuthStore lifecycle (3), RateLimiter (4), deploy generators (4).
- Input validation for deploy template generators to prevent injection.
- `WithOAuthDBPath` option for configurable SQLite database path.

### Fixed
- **Auth context tampering**: OAuth auth request params now stored server-side instead of in browser form fields.
- **SQL injection**: Scope string was concatenated into DDL; now validated with regex.
- **PKCE bypass**: `code_challenge` now mandatory at both `/authorize` and `/token`.
- **HTTP status bugs**: `WriteHeader` called after body write on 406/415 responses.
- **Auth code replay**: All `db.Exec` errors now checked in auth store (prevents auth code replay, token rotation bypass, maxClients bypass).
- **Redirect URI bypass**: Rejected when client has empty `redirect_uris`.
- **Rate limit spoofing**: Rate limiting now uses `r.RemoteAddr` instead of spoofable `X-Forwarded-For`.
- **SSE compatibility**: Replaced `http.TimeoutHandler` with `context.WithTimeout`.
- **Route registration panic**: Wrapped in `sync.Once` to prevent panic on restart.
- **Refresh token ordering**: `ConsumeRefreshToken` now checks expiry before delete.
- **Env var side effects**: Moved env var reads from `ListenAndServe()` to `New()`.
- **Marshal failures**: `marshalResult` now sets `isError=true` and produces valid JSON on failure.
- **Health check leak**: `RunHealthCheck` now closes response body.
- Traefik priority collision between routers.
- Default Go version updated to 1.24.

## [v0.1.0] — 2026-04-13

### Added
- Initial release — extracted from claude-log-archive into standalone library.
- JSON-RPC 2.0 transport over HTTP with SSE responses.
- OAuth 2.0 with PIN-based consent flow (RFC 8414, RFC 9728, RFC 7591).
- Dual-mode bearer middleware (static token + OAuth).
- `deploy` package: Dockerfile and Traefik label generators.
- API-first pattern: mount REST routes on `Mux()`, wrap with `ToolHandler`.
- Health check endpoint and `RunHealthCheck` for distroless containers.
- Graceful shutdown with configurable drain window.
- Pure-Go SQLite via modernc.org/sqlite (CGO-free, distroless compatible).

[v0.6.0]: https://github.com/Superposition-Systems/go-mcp-server/compare/v0.5.0...v0.6.0
[v0.5.0]: https://github.com/Superposition-Systems/go-mcp-server/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/Superposition-Systems/go-mcp-server/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/Superposition-Systems/go-mcp-server/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/Superposition-Systems/go-mcp-server/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/Superposition-Systems/go-mcp-server/releases/tag/v0.1.0
