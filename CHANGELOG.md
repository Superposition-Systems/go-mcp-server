# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[v0.4.0]: https://github.com/Superposition-Systems/go-mcp-server/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/Superposition-Systems/go-mcp-server/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/Superposition-Systems/go-mcp-server/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/Superposition-Systems/go-mcp-server/releases/tag/v0.1.0
