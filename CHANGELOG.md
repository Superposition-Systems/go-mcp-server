# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.7.5] — 2026-04-14

Hotfix surfaced by the first real post-v0.7.4 deploy of vps-mcp:
`WithAllowedOrigins` was rejecting the library's own PIN consent form
submission with `403 {"error":"origin not allowed"}`, blocking every
new OAuth authorization end-to-end.

### Fixed
- **`WithAllowedOrigins` now implicitly trusts the server's own
  ExternalURL origin.** The PIN consent page at `/authorize` is served
  from ExternalURL and POSTs back to the same endpoint; the browser
  therefore carries `Origin: <ExternalURL>`. When the consumer passed
  `WithAllowedOrigins("https://claude.ai")` (the expected third-party
  browser caller) without also listing their own URL, the library
  rejected the form's own submission. Server startup now extracts the
  origin from ExternalURL and injects it into the effective allowlist
  before handing it to `OriginAllowlistMiddleware`. A same-origin POST
  cannot be a DNS-rebinding attack — the browser can only be on the
  server's origin if the user already trusts it — so this is a safe
  default, not a security relaxation. The public `WithAllowedOrigins`
  semantics remain focused on *third-party* browser callers, which is
  the mental model consumers reach for first.

### Tests
- `TestSelfOriginFromExternalURL` covers origin extraction: trailing
  slash stripping, non-standard ports preserved, path/query discarded,
  localhost dev shape accepted, malformed input returns empty.

### Migration
No API change. Consumers currently adding their own URL to
`WithAllowedOrigins` (the vps-mcp workaround) can revert that line —
the dedup check ensures it's a no-op either way.

## [v0.7.4] — 2026-04-14

Fifth-pass audit, portfolio-wide scope. Treated this library as the
shared auth surface for every public-facing MCP server in the
Superposition Systems portfolio (Atlassian, GitHub, Slack, VPS,
Voxhub, Traxos, md2pdf, Claude Logs, Doc-Crawler, YouDoYoutube), so
severity was weighted accordingly.

One HIGH finding, three MEDIUM, two LOW applied. One LOW deferred
(tool-handler `client_id` plumbing — adds unused API surface until a
consumer actually needs per-tenant partitioning).

### Breaking (for invalid configs)
- **`ListenAndServe` now refuses to start** if `AUTH_PIN` is shorter than 6 characters. With the current 5-per-15-minute rate limit, a 4-digit numeric PIN falls in days from a single IP. Unset PIN is still allowed (static-bearer-only mode). PINs of 6–7 chars log a warning banner. (M-1)
- **`ListenAndServe` now refuses to start** if `ExternalURL` is set to a non-`https://` URL, unless the host is `localhost`/`127.0.0.1`/`::1`. Closes the footgun of a typo'd or copy-pasted `http://` production URL silently producing spec-violating discovery metadata. (M-3)

### Added
- **`POST /revoke` (RFC 7009)** — authenticated token revocation for access and refresh tokens. Client authenticates via `client_secret_post`; presented token is removed from the store on success. Returns 200 on both known and unknown tokens (RFC-mandated, prevents probing). Returns 503 on store failure rather than a silent 200, so operators know a revocation did not take effect. Advertised in OAuth discovery as `revocation_endpoint`. Covered by four tests including a cross-client safety test proving a DCR'd client cannot revoke another client's tokens. (M-2)
- **Consent page now displays client identity.** The registered `client_name` and the `redirect_uri` host are rendered on the PIN consent page (both `html.EscapeString`'d). Without this, a DCR-registered client with an attacker-controlled redirect URI was visually indistinguishable from a legitimate one — the operator had no signal they were handing the PIN to the wrong party. The redirect host is the *validated* registered value, not raw query input. (H-1)

### Fixed
- **`RateLimiter.IsRateLimited` fails closed at map saturation.** Previously, when the 100k-IP tracker hit its cap, `RecordFailure` silently no-op'd and novel IPs returned "not limited" — an attacker with a large IP pool could bypass rate limiting entirely by cycling fresh addresses. The limiter now treats untracked IPs at saturation as rate-limited, turning the DoS-on-the-limiter into a bounded, logged global lockout. Tracked IPs within their per-IP budget are unaffected, minimizing legitimate-user impact during an attack. (L-3)
- **OAuth SQLite DB file permissions** — parent directory is now chmod'd to `0700` and the DB file to `0600` after `createTables` (SQLite creates the file lazily on first write). WAL/SHM sidecars are chmodded best-effort. Bind-mount / volume-copy scenarios no longer leak metadata (client_ids, issuance timestamps) to other UIDs. Secrets remain SHA-256 hashed at rest, so the blast radius was limited before this fix. (L-2)
- **Default Go version in generated Dockerfiles** bumped from `1.24` to `1.25` to match the `go` directive in this module's `go.mod`. Previously, a consumer who ran `GenerateDockerfile` with no explicit version got a Dockerfile that couldn't build the library, pushing operators to drop version pinning (`FROM golang:alpine`) and lose reproducibility across the portfolio. (M-4)

### Tests
- `TestBearerMiddlewareFailsClosedOnStoreUnreachable` — seeds a valid OAuth token, closes the DB mid-request, asserts 401 and that the inner handler is not reached. Locks in the "fail-closed on store failure" property that the whole portfolio inherits.
- `TestRevokeAccessToken`, `TestRevokeRejectsBadClientAuth`, `TestRevokeUnknownTokenReturns200`, `TestRevokeCannotTouchOtherClientsTokens` — full coverage of the new `/revoke` endpoint including the cross-client safety invariant.
- `TestRateLimiterFailsClosedAtSaturation` — encodes the IP-cycling attack and asserts the fail-closed behavior at map cap.

### Audit artifact
- `SECURITY_AUDIT_2026-04-14.md` — full fifth-pass findings document, including the "clean" enumeration of every question the substrate already answers correctly (constant-time compares, PKCE-mandatory, hashed-at-rest, parameterized SQL, auth-before-parse, etc.) and the executable fail-closed proof.

## [v0.7.3] — 2026-04-14

Fourth-pass audit. Small, focused round — no critical bugs, mostly
hardening cleanup. Several headline "critical" agent findings turned
out to be false positives (audit agents misreading intentional
single-use credential deletion as "regression") and were rejected.

### Fixed
- **`clientIP` now canonicalizes trusted-proxy header values through `net.ParseIP`.** Previously an attacker behind a trusted proxy could send `X-Forwarded-For: anything_here` (any string) and the raw value became a rate-limit key, letting them spray unlimited distinct buckets and defeat per-IP limiting. XFF and X-Real-IP values are now parsed, port-stripped if present, and rejected if not a valid IP. Untrusted or unparseable entries fall back to `RemoteAddr`. (R1)
- **`pkceVerify` adds an explicit length guard after the verifier hash.** Previously, `subtle.ConstantTimeCompare` was called with `computed` (always 43 bytes) vs `codeChallenge` (capped at 128 bytes); an unequal-length input would short-circuit instantly, violating the claimed constant-time property even if not exploitable. Verifier-side timing remains uniform because the hash runs unconditionally before the check. (R2)
- **`verifyPassword` refuses to compare against a stored hash shorter than `pbkdf2KeyLen`.** Defense-in-depth against a corrupted or zero-length DB row: `pbkdf2.Key(..., 0)` returns `[]byte{}` and `subtle.ConstantTimeCompare([]byte{}, []byte{})` returns 1 (equal), which would accept any password. No current code path produces this state; the guard is preventative. (R3)
- **`elevationTools.ListTools` now uses the precomputed `userNames` map** set by `wrapToolsWithElevation`, falling back to a local rebuild only when the struct is instantiated directly (tests). Prior code rebuilt the map on every `ListTools` call, contradicting the intent of the v0.7.1 precompute fix. (R4)
- **`ErrBootstrapAlreadyElevated` is now a single exported sentinel.** Prior code had both an unexported `errBootstrapAlreadyElevated` and an exported `ErrBootstrapAlreadyElevated` pointing at the same value — a maintenance hazard where a reassignment could silently break `errors.Is`. (R6)
- **`dummyClientSecretHash` is now generated at package-init via `RandomHex(32)`** instead of being the all-zeros constant. Prevents a hypothetical compiler from recognizing that SHA-256 output is never all-zero and folding the dummy compare to constant-false. (R7)

### Tests
- `TestRegLimiterReturns429AtHTTPLayer` and `TestAuthorizeLimiterReturns429AtHTTPLayer` exercise the rate-limit primitives through their HTTP handlers — previously only the `RateLimiter` struct itself was tested, not the wiring. (R5)
- `TestClientIPRejectsInvalidXForwardedFor` covers the XFF validation path end-to-end: garbage falls back to RemoteAddr, `ip:port` gets canonicalized, multi-entry skips unparseable, untrusted proxy ignores XFF.

### Rejected audit findings (for the record)
- "ConsumeAuthCode / ConsumeRefreshToken delete expired credentials before checking expiry — regression of v0.4.0 fix." This is intentional: single-use credentials that reach this code path have been *presented*, and must be burned whether valid or expired to prevent replay. The v0.4.0 fix corrected a different bug (a delete-error was being swallowed).
- "Client-registered `scope` with newline bypasses validation." Not reachable — the client's registered `scope` field is echoed on registration but never consulted at authorize time; only `h.config.Scope` gates subsequent issuance.

## [v0.7.2] — 2026-04-14

Third-pass audit follow-up. No critical vulnerabilities; a mix of
real hardening, operator-visibility improvements, and
documentation-vs-implementation cleanup.

### Changed — behavior
- **OAuth discovery returns HTTP 500** when `WithExternalURL` is not set and the request Host isn't localhost, instead of silently advertising `http://localhost/authorize`. Clients now get a clear error; operators see a concrete log line. (A2)
- **`VerifyClientSecret` miss-path dummy compare** now targets a distinct 64-char dummy hash rather than comparing the presented hash to itself. Prevents a clever compiler from folding self-compares to trivially-true and defeating the timing equalization. (A1)
- **Startup warning banners** for two high-impact misconfigurations: OAuth mounted with empty PIN, and `ExternalURL` unset. Neither refuses to start (both have legitimate local-dev / static-bearer-only modes). (A3)
- **`RateLimiter.PruneAll()`** is now called every 5 min from the cleanup goroutine for all four limiters (PIN, Reg, Authorize, Elevation). Prevents the 100k-IP cap from sticking at capacity under sustained traffic, which would silently allow new attackers through. (A4)
- **`OAuthStore.Cleanup` uses batched `DELETE ... LIMIT 1000`** releasing `s.mu` between batches. Prior behavior could stall the auth path for seconds under high row counts. Added indexes on `expires_at` / `created_at` columns so the per-batch delete stays fast. (A5)
- **Cleanup goroutine wrapped in panic recovery** so a SQLite driver panic cannot kill the server process. (A6)

### Fixed — docstrings
- `VerifyClientSecret` comment no longer overstates the timing guarantee — documents the small remaining DB-SELECT gap. (A7)
- `pkceVerify` comment correctly describes that one input is the raw verifier, not a pre-computed digest. (A9)
- `ConsumeAuthCode` godoc documents `(nil, err)` on miss/expiry, not `(nil, nil)`. Callers who check only the pointer would misbehave. (A10)
- `_elevate` tool description stops calling itself a "no-op" in bootstrap mode (it returns a structured success payload, which LLM clients may otherwise skip). (A8)

### Documentation
- README rate-limit table adds `GET /authorize` (60/hr) and per-session elevation limiter rows, plus the 100k-IP cap and `WithTrustedProxyCIDRs` expectation. (A11)
- README `ExternalURL` section updated to describe the new 500-on-non-localhost behavior. (A2 docs)
- README "secret comparisons" section corrected — not all are `SafeEqual`, several use `subtle.ConstantTimeCompare` directly on fixed-length digests (which is correct). (A12)

### Tests
- `TestDiscoveryRefusesWithoutExternalURLForNonLocalhost` covers the three metadata-serving branches.
- `TestRateLimiterPruneAll` covers the new background-prune path.

## [v0.7.1] — 2026-04-14

Second-pass audit follow-up: fixes stragglers found after the v0.7.0
hardening landed. All changes are backwards-compatible except the
`elevationTools` struct layout (internal only).

### Fixed
- **`parseBearer` silently stripped whitespace in the token position** — `Bearer  token` (double space) and `Bearer\ttoken` now fail instead of being quietly normalized. RFC 6750 §2.1 mandates exactly one SP. (H1)
- **`VerifyClientSecret` timing oracle on unknown `client_id`** — the unknown-client branch bypassed the SHA-256 hash entirely, letting an attacker enumerate valid client IDs via microsecond-scale timing. Both branches now hash unconditionally. (H2)
- **Shutdown goroutine leaked on non-signal `ListenAndServe` exit** (e.g. bind failure). Switched to `signal.NotifyContext` and a done-channel so the goroutine always terminates. (H3)
- **`req.ID` and `req.Params` were unbounded** — a JSON-RPC request with an enormous `id` was re-echoed in every response. `id` is now validated to be string/number/null, strings capped at 256 bytes, and `params` is capped at 1 MB of raw JSON. (H4)
- **`RegisterClient` leaked SQLite error details** in `error_description`. Now logs server-side and returns a generic message. (M3)
- **`validateRedirectURI` accepted a bare `?` suffix and `userinfo`** (credentials in URLs end up in browser history / server logs). Both are now rejected. (M4)
- **`state` and `code_challenge` had no length cap** — 10,000-row auth-request store × unbounded TEXT fields enabled disk DoS. Now 512 bytes and 128 bytes respectively. (M5)
- **Dead `if e == nil` guard** inside `Elevation.Middleware()` closure removed; docstring explains why the method is deliberately nil-unsafe. (M1)
- **`elevationTools.Call` probed `e.inner.ListTools()` on every dispatch** — O(n) and TOCTOU-sensitive if `ListTools` is non-deterministic. User tool names are now precomputed once at wrap time. (M2)
- **`sanitizeChallenge`** now caps its output at 200 bytes as defense-in-depth for future callers passing user-controlled descriptions. (L2)

### Documentation
- `PasswordStore.Verify` docstring warns that the row-absent branch short-circuits PBKDF2; all callers must front with `IsSet()`. (L5)
- `Elevation.Middleware` docstring documents the snapshot semantics and max-revocation-latency (= request timeout) for in-flight tool calls. (L6)
- `PasswordStore` type doc explains env-vs-DB coexistence (env wins cleanly while set; stored password is preserved and re-activated when env is removed). (L7)
- `WithOAuthDBPath` docstring notes the distroless-container pitfall on the `/data/oauth.db` default. (L3)
- `example/main.go`: replaced literal `my-secret` in curl snippets with `YOUR_TOKEN_HERE` to prevent copy-paste credential leaks. (L4)

### Tests
- New `TestParseBearerRejectsMalformed` covers case-insensitive scheme match, rejection of double-space / tab / trailing newline / internal space.
- New `TestVerifyClientSecretConstantTime` smoke-tests unknown / wrong / correct cases.
- New `TestValidateRedirectURIRejectsDangerousForms` covers bare `?`, fragments, userinfo, wrong scheme.

## [v0.7.0] — 2026-04-14

Security hardening round following a multi-agent audit of the OAuth flow,
transport, elevation, and storage layers. Addresses 5 critical, 6 high,
7 medium, and several lower-severity findings.

### Added
- **Bootstrap token for elevation**: when no elevation password is set, `NewPasswordStore` generates a random one-time token logged at startup. `set_elevation_password` now requires this token alongside `new_password` in bootstrap mode, preventing a compromised OAuth client from racing to seize the elevation feature. (Fixes C2.)
- **`Elevation.Middleware()`**: HTTP middleware that stamps `auth.IsElevated(ctx)` with the current grant state. Automatically wired in `ListenAndServe` when `WithElevation` is set, so `auth.IsElevated` is now the authoritative check instead of a dead flag. (Fixes C1.)
- **Per-session rate limit on `Elevate`**: 5 wrong-password attempts / 15 min per token hash, returning `ErrElevationRateLimited`. Blocks brute-force over the authenticated MCP channel. (Fixes H6.)
- **Grant store cap**: default 10,000 active grants, consistent with other stores in the codebase. Configurable via `GrantStore.SetMaxGrants`. (Fixes M6.)
- **`WithAllowedOrigins`**: optional browser Origin allowlist. When set, requests carrying a non-matching Origin are rejected with 403 and preflight is handled. Mitigates DNS-rebinding against local MCP servers. (Fixes H4.)
- **`WithTrustedProxyCIDRs`**: enables `X-Forwarded-For` / `X-Real-IP` parsing only for proxies in the configured CIDR ranges. Without it, rate limiters correctly key on `RemoteAddr` (port-stripped). (Fixes H5.)
- **`WithAllowMissingState`**: escape hatch for legacy OAuth clients that don't send `state`. Default is now strict (state required). (Related to C3.)
- **`OAuthStore.VerifyClientSecret(id, secret)`**: constant-time comparison against the stored hash; `GetClient` no longer returns `ClientSecret`. (Fixes H2.)
- **`AuthorizeLimiter`**: per-IP limiter on `GET /authorize` (60/hr default) to bound auth-request store flooding. (Fixes M3.)
- **`auth.ScopeContains`**: RFC 6749 §3.3-correct space-delimited subset check, used by `VerifyAccessToken` and scope validation at authorize time. (Fixes M1.)
- **`PasswordStore.BootstrapToken()`** and **`Elevation.LogBootstrapBanner()`** public helpers.
- **`auth.OriginAllowlistMiddleware`** exposed for embedders.

### Changed — BREAKING
- **Token / code / client_secret storage is now hashed.** Access tokens, refresh tokens, authorization codes, and client secrets are stored as SHA-256 digests; lookups hash the presented value before comparison. A database file no longer discloses live credentials. (Fixes C4.)
- **`OAuthStore.ConsumeRefreshToken(token, expectedClientID string)`** — client binding is checked BEFORE deletion. A wrong-client request now returns an error without consuming the legitimate client's token. (Fixes M2.)
- **`PasswordStore.SetInitial(bootstrapToken, newPassword string)`** — requires the one-time token in bootstrap mode.
- **`GrantStore.Grant(key, ttl) error`** — returns `ErrGrantStoreFull` when the cap is hit (for a new key; refreshing an existing grant remains always allowed).
- **`ClientData.ClientSecret`** is populated only by `RegisterClient` (once, at issuance). `GetClient` returns an empty secret.
- **State is required at `/authorize`** unless `WithAllowMissingState()` is set. PKCE alone does not fully substitute for CSRF state. (Fixes C3.)
- **Scope at token exchange is no longer widened.** An empty requested scope now yields an empty granted scope rather than silently inheriting the server-configured scope. (Fixes H1.)
- **`redirect_uri` registration rejects query strings and fragments** (RFC 6749 §3.1.2). (Fixes H3.)
- **`VerifyAccessToken` and scope validation at `/authorize`** use set-based subset matching rather than string equality. Multi-scope tokens now work correctly. (Fixes M1.)

### Fixed
- **PKCE method normalization**: absent/empty `code_challenge_method` is normalized to `"S256"` at authorize time. The token exchange rejects anything other than `"S256"`. (Fixes C5.)
- **`pkceVerify`**: uses direct `crypto/subtle.ConstantTimeCompare` on base64-encoded digests instead of double-hashing via `SafeEqual`. (Fixes L1.)
- **Bearer scheme parsing**: case-insensitive per RFC 6750 §2.1; explicitly rejects empty tokens; trims whitespace. (Fixes L2.)
- **`WWW-Authenticate` header** on all 401 responses from `BearerMiddleware`, as required by RFC 6750 §3. OAuth clients now correctly trigger re-authorization on token expiry. (Fixes M4.)
- **`clientIP` port stripping**: `RemoteAddr`'s port suffix no longer fragments per-IP rate limit buckets. (Fixes H5.)
- **`GetAuthRequest` timestamp capture**: `time.Now()` is captured once before the transaction and used for expiry, closing a microsecond TOCTOU window. (Fixes L6.)
- **PIN value zeroized** on the `Server` struct after the OAuth handler is constructed, so a log dump of the server value cannot disclose it. (Fixes L5.)

### Security advisory
Operators upgrading from ≤v0.6.0 should plan for:
1. **OAuth database migration** — existing unhashed tokens/codes/secrets will no longer verify. Roll the OAuth SQLite file (clients will re-register; issued access/refresh tokens are invalidated).
2. **Elevation bootstrap token** — on first start after upgrade, the bootstrap token is printed to stdout and is required to call `set_elevation_password`. If a password is already set, nothing changes.
3. **OAuth clients that do not send `state`** will be rejected — set `WithAllowMissingState()` to preserve legacy behavior while migrating.

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
