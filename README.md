# go-mcp-server

A reusable Go library for building [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) servers with built-in OAuth 2.0 authentication, JSON-RPC 2.0 transport, and deployment helpers.

Designed around an **API-first pattern**: define your business logic as standard REST endpoints, then expose it over MCP with a single interface implementation. One binary, two transports.

## Quick Start

```go
package main

import (
    "context"
    "log"
    "os"

    mcpserver "github.com/Superposition-Systems/go-mcp-server"
)

func main() {
    // Docker healthcheck mode (distroless has no curl)
    if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
        os.Exit(mcpserver.RunHealthCheck("8080"))
    }

    srv := mcpserver.New(
        mcpserver.WithName("my-mcp"),
        mcpserver.WithVersion("1.0.0"),
        mcpserver.WithInstructions("A server that does useful things."),
        mcpserver.WithPort("8080"),
        mcpserver.WithPIN(os.Getenv("AUTH_PIN")),
        mcpserver.WithExternalURL(os.Getenv("EXTERNAL_URL")),
        mcpserver.WithBearerToken(os.Getenv("BEARER_TOKEN")),
    )

    // Mount REST API
    srv.Mux().HandleFunc("GET /api/v1/greet", greetHandler)

    // Register MCP tools (wrapping the same business logic)
    srv.RegisterTools(&MyTools{})

    if err := srv.ListenAndServe(); err != nil {
        log.Fatal(err)
    }
}
```

See [`example/`](example/) for a complete working example.

## Install

```bash
go get github.com/Superposition-Systems/go-mcp-server
```

## Architecture

```
┌─────────────────────────────────────────────┐
│                  Server                      │
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │  REST    │  │   MCP    │  │   OAuth   │  │
│  │ Handlers │  │Transport │  │  Endpoints│  │
│  │ (Mux)   │  │(JSON-RPC)│  │  (PIN)    │  │
│  └────┬─────┘  └────┬─────┘  └───────────┘  │
│       │              │                       │
│       └──────┬───────┘                       │
│              │                               │
│     ┌────────▼────────┐                      │
│     │  Business Logic │                      │
│     │  (ToolHandler)  │                      │
│     └─────────────────┘                      │
└─────────────────────────────────────────────┘
```

The library enforces a separation between transport and business logic:

1. **Business logic** lives in plain Go functions — no MCP or HTTP dependencies.
2. **REST handlers** call that logic and are mounted on the standard `http.ServeMux` via `srv.Mux()`.
3. **MCP tools** wrap the same logic by implementing the `ToolHandler` interface.
4. **Auth** is handled by middleware — your business logic never sees tokens.

## Server Lifecycle

```
New(opts...) → Mux() → [mount REST routes] → RegisterTools() → ListenAndServe()
```

`ListenAndServe()` blocks until `SIGINT`/`SIGTERM` and performs graceful shutdown (default 30s drain window).

### Routes registered automatically

| Path | Method | Purpose |
|------|--------|---------|
| `/health`, `/healthz` | GET | Health checks |
| `/mcp` | POST | MCP JSON-RPC 2.0 transport (SSE) |
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 OAuth metadata |
| `/.well-known/oauth-protected-resource` | GET | RFC 9728 resource metadata |
| `/register` | POST | RFC 7591 dynamic client registration |
| `/authorize` | GET/POST | OAuth PIN consent page |
| `/token` | POST | Token exchange & refresh |
| `/revoke` | POST | RFC 7009 token revocation (access + refresh) |

## ToolHandler Interface

Implement this interface to expose your business logic over MCP:

```go
type ToolHandler interface {
    ListTools() []ToolDef
    Call(ctx context.Context, name string, args map[string]any) (result any, isError bool)
}

type ToolDef struct {
    Name        string `json:"name"`
    Description string `json:"description"`
    InputSchema any    `json:"inputSchema"`
}
```

`ListTools()` returns MCP tool definitions (including JSON Schema for arguments). `Call()` dispatches tool invocations by name. Return `isError: true` to signal a tool-level error to the client.

For servers with more than a handful of tools, the [Registry](#extension-layer-v080) added in v0.8.0 is usually a nicer fit than implementing this interface directly — each tool is a self-describing struct with category, alias, and schema metadata, and `Registry.AsToolHandler()` produces the same interface.

## Configuration Options

All options are passed to `New()`:

| Option | Default | Description |
|--------|---------|-------------|
| `WithName(name)` | `"mcp-server"` | Server name in MCP `initialize` response |
| `WithVersion(version)` | `"1.0.0"` | Semantic version in MCP `initialize` response |
| `WithInstructions(text)` | `""` | Human-readable server description |
| `WithPort(port)` | `"8080"` | Listen port |
| `WithTimeout(d)` | `120s` | Per-request context timeout |
| `WithDrainTime(d)` | `30s` | Graceful shutdown drain window |
| `WithMCPPath(path)` | `"/mcp"` | MCP endpoint path |
| `WithBearerToken(token)` | `BEARER_TOKEN` env | Static bearer token for CLI auth |
| `WithTokenValidator(fn)` | `nil` | Custom token validation function |
| `WithExternalURL(url)` | `""` | Canonical public URL (**required for production**) |
| `WithPIN(pin)` | `AUTH_PIN` env | OAuth consent PIN |
| `WithScope(scope)` | `"mcp:tools"` | OAuth scope |
| `WithConsent(title, desc)` | `"MCP Server"` | PIN consent page branding |
| `WithOAuthDBPath(path)` | `OAUTH_DB_PATH` env or `/data/oauth.db` | SQLite database path |
| `WithAuth(cfg)` | — | Full `OAuthConfig` struct |
| `WithMiddleware(mw)` | `nil` | Outer middleware (runs before auth) |
| `WithAllowedOrigins(...)` | `nil` | Browser `Origin` allowlist; non-matching requests get 403. Mitigates DNS-rebinding on SSE endpoints. |
| `WithTrustedProxyCIDRs(...)` | `nil` | CIDR ranges whose `X-Forwarded-For` / `X-Real-IP` the server may trust for rate-limiting keys. |
| `WithAllowMissingState()` | `false` | Legacy opt-out — permits OAuth `/authorize` without the `state` parameter. Not recommended. |
| `WithElevation(cfg)` | `nil` | Enables step-up-auth elevation (see [Elevation](#elevation)) |
| `WithToolMiddleware(mw...)` | `nil` | Installs one or more tool-call middlewares; outermost-first (see [Extension layer](#extension-layer-v080)) |
| `WithResponseTransformer(t)` | `nil` | Installs a tool-response transformer (e.g. `CompactREST()` for REST-envelope stripping) |
| `WithParamAliases(global)` | `nil` | Rewrites parameter names before tool dispatch (e.g. `issueKey → issueKeyOrId`) |
| `WithInputValidation(opts...)` | `nil` | Validates tool args against each `Tool.InputSchema` via JSON Schema 2020-12 |
| `WithSuggestionHook(h)` | `nil` | Wires a `suggest.Hook` for fuzzy "did you mean?" telemetry from mux/aliases/validator |

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `BEARER_TOKEN` | Static bearer token for CLI authentication | — |
| `AUTH_PIN` | OAuth consent PIN | — |
| `OAUTH_DB_PATH` | SQLite database path for OAuth state | `/data/oauth.db` |
| `EXTERNAL_URL` | Canonical public URL for OAuth metadata | — |

## Authentication

The server supports three authentication modes, checked in order:

### 1. Custom Token Validator

Set via `WithTokenValidator(fn)`. Receives the raw token (after stripping `Bearer `) and returns `true` to accept. Use this for multi-token schemes, scoped auth, or external auth delegation.

```go
mcpserver.WithTokenValidator(func(token string) bool {
    return myAuthService.Validate(token)
})
```

### 2. Static Bearer Token

Set via `WithBearerToken(token)` or the `BEARER_TOKEN` env var. Simple shared secret suitable for CLI tools.

```bash
curl -X POST https://my-mcp.example.com/mcp \
  -H "Authorization: Bearer my-secret-token" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

### 3. OAuth 2.0 (Dynamic Client Registration + PKCE)

Full OAuth 2.0 flow with PIN-based consent, designed for browser-based MCP clients like [claude.ai](https://claude.ai).

**Flow:**

```
Client                          Server                          User
  │                               │                               │
  │── GET /.well-known/oauth-*  ──▶│                               │
  │◀── discovery metadata ────────│                               │
  │                               │                               │
  │── POST /register ────────────▶│                               │
  │◀── client_id + client_secret ─│                               │
  │                               │                               │
  │── GET /authorize?... ────────▶│── render PIN page ───────────▶│
  │                               │◀── user enters PIN ───────────│
  │◀── 302 redirect + code ──────│                               │
  │                               │                               │
  │── POST /token ───────────────▶│                               │
  │◀── access_token + refresh ────│                               │
  │                               │                               │
  │── POST /mcp (Bearer token) ──▶│                               │
  │◀── MCP response ─────────────│                               │
```

**Key details:**
- PKCE (S256) is mandatory — no plain challenge fallback.
- Authorization codes expire after 5 minutes (single-use).
- Access tokens expire after 1 hour; refresh tokens after 30 days.
- Refresh tokens rotate on use (old token invalidated).
- All secrets compared using constant-time operations (`SafeEqual`).
- Auth request parameters stored server-side (not in browser forms).
- The PIN consent page displays the registered `client_name` and the `redirect_uri` host so the operator can visually confirm *who* they are authorizing. Without this, a DCR-registered client with an attacker-controlled redirect URI would be visually indistinguishable from a legitimate one.
- `POST /revoke` (RFC 7009) removes a presented access or refresh token from the store. Authenticates the client with `client_secret_post` and silently succeeds on unknown tokens (RFC-mandated, prevents probing). Store failures surface as `503` rather than a quiet `200` so operators know the revocation did not take effect.

### Bearer Middleware

Only paths matching the MCP endpoint (default `/mcp`) require authentication. All other paths — health checks, OAuth endpoints, and user-mounted routes — pass through without auth. Use a reverse proxy for infrastructure-level access control on other routes.

On successful auth, `BearerMiddleware` stashes a SHA-256 hash of the presented token on the request context (`auth.GetTokenHash(ctx)`). Handlers can use this as a stable session identifier — for per-session state, step-up elevation, or any feature that needs to answer *"is this the same caller as before?"* without ever touching the raw token.

## Elevation

Opt-in step-up-authentication feature. When configured via `WithElevation(ElevationConfig{...})`, the server exposes two extra tools — `<prefix>_elevate` and `<prefix>_set_elevation_password` — that let an authenticated session temporarily promote itself to write access by proving knowledge of an elevation password.

The intended use case: distinguishing *read-only* sessions (e.g. a cloud connector holding an OAuth token) from *write-capable* sessions, without requiring a second credential store or re-auth flow. The elevation is ephemeral (in-memory, TTL-bounded) and scoped to the specific token that called `elevate` — other sessions holding other tokens are unaffected.

### Bootstrap mode

When no password is configured (neither stored on disk nor supplied via the env var), the server runs in **bootstrap mode**: every authenticated session is treated as elevated by default. The server generates a random one-time **bootstrap token** at startup and prints it to stdout in a prominent banner. Calling `set_elevation_password` in bootstrap mode requires this token — preventing a compromised OAuth client from racing to seize the elevation feature. Once the initial password is set, the token is cleared and bootstrap mode closes.

If that tradeoff is unacceptable (e.g. production deploys where no free-access window should ever exist), configure `EnvPasswordVar` and set that environment variable at startup. The env value becomes the elevation password, bootstrap mode is disabled, and runtime rotation is refused (rotate by changing the env var and restarting).

### Configuration

```go
srv := mcpserver.New(
    // ...other options...
    mcpserver.WithElevation(mcpserver.ElevationConfig{
        DBPath:         "/data/elevation.db",        // required — SQLite path
        GrantTTL:       10 * time.Minute,            // default 10m
        EnvPasswordVar: "MY_ELEVATION_PASSWORD",     // optional strict-mode override
        ToolNamePrefix: "",                          // defaults to server name, hyphen→underscore
    }),
)
```

### Registered tools

The library prefixes these with the server name (hyphens → underscores) unless `ToolNamePrefix` overrides it.

| Tool | Arguments | Behavior |
|---|---|---|
| `<prefix>_elevate` | `password` | Grants elevation to the current session for `GrantTTL`. In bootstrap mode returns immediately with `elevated=true, bootstrap=true`. Rate-limited to 5 wrong-password attempts per 15 min per session. |
| `<prefix>_set_elevation_password` | `new_password` + `bootstrap_token` (first time) or `current_password` (rotation) | Establishes the first password (bootstrap) or rotates an existing one. Rotation revokes all active elevations. The bootstrap token is printed to server logs at startup. |

### Composing with handler-level checks

The server doesn't enforce elevation on any tool automatically — that's policy the app owns. Check it inside any write-gated handler:

```go
func (t *MyTools) handleWrite(ctx context.Context, args map[string]any) (any, bool) {
    if !t.elev.HasCurrentSession(ctx) {
        return map[string]any{"error": "write requires elevation"}, true
    }
    // ...
}
```

Fetch the handle during tool construction — `srv.Elevation()` is safe to call before `ListenAndServe()` (the underlying stores open lazily on first access):

```go
tools := NewMyTools(cfg, srv.Elevation())
srv.RegisterTools(tools)
```

### Primitives

For apps that want finer control than the bundled tools, the underlying primitives in `auth/elevation.go` can be used directly:

- `auth.PasswordStore` — persistent hashed-password store (PBKDF2-SHA256, 600k iterations, stdlib `crypto/pbkdf2`)
- `auth.GrantStore` — in-memory TTL-keyed "is this key currently elevated" store
- `auth.Elevation` — composes both with a configured TTL; provides `HasCurrentSession(ctx)`, `Elevate(ctx, password)`, etc.
- `auth.TokenHash(token)`, `auth.GetTokenHash(ctx)` — stable per-session identity derived from the bearer token

## Extension layer (v0.8.0)

v0.8.0 added an opt-in composition surface for tool-handling concerns that used to live in consumer `switch` statements. Every feature below is additive — the existing `ToolHandler` interface is untouched, and consumers who don't install any of the new options see identical behaviour to v0.7.x.

Design doc (frozen): [`docs/plans/v0.8.0-middleware-and-registry.md`](docs/plans/v0.8.0-middleware-and-registry.md). The doc locks the original design from the parallel-session delivery; behaviour guarantees below reflect the shipped code after the v0.8.0 sweep. When the two disagree, the code is authoritative.

### Behaviour guarantees

These invariants hold across every combination of `With*` options:

- **Registry sealing.** The backing `*Registry` is sealed against further `Register` / `MustRegister` calls on the first call to either `Server.ListenAndServe()` or `Server.ToolCallChain()` (whichever comes first). When a mux wraps an underlying registry, sealing the mux cascades to the underlying — no path leaves a mutable registry captured in live dispatch closures.
- **Error contract on the chain.** `err != nil` from any middleware is a library-level failure: the response transformer is skipped, and the wire envelope carries the error text with `isError: true`. `isError: true` with `err == nil` is a successful call reporting a tool-level error; transformers still skip it. A `marshalResult` failure on a successful tool result is logged server-side (`log.Printf`) in addition to being reported on the wire.
- **Input validation.** `WithInputValidation` actually compiles each tool's `InputSchema` under draft 2020-12 and rejects on failure before the handler runs. `ValidationStrict()` rejects unknown top-level properties and fires `suggest.EventUnknownParam`. Validator wiring works under elevation-wrapped handlers too.
- **Alias resolution.** `WithParamAliases(nil)` and `WithParamAliases(map[string]string{})` both skip installation of the alias middleware entirely — no per-call overhead when there's nothing to rewrite. Per-tool `Tool.ParamAliases` override the global map.
- **JSON-RPC notifications.** Any request with no `id` field is treated as a notification: `202 Accepted` with an empty body, regardless of method. Historical `notifications/initialized` / `notifications/cancelled` are accepted even when a lenient client mistakenly sends an id.
- **Compaction safety.** `CompactResponse` and `CompactREST` bail out at 1000 levels of recursion, so a buggy tool handler returning a self-referential or pathologically nested graph cannot stack-overflow the server.
- **Config store.** `Set` and `Delete` reject keys that aren't env-var-shaped (`[A-Za-z0-9_]`, non-empty, non-leading-digit), and `Set` rejects values containing `\n`/`\r`. `config_list` propagates DB errors to the caller instead of returning an empty-keys response on failure.
- **Telemetry sinks.** `suggest.JSONLFile` holds one long-lived file descriptor per process and drops back to re-opening only on write error; files are created `0600` under a `0700` parent.
- **Diag logger shutdown.** `diag.Logger.Close` takes the write-lock and nil-clears the `*sql.DB` so in-flight readers/writers observe a consistent terminal state.

Everything above is exercised by production code and tests; if you hit a counter-example, file it.

### Registry: self-describing tool catalogue

Alternative to hand-rolling `ToolHandler`. Define each tool once, including its metadata and handler; `registry.AsToolHandler()` satisfies the interface.

```go
reg := mcpserver.NewRegistry()
reg.MustRegister(mcpserver.Tool{
    Name:        "jiraGetIssue",
    Description: "Fetch a Jira issue by key.",
    Category:    "Issues",
    InputSchema: json.RawMessage(`{"type":"object","properties":{"issueKeyOrId":{"type":"string"}},"required":["issueKeyOrId"]}`),
    ParamAliases: map[string]string{"issueKey": "issueKeyOrId", "key": "issueKeyOrId"},
    Handler: func(ctx context.Context, args map[string]any) (any, error) {
        return jiraClient.GetIssue(ctx, args["issueKeyOrId"].(string))
    },
})
srv.RegisterTools(reg.AsToolHandler())
```

### Mux: collapse many tools into 4

`NewMux` wraps a Registry and exposes exactly four dispatcher tools: `<prefix>_execute`, `<prefix>_list_tools`, `<prefix>_health`, `<prefix>_get_skill`. The routing guide (`_get_skill`) is rendered from the Registry — parameter signatures come from each tool's `InputSchema`, no parallel metadata required. Matches the "150 tools → 4" pattern used by the Node atlassian-mcp server.

```go
mux := mcpserver.NewMux(reg, mcpserver.MuxConfig{
    Prefix:  "atlassian",
    Compact: true, // apply CompactREST to every successful result
    Skill: mcpserver.DefaultSkillBuilder(mcpserver.SkillOptions{
        Title:      "Atlassian MCP — Routing Guide",
        Featured:   []mcpserver.Featured{{Section: "Issues", Tools: []string{"jiraGetIssue"}}},
        Categorise: true,
    }),
})
srv.RegisterTools(mux.AsToolHandler())
```

### Middleware chain and built-in transformers

Every `tools/call` passes through a composable chain when any of the `With*` middleware options is set. Order (outer → inner): user middlewares → parameter aliases → schema validator → response transformer → registry dispatch. `initialize` / `tools/list` / `ping` bypass.

```go
srv := mcpserver.New(
    mcpserver.WithName("my-mcp"),
    mcpserver.WithResponseTransformer(mcpserver.CompactREST()),
    mcpserver.WithParamAliases(map[string]string{"issueKey": "issueKeyOrId"}),
    mcpserver.WithInputValidation(mcpserver.ValidationStrict()),
    mcpserver.WithSuggestionHook(suggest.JSONLFile("/data/alias-suggestions.jsonl")),
)
```

`CompactREST()` is a preset matching the Node atlassian-mcp strip keys (`avatarUrls`, `avatarUrl`, `iconUrl`, `expand` at any depth; URL-valued `self`; top-level `schema` and nulls). Custom transformers: `CompactResponse(StripFields("x"), StripNulls(), StripEmptyArrays())`.

### Telemetry: fuzzy suggestions + alias collisions

`WithSuggestionHook` wires one hook across the mux, the alias middleware, and the validator. Each unknown tool name, unknown parameter name, and alias collision produces a `suggest.Event` (Kind = `tool` / `param` / `alias_collision`). `suggest.JSONLFile(path)` is a ready-made sink; `suggest.Multi(h1, h2, ...)` fans out to many. Hook panics are recovered.

### Subpackages

| Subpackage | Purpose |
|------------|---------|
| [`suggest/`](suggest/) | Levenshtein `Closest`, typed `Event`/`Hook`, `JSONLFile`, `Multi`. Used by mux + aliases + validator. |
| [`diag/`](diag/) | SQLite ring-buffer logger on its own DB file, `slog.Handler` adapter, tool-call `Middleware()`, auto-registered `server_get_logs` / `server_get_stats` tools. |
| [`config/`](config/) | SQLite KV store with SQLite → file → env precedence, write-through, auto-registered `config_get` / `config_set` / `config_list` / `config_delete` tools. |
| [`webhook/`](webhook/) | `HMACSHA256` and `BearerOrQuerySecret` verifiers plus a `Router` that attaches signature-verified endpoints to an existing `http.ServeMux`. Raw body buffered once (10 MB cap). |

Runnable demos: [`example/mux_compact_example/`](example/mux_compact_example/) and [`example/diag_config_webhook_example/`](example/diag_config_webhook_example/).

## Security

### Request Limits

| Endpoint | Max Body |
|----------|----------|
| `POST /mcp` | 10 MB |
| `POST /register` | 1 MB |
| `POST /authorize` | 64 KB |
| `POST /token` | 64 KB |

### Server Timeouts

All connections enforce timeouts to prevent slowloris and connection exhaustion:

| Timeout | Value | Purpose |
|---------|-------|---------|
| `ReadHeaderTimeout` | 10s | Slow header sending |
| `ReadTimeout` | 30s | Entire request body |
| `WriteTimeout` | request timeout + 10s | Response writing (accommodates long tool calls) |
| `IdleTimeout` | 120s | Keep-alive connections |

### Rate Limiting

| Endpoint | Limit | Window |
|----------|-------|--------|
| `POST /authorize` (PIN attempts) | 5 attempts per IP | 15 minutes |
| `GET /authorize` (consent page views) | 60 per IP | 1 hour |
| `POST /register` (client registration) | 10 attempts per IP | 1 hour |
| Elevation password attempts (per session) | 5 attempts per token hash | 15 minutes |

PIN rate limits clear on successful authentication. Registration and authorize-GET rate limits count all attempts regardless of outcome. All limiters have a 100k-IP capacity cap and are periodically pruned (every 5 min) so idle entries do not stick and allow bypass. At saturation (map at cap), limiters fail closed — novel IPs are rejected rather than silently untracked — so an attacker with a large IP pool cannot bypass rate limiting by cycling fresh addresses.

When running behind a reverse proxy, use `WithTrustedProxyCIDRs(...)` so the limiters key on the real client IP rather than the proxy's IP — otherwise all clients share one bucket.

### ExternalURL

In production, set `WithExternalURL("https://your-domain.com")` (or the `EXTERNAL_URL` env var). This hardcodes the OAuth issuer URL in discovery metadata, preventing Host header injection attacks.

The server refuses to start if `ExternalURL` is set to a non-`https://` URL unless the host is a loopback address (`localhost`, `127.0.0.1`, `::1`). This closes the common footgun of a typo'd or copy-pasted `http://` production URL producing spec-violating discovery metadata.

Without it, OAuth discovery (`/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource`) will serve metadata only for `localhost`, `127.0.0.1`, or `::1` requests. Non-localhost requests receive `HTTP 500` with a clear error message instead of silently-poisoned "http://localhost" metadata. This makes misconfigured production deployments fail loudly rather than silently trusting attacker-controlled `Host` headers.

### PIN Strength

The server refuses to start if `AUTH_PIN` is shorter than 6 characters, and logs a warning for PINs shorter than 8 characters. With the 5-per-15-minute rate limit, a 4-digit numeric PIN is brute-forceable in days from a single IP; the floor closes that footgun without constraining legitimate deployments. An unset PIN is allowed (static-bearer-only mode).

### Redirect URI Validation

Redirect URIs are validated at two points:

1. **Registration** (`POST /register`): Rejects URIs that don't use `https://`. The exceptions are `http://localhost`, `http://127.0.0.1`, and `http://[::1]` for local development.
2. **Authorization** (`GET /authorize`): Validates the requested `redirect_uri` against the client's registered URIs *before* rendering the consent page (per RFC 6749 §3.1.2.4). The same check is repeated at `POST /authorize` before issuing the redirect.

The token endpoint (`POST /token`) also verifies that the `redirect_uri` matches the one from the original authorization request (per RFC 6749 §4.1.3), preventing authorization code interception.

### Scope Enforcement

OAuth access tokens carry a `scope` field that is enforced at the bearer middleware layer. Tokens whose scope doesn't match the server's configured scope (default `"mcp:tools"`) are rejected. Static bearer tokens and custom token validators bypass scope checks.

### Resource Caps

All database tables are bounded to prevent disk exhaustion from unauthenticated or compromised callers:

| Resource | Cap |
|----------|-----|
| Registered clients | 1,000 |
| Pending auth requests | 10,000 |
| Access tokens | 50,000 |
| Refresh tokens | 50,000 |
| Rate limiter IP entries | 100,000 |

### Other Measures

- All secret comparisons are constant-time: `SafeEqual()` (SHA-256 + `crypto/subtle.ConstantTimeCompare`, length-hiding) for raw-secret compares, and direct `crypto/subtle.ConstantTimeCompare` on fixed-length digests where the inputs are already hashed (`VerifyClientSecret`, `pkceVerify`, `verifyPassword`).
- Tokens generated with `crypto/rand` (32 bytes = 64 hex characters).
- OAuth state stored in SQLite with WAL mode, foreign keys, and `SetMaxOpenConns(1)` for single-writer safety. The database directory is chmod'd to `0700` and the DB file to `0600` at startup so bind-mount / volume-copy scenarios do not leak metadata to other UIDs.
- All consume operations (auth codes, refresh tokens, auth requests) use database transactions for atomicity.
- Expired tokens and codes cleaned up every 5 minutes in a background goroutine.
- Unknown JSON-RPC method names are truncated to 64 characters before inclusion in error messages.

## Transport

The MCP transport uses JSON-RPC 2.0 over HTTP with Server-Sent Events (SSE) responses.

**Supported methods:**

| Method | Description |
|--------|-------------|
| `initialize` | Returns server info, capabilities, protocol version (`2025-03-26`) |
| `tools/list` | Returns tool definitions from `ToolHandler.ListTools()` |
| `tools/call` | Dispatches to `ToolHandler.Call()` |
| `ping` | Returns empty result (health check) |
| `notifications/initialized` | Accepted, no-op (202) |
| `notifications/cancelled` | Accepted, no-op (202) |

**Required headers:**

```
Content-Type: application/json
Accept: application/json, text/event-stream
Authorization: Bearer <token>
```

**Response format** (SSE):

```
event: message
data: {"jsonrpc":"2.0","id":1,"result":{...}}

```

### Standalone Transport Handler

For custom server setups, use `TransportHandler` directly on any router:

```go
mux.HandleFunc("POST /mcp", mcpserver.TransportHandler(info, tools))
```

## Deploy Package

The `deploy` package generates deployment configuration files.

### Dockerfile Generation

Generates a two-stage Dockerfile using distroless base images (~12 MB final image):

```go
import "github.com/Superposition-Systems/go-mcp-server/deploy"

content, err := deploy.GenerateDockerfile(deploy.DockerfileConfig{
    GoVersion:  "1.25",
    BinaryName: "my-mcp-server",
    Port:       "8080",
})
```

Output:
- Builder stage: `golang:<version>-alpine` with `CGO_ENABLED=0`
- Final stage: `gcr.io/distroless/static-debian12` running as `nonroot`
- Binary stripped with `-ldflags="-s -w"`

### Traefik Labels Generation

Generates docker-compose labels for Traefik reverse proxy routing:

```go
labels, err := deploy.GenerateTraefikLabels(deploy.TraefikConfig{
    ServiceName: "my-mcp",
    Hostname:    "my-mcp.example.com",
    Port:        "8080",
    MCPPath:     "/mcp",
})
```

Generates a multi-router setup with priority ordering:

| Router | Priority | Auth | Paths |
|--------|----------|------|-------|
| Health | 120 | Public (rate-limited) | `/health`, `/healthz` |
| OAuth discovery | 110 | Public | `/.well-known/*`, `/token`, `/register` |
| OAuth authorize | 110 | QA gate | `/authorize` |
| MCP transport | 100 | Public (app handles auth) | `/mcp` |
| API routes | 90 | QA gate | `/api/*` |
| Default | — | QA gate | Everything else |

Includes security headers: HSTS (1 year), CSP, frame deny, XSS filter, nosniff.

## Health Checks

The server exposes `GET /health` and `GET /healthz` endpoints returning `{"status":"ok"}`.

For distroless containers (no `curl` available), use `RunHealthCheck`:

```go
if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
    os.Exit(mcpserver.RunHealthCheck("8080"))
}
```

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/my-binary", "healthcheck"]
```

## Dependencies

- [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) — Pure-Go SQLite (no CGO required, compatible with distroless images)
- [github.com/google/uuid](https://pkg.go.dev/github.com/google/uuid) — UUID generation for client IDs and auth codes

