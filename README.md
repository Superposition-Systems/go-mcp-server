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

### Bearer Middleware

Only paths matching the MCP endpoint (default `/mcp`) require authentication. All other paths — health checks, OAuth endpoints, and user-mounted routes — pass through without auth. Use a reverse proxy for infrastructure-level access control on other routes.

## Security

### Request Limits

- **MCP endpoint**: 10 MB max request body (`http.MaxBytesReader`).
- **Registration endpoint**: 1 MB max request body.

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
| `POST /register` (client registration) | 10 attempts per IP | 1 hour |

PIN rate limits clear on successful authentication. Registration rate limits count all attempts regardless of outcome.

### ExternalURL

In production, set `WithExternalURL("https://your-domain.com")` (or the `EXTERNAL_URL` env var). This hardcodes the OAuth issuer URL in discovery metadata, preventing Host header injection attacks.

Without it, the server derives the issuer from request headers (`X-Forwarded-Proto` and `Host`) — suitable for local development only.

### Redirect URI Validation

Client registration rejects redirect URIs that don't use `https://`. The exceptions are `http://localhost`, `http://127.0.0.1`, and `http://[::1]` for local development.

### Other Measures

- All secret comparisons use `SafeEqual()` — SHA-256 hashing + `crypto/subtle.ConstantTimeCompare` to prevent timing and length-leak attacks.
- Tokens generated with `crypto/rand` (32 bytes = 64 hex characters).
- OAuth state stored in SQLite with WAL mode and foreign keys enabled.
- Expired tokens and codes cleaned up every 5 minutes in a background goroutine.
- Max 1000 registered clients (configurable in `OAuthStore`).

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
    GoVersion:  "1.24",
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

