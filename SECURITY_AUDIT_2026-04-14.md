# Security Audit — go-mcp-server — 2026-04-14

Scope: the auth substrate shared by every public-facing MCP server in the
Superposition Systems portfolio (Atlassian, GitHub, Slack, VPS, Voxhub,
Traxos, md2pdf, Claude Logs, Doc-Crawler, YouDoYoutube). Every finding
below has a blast radius of *all ten services* unless otherwise noted.

## Map of the auth surface

| Concern | File:lines |
|---|---|
| Bearer middleware | `auth/middleware.go:166-220` |
| OAuth discovery | `auth/oauth.go:104-134` |
| DCR `/register` | `auth/oauth.go:137-174` |
| `/authorize` GET (consent) | `auth/oauth.go:177-304` |
| `/authorize` POST (PIN verify) | `auth/oauth.go:307-413` |
| `/token` dispatch | `auth/oauth.go:416-547` |
| Token store (SQLite schema + I/O) | `auth/store.go:86-627` |
| PIN constant-time compare | `auth/oauth.go:549-556` (`SafeEqual`) |
| Route wiring + middleware stack | `server.go:201-241` |
| `/mcp` transport handler | `transport.go:19-116` |
| Rate limiters | `auth/middleware.go:10-96` + construction `auth/oauth.go:85-100` |
| Auth-success logging | none beyond startup banners (see `log\.Printf` grep) |

Openid-configuration is *not* mounted (server.go:201-211). Only
`oauth-authorization-server` + `oauth-protected-resource`. That is
correct — the library does not claim OIDC support.

`★ Insight ─────────────────────────────────────`
The middleware stack order is **Origin → outer → Bearer → elevation → mux**
(server.go:223-241). Bearer auth therefore runs *before* JSON parsing,
tool dispatch, and the per-request context timeout — an unauthenticated
caller reaches at most `parseBearer` + one indexed SQLite lookup before
being rejected. This layout is the reason question 27 is a clean "yes."
`─────────────────────────────────────────────────`

---

## CRITICAL

*(None.)*

## HIGH

### H-1 — Consent page hides client identity, enabling DCR-phishing of the PIN gate

**file:line**: `auth/consent.go:8-41` (renders no client_name / redirect_uri)
together with `auth/oauth.go:137-174` (public DCR, no gating on `/register`).

**Exploit narrative**: `/register` is open to the internet (the design
intent — DCR is how claude.ai bootstraps). An attacker registers a
client with `redirect_uri=https://attacker.example/cb` and any
`client_name`. They then lure an authorized operator to
`https://<service>/authorize?response_type=code&client_id=<attacker>&...`.
The consent page at `auth/consent.go:13-40` shows only the configured
title and description — it displays **neither the registered
`client_name` nor the `redirect_uri`**. The operator, seeing only the
familiar branding, enters the PIN. `AuthorizePOST` redirects the code
to the attacker's URI. The attacker — who holds the client_secret from
their own DCR registration — exchanges it at `/token` and gets a
3600-second access token with full `mcp:tools` scope. Every subsequent
operator log-in flow is similarly hijackable.

PKCE does not help: the attacker generated the verifier. Redirect-URI
allowlisting does not help: the attacker's URI is on *their own*
client's allowlist. The PIN alone is the whole gate, and the consent
page gives the user no signal that they are handing it to the wrong
relying party.

**Concrete fix**: render the registered client's identity on the
consent page, and render the redirect_uri host. In `auth/oauth.go`
around the `RenderPINPage(...)` call at line 303, fetch the client and
pass its display fields through:

```go
// auth/oauth.go  (AuthorizeGET, replacing the final render)
redirectHost := "(unknown)"
if u, err := url.Parse(reqRedirectURI); err == nil {
    redirectHost = u.Host
}
w.Header().Set("Content-Type", "text/html")
fmt.Fprint(w, RenderPINPage(
    h.config.ConsentTitle,
    h.config.ConsentDescription,
    requestID, "",
    client.ClientName,  // new arg
    redirectHost,       // new arg
))
```

And in `auth/consent.go`, extend the signature and render (both
html-escaped):

```
Connecting: <b>{{.ClientName}}</b>
Redirect:   <code>{{.RedirectHost}}</code>
```

Make this non-optional — consumers should not have to opt in. The
PIN-gating model assumes the operator knows *who* they are granting
access to; without the client_name/redirect_host on the page that
assumption is unsound.

**Blast radius**: every SPS service. Any service that has an open
internet path to `/authorize` (i.e. any service not hiding
`/authorize` behind the Traefik qa-gate) is directly vulnerable. Per
the deployment notes, `/authorize` *is* gated by qa-gate — which
downgrades this finding somewhat, because the attacker must also
satisfy the qa-gate. Severity remains **HIGH** because (a) the
qa-gate is a password, not cryptographic auth, and (b) the whole
point of the PIN gate is defense-in-depth against operator confusion;
removing the user's ability to see what they are consenting to
defeats that purpose.

---

## MEDIUM

### M-1 — No minimum-strength check on `AUTH_PIN`; operator can set a 4-digit PIN

**file:line**: `server.go:73` (read) and `auth/oauth.go:307-346` (no length/charset
validation on `h.config.PIN` at startup).

**Exploit narrative**: `AUTH_PIN` is whatever the operator put in env.
Rate limit is 5 attempts per 900 seconds per IP = 480/day. A 4-digit
numeric PIN has 10 000 values; 50% expected cracking time behind a
single IP is ~10 days. Behind a modest distributed attacker (100 IPs,
say cheap residential proxies), it collapses to hours. Nothing in the
library warns the operator if the PIN is short or numeric.

**Concrete fix**: in `server.go:73` after reading the PIN (and in
`WithPIN`), validate:

```go
if s.oauthConfig.PIN != "" {
    if len(s.oauthConfig.PIN) < 8 {
        log.Printf("mcpserver: =========================================================")
        log.Printf("mcpserver: WARNING: AUTH_PIN is shorter than 8 characters. With the")
        log.Printf("mcpserver: current 5/15min rate limit, a 6-digit PIN falls in ~2y")
        log.Printf("mcpserver: from a single IP and hours under modest distribution.")
        log.Printf("mcpserver: =========================================================")
    }
}
```

Prefer a hard refuse (`return fmt.Errorf(...)` in
`ListenAndServe`) for PINs < 6 characters; that closes the
obviously-broken case without over-constraining the operator.

**Blast radius**: every SPS service where the operator chose a short
PIN. Unknown without probing each env file.

### M-2 — No token revocation endpoint (RFC 7009)

**file:line**: not present. Searched server.go, auth/oauth.go for
`/revoke` — no match.

**Exploit narrative**: if an access token or refresh token is leaked
(log spillage in a consumer service, client-side compromise, a
disaffected operator, a lost laptop), there is no API to invalidate
it. The only revocation path is to open the SQLite file and
`DELETE FROM access_tokens WHERE ...` — which is a manual ops
procedure the portfolio does not have runbooks for. Tokens live to
their 3600s / 30-day TTL regardless.

**Concrete fix**: add `POST /revoke` per RFC 7009. Authenticates the
client via `VerifyClientSecret`, looks up the presented token by
hash in both `access_tokens` and `refresh_tokens`, deletes any match
(silent 200 either way per RFC). Mount in `server.go` alongside the
other OAuth routes.

**Blast radius**: every SPS service, in the rare event of token
leakage. Not an active exploit path; a "fire-drill-readiness" gap.

### M-3 — `ExternalURL` scheme is not validated; an `http://` issuer is silently accepted

**file:line**: `auth/oauth.go:592-605` (`baseURLFromConfig` returns
`cfg.ExternalURL` verbatim if non-empty).

**Exploit narrative**: operator sets `EXTERNAL_URL=http://mcp.example`
(typo / test config leak). Discovery then advertises an `http://`
issuer, which (a) some spec-strict clients will refuse, breaking the
flow with an obscure error, and (b) more importantly, any downstream
audience-validation that compares `iss` against an expected `https://`
value can be fooled by a MITM that strips TLS between Traefik and the
client.

**Concrete fix**: in `server.go` `ListenAndServe`, refuse to start
(or at minimum loudly warn) when `ExternalURL` is set but the scheme
is not `https://` — unless the host is localhost/127.0.0.1/::1:

```go
if s.oauthConfig.ExternalURL != "" {
    u, err := url.Parse(s.oauthConfig.ExternalURL)
    if err != nil || (u.Scheme != "https" && !isLocalHost(u.Hostname())) {
        return fmt.Errorf("mcpserver: ExternalURL must be https:// (or http://localhost for dev), got %q", s.oauthConfig.ExternalURL)
    }
}
```

**Blast radius**: every SPS service if the operator ever makes this
mistake. Active impact low because Traefik terminates TLS in
production, but the library should refuse to produce spec-violating
discovery metadata.

### M-4 — Go toolchain version drift between module directive and generated Dockerfile

**file:line**: `go.mod:3` (`go 1.25.0`) vs `deploy/dockerfile.go:46`
(`cfg.GoVersion = "1.24"` default).

**Exploit narrative**: this is not a direct vulnerability but it
pressures consumers to unpin their Go version. A fresh consumer
generating a Dockerfile via `deploy.GenerateDockerfile` gets
`FROM golang:1.24-alpine`, which then *fails to build* this library
(requires 1.25). The path of least resistance for a hurried operator
is to bypass pinning — `FROM golang:alpine` — which floats to
whatever Docker Hub shipped last, defeating reproducibility and
making the scheduled-security-patch story fuzzy.

`govulncheck` output on the local toolchain (`go 1.26.0`) reports 7
stdlib vulns (x509 / tls / net/url), all fixed in 1.26.1 / 1.26.2.
That's the expected Go patch cadence — but the drift above means no
one can give a definitive statement of what version actually runs in
production containers.

**Concrete fix**: update `deploy/dockerfile.go:46` default to
`"1.25"` (or better: read it from the `go.mod` at generation time).

**Blast radius**: every SPS service that used the library's
Dockerfile generator.

---

## LOW

### L-1 — Tool handlers do not receive `client_id`; DCR clients cannot be partitioned

**file:line**: `auth/middleware.go:191-215` (only `TokenHash` is
stashed on the context; `TokenData.ClientID` is not).

**Exploit narrative**: not an exploit per se — a limitation. If an
SPS service wants to expose different data to different OAuth clients
(e.g., "tenant A's claude.ai instance sees only tenant A's tickets"),
the tool handler has no way to read the client_id. Every issued
OAuth token is effectively a god-token for whatever tools are
registered. Adding this later is straightforward; shipping without
it makes multi-tenant-by-client impossible.

**Concrete fix**: extend `VerifyAccessToken` to return
`(*TokenData, bool)` (or add a sibling method), and stash the
`ClientID` on the context alongside `TokenHash`:

```go
// auth/middleware.go, around line 212:
if td, ok := store.VerifyAccessTokenData(token, requiredScope); ok {
    ctx := WithTokenHash(r.Context(), TokenHash(token))
    ctx = WithClientID(ctx, td.ClientID)  // new
    next.ServeHTTP(w, r.WithContext(ctx))
    return
}
```

**Blast radius**: any SPS service that ever wants per-tenant
partitioning. Today, zero of them do it — which is also the reason
this is LOW.

### L-2 — OAuth DB file mode inherits process umask

**file:line**: `auth/store.go:91-99` (`os.MkdirAll(dir, 0755)`,
`sql.Open("sqlite", dbPath)` without an explicit mode).

**Exploit narrative**: inside a distroless container as
`nonroot:nonroot`, the default umask is typically 022, so
`/data/oauth.db` ends up 0644. Anyone who *inherits* the container
filesystem (sidecar container, `docker cp`, volume backup) reads
the DB. Because secrets are hashed at rest (SHA-256), this does not
directly leak live tokens — but it leaks (a) which client_ids exist,
(b) issuance timestamps, (c) the hash set itself (enabling offline
brute-force against a 64-char hex token: computationally infeasible
for 32-byte secrets, so this is mostly confidentiality of metadata).

**Concrete fix**: after `sql.Open` succeeds, `os.Chmod(dbPath, 0600)`.
And tighten the parent dir to 0700.

**Blast radius**: limited by the SHA-256-at-rest design decision.
LOW is the right severity. Still worth fixing.

### L-3 — Rate-limiter memory-exhaustion cap silently bypasses limiting at saturation

**file:line**: `auth/middleware.go:44-47`: when `len(rl.attempts) >= maxIPs`
(100 000), `RecordFailure` no-ops — so the 100 001st attacker IP
**is not tracked at all**, and `IsRateLimited` for that IP returns
false until `PruneAll` runs (5-minute cycle, server.go:172).

**Exploit narrative**: an adversary that can source > 100 000
distinct IPs (botnet / residential proxy vendor) can fill the map
once, then each unique new IP gets a free attempt per 5-minute
window — roughly 100k attempts per 5 minutes before the pruner
catches up. At 5/15min per *remembered* IP, one IP's worth of PIN
attempts is trivial; at 100k free IPs every 5 min, a 6-digit PIN
falls in minutes.

**Concrete fix**: when at cap, *deny* (fail-closed) rather than no-op:

```go
// auth/middleware.go RecordFailure, replace the no-op branch
if len(rl.attempts) >= rl.maxIPs {
    // Fail closed: treat as globally rate-limited.
    // Better to take a small availability hit than silently disable
    // rate limiting for the rest of the window.
    return
}
```

…and more importantly, have `IsRateLimited` return *true* when the
map is at saturation and the requesting IP is not currently tracked:

```go
func (rl *RateLimiter) IsRateLimited(ip string) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    rl.prune(ip)
    if _, tracked := rl.attempts[ip]; !tracked && len(rl.attempts) >= rl.maxIPs {
        return true  // saturation -> globally limited
    }
    return len(rl.attempts[ip]) >= rl.maxAttempts
}
```

That turns the DoS from "attacker bypasses rate limits" into
"attacker triggers a global lockout, operator sees it in logs."

**Blast radius**: every SPS service. Exploitation requires a
substantial IP pool; LOW reflects that cost floor.

---

## Clean (explicit positives — enumerated per question)

| Q | Topic | Verdict |
|---|---|---|
| 1 | Bearer constant-time compare | ✅ `SafeEqual` = SHA-256 + `subtle.ConstantTimeCompare` (`auth/oauth.go:552-556`) |
| 2 | Header-only bearer | ✅ `parseBearer` reads only `Authorization` (`auth/middleware.go:102-119`) |
| 3 | Token never logged | ✅ grep of all `log.Printf` shows no token/PIN/secret formatted into any log line |
| 4 | Empty `BEARER_TOKEN` safe | ✅ `bearerToken != "" && SafeEqual(...)` short-circuits on empty (`auth/middleware.go:206`) |
| 5 | Server start with unset env | ✅ starts; /mcp returns 401 because all three auth paths fail — fail-closed |
| 7 | DCR redirect_uri validation | ✅ `validateRedirectURI` requires https (or http-localhost), rejects fragment/query/userinfo (`auth/oauth.go:629-652`) |
| 9 | DCR rate limit | ✅ 10/3600s per IP, plus max 1000 clients hard cap (`auth/oauth.go:89`, `auth/store.go:205-207`) |
| 10 | PIN constant-time | ✅ `SafeEqual` (`auth/oauth.go:340`) |
| 11 | PIN rate-limit per-IP | ✅ 5/900s, cleared on success (`auth/oauth.go:88, 326-347`) |
| 13 | `state` required by default | ✅ rejected unless `AllowMissingState` is set (`auth/oauth.go:233-239`) |
| 14 | PKCE required + S256 only | ✅ plain rejected, missing rejected, length-capped at 128 (`auth/oauth.go:202-229`, `auth/oauth.go:466-469`) |
| 15 | Auth code single-use + TTL | ✅ Consume inside tx + DELETE, 300s TTL (`auth/store.go:324-356`) |
| 17 | `/token` client auth enforced | ✅ `VerifyClientSecret` before code exchange and before refresh (`auth/oauth.go:440, 511`) |
| 18 | Refresh rotation | ✅ Consume deletes, new pair issued (`auth/oauth.go:519-538`) |
| 19 | Access token TTL | ✅ 3600s (`auth/oauth.go:486`) |
| 21 | `code_verifier` validated | ✅ `pkceVerify`, constant-time, unconditional hash (`auth/oauth.go:571-581`) |
| 23 | Tokens hashed at rest | ✅ `hashSecret` = hex(SHA-256) — clients, codes, access, refresh all hashed (`auth/store.go:79-82`) |
| 24 | Expiry checked every request | ✅ `VerifyAccessToken` compares `expires_at`, lazily deletes (`auth/store.go:399-404`) |
| 26 | SQL parameterized | ✅ every query uses `?` placeholders; no `fmt.Sprintf` into SQL (grep confirms) |
| 27 | Auth before parsing | ✅ `BearerMiddleware` wraps the mux, runs before `TransportHandler` (`server.go:228-231`) |
| **28** | **Fail-closed on store failure** | **✅ confirmed by test — see below** |
| 29 | Generic error to unauthenticated | ✅ `{"error":"unauthorized"}` body, minimal `WWW-Authenticate` (`auth/middleware.go:124-134`) |
| 30 | Per-IP rate limiting for OAuth | ✅ PIN, register, authorize limiters; XFF canonicalized to defeat spray (`auth/oauth.go:665-716`) |
| 32 | Token hash on context | ✅ `WithTokenHash` stashes hash — consumers can session-partition (`auth/middleware.go:194-197`, `auth/context.go:20-39`) |
| 33 | Discovery lists only real endpoints | ✅ `/authorize`, `/token`, `/register` all exist (`auth/oauth.go:109-120`, `server.go:205-211`) |
| 34 | No unsafe OIDC claims | ✅ `openid-configuration` endpoint is **not mounted** — the library makes no OIDC promises |
| 35 | Startup log hygiene | ✅ PIN/token/DB path never logged at any level; only booleans ("configured: true") |
| 36 | ExternalURL warning on miss | ⚠️ warns but does not fail-fast (see M-3) |
| 37 | govulncheck baseline | ✅ no deps with known CVEs in call-graph; 7 stdlib vulns (x509/tls/net-url) fixed in 1.26.1/1.26.2 — requires toolchain bump, not code change |

### Question 28 — proof via executable test

Added `auth/failclosed_test.go` (single test, 60 lines with comments):
seeds a valid OAuth access token, calls `store.Close()` (simulating
SQLite file becoming unreachable mid-request — disk full, EIO, perm
error), then presents the valid token at `/mcp` through
`BearerMiddleware`.

Result:

```
=== RUN   TestBearerMiddlewareFailsClosedOnStoreUnreachable
2026/04/14 15:19:41 mcpserver: failed to verify access token: sql: database is closed
--- PASS: TestBearerMiddlewareFailsClosedOnStoreUnreachable (0.00s)
```

`VerifyAccessToken` returns `false` on any `sql` error
(`auth/store.go:392-398`); `BearerMiddleware` falls through all three
acceptance paths and calls `writeUnauthorized` (`auth/middleware.go:217`).
**The library fails closed** on store unavailability — verified, not
assumed.

---

## Unknowns

| Topic | What would resolve it |
|---|---|
| **Q6** — is `/register` gated by Traefik in each service? | Inspect Traefik labels per service. The library mounts `/register` unconditionally (`server.go:207`); gating is a deployment-time concern handled by each consumer's Traefik config. Every service team should confirm `/register` is public (the design) or that they've locked it (rare). |
| **Q8** — XSS on consent page via registered `client_name` | **Not applicable** as implemented — `client_name` is not rendered today (`auth/consent.go` grep: no match). See H-1: once client_name *is* rendered, all placeholders must be `html.EscapeString`'d. |
| **Q12** — PIN entropy in prod | Would need to inspect each service's env file. See M-1 — enforce at startup rather than trusting operators. |
| **Q16** — does consent show redirect_uri | **No.** Finding H-1. |
| **Q20** — is there `/revoke` | **No.** Finding M-2. |
| **Q22** — actual file mode of `/data/oauth.db` in production | `ls -la /data/oauth.db` in a running container. The code does not explicitly set 0600 — finding L-2. |
| **Q25** — SQLite timing oracle on PK lookup | Microseconds per the index structure; `VerifyClientSecret` explicitly acknowledges a residual gap. Not measurable without a stopwatch-based probe under concurrent load. Acceptable as-is given the hashed comparand is already a uniform-length 64-byte hex string. |
| **Q31** — per-client scoping of issued tokens | The library stores `ClientID` in `TokenData` but does not surface it to tool handlers. See L-1. |

---

## Summary for the operator

- **1 HIGH**: consent page does not show who the operator is consenting to (H-1). Fix is ~30 lines across `auth/consent.go` and `auth/oauth.go`.
- **4 MEDIUM**: PIN strength floor (M-1), no `/revoke` (M-2), `ExternalURL` scheme not validated (M-3), Dockerfile Go default (M-4).
- **3 LOW**: tool-handler client_id plumbing (L-1), SQLite file mode (L-2), rate-limiter saturation bypass (L-3).
- **Question 28 definitive**: the library **fails closed** on token-store unavailability. Proof is the new `auth/failclosed_test.go`.
- Everything else on the question list checks out — and nontrivially so: the constant-time comparisons, PKCE-mandatory enforcement, DCR redirect-URI validation, single-use auth-code TTL, refresh rotation, token-hashing-at-rest, and parameterized SQL are all implemented correctly.

Given prior audit rounds (v0.7.0 → v0.7.3), the substrate is in good
shape. H-1 and L-3 are the two findings most worth acting on before
the next release; the others are tractable but lower urgency.
