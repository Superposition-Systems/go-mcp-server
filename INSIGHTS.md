# Insights

---
_2026-04-04 19:49_

`★ Insight ─────────────────────────────────────`
**Why a multi-agent review team?** Each agent brings a different lens — a code reviewer catches logic bugs while a silent-failure hunter specifically targets error paths that "work" but hide problems. Running them in parallel against the same codebase mimics how a real review team operates: the auth specialist won't miss the same things as the API design reviewer. For a ~2500-line library with security-sensitive auth code, this coverage is important.
`─────────────────────────────────────────────────`
---
_2026-04-04 19:53_

`★ Insight ─────────────────────────────────────`
**The "silent error" pattern is the dominant risk here.** Most of the security issues (auth code replay, token rotation defeat, maxClients bypass) aren't traditional vulnerabilities — they're *correct code that becomes vulnerable when a database write fails silently*. This is a great example of why Go's explicit error returns need to be checked: the `_ = db.Exec(...)` pattern turns routine operational failures (disk full, lock contention) into security holes. The cascade is: disk pressure → failed DELETE → auth code not consumed → replay attack.

**The `auth_context` issue (#1) is an architectural flaw, not a bug.** It reflects a common mistake in OAuth implementations: treating browser-submitted form data as trusted after PIN validation. The PIN proves the user is present — it doesn't authenticate the *request parameters*. Server-side session storage for auth request params is the standard fix (used by most OAuth libraries).
`─────────────────────────────────────────────────`
---
_2026-04-04 19:59_

`★ Insight ─────────────────────────────────────`
**File-based parallelism:** Each agent owns a non-overlapping set of files. This avoids merge conflicts entirely — a technique borrowed from how microservice teams work. The one coupling point is `Cleanup()` signature change: the auth agent changes the return type to `error`, and the server agent updates the caller. Go's type system catches any mismatch at compile time, so this is safe to split.
`─────────────────────────────────────────────────`
---
_2026-04-04 20:02_

`★ Insight ─────────────────────────────────────`
**The auth_context fix is the most architecturally significant change.** It transforms the OAuth consent flow from a stateless (but tamperable) model to a stateful server-side session model. The `auth_requests` table acts as a short-lived session store with 10-minute TTL and single-use semantics. The browser form now only carries an opaque UUID — the actual authorization parameters (scope, redirect_uri, state, PKCE challenge) are stored server-side and can't be tampered with after the initial `GET /authorize` validation.

**The silent error cascade was the most pervasive fix.** Nearly every `db.Exec` in the auth store was upgraded from `db.Exec(...)` to `if _, err := db.Exec(...); err != nil { return ... }`. This turns what were invisible failures under disk pressure into properly surfaced errors that callers can handle.
`─────────────────────────────────────────────────`
---
_2026-04-04 20:08_

`★ Insight ─────────────────────────────────────`
**The `clientIP` fix shows a common security trade-off.** The first fix changed from "last XFF entry" to "first XFF entry" — but both are spoofable when there's no trusted proxy. The rescan correctly identified that `r.RemoteAddr` is the only value the client can't forge. The trade-off: behind a reverse proxy, `RemoteAddr` is the proxy's IP, so all clients share one rate-limit bucket. The right answer is a configurable trusted-proxy setting, but for a library shipping secure defaults, `RemoteAddr` is the safe choice. This is why security reviews need multiple passes — the first pass fixes the obvious bug, the second pass questions whether the fix itself is robust.
`─────────────────────────────────────────────────`
---
_2026-04-04 20:12_

`★ Insight ─────────────────────────────────────`
**Diminishing returns across scan rounds:** Round 1 found ~27 issues (12 critical). Round 2 found ~12 issues (3 critical). Round 3 found ~8 issues (2 critical). The critical findings are getting more subtle each round — from "SQL injection" to "expiry checked after delete on one of two consume functions." This convergence pattern is exactly what you want from iterative security review: each pass catches the issues the previous lens missed, until the remaining items are design trade-offs rather than bugs.
`─────────────────────────────────────────────────`
---
_2026-04-04 20:17_

`★ Insight ─────────────────────────────────────`
**Go module versioning as deployment:** For Go libraries, pushing a semver tag IS the release. The Go module proxy (`proxy.golang.org`) will automatically cache and serve `v0.2.0` once any consumer requests it. There's no build/deploy pipeline needed — the tag is the artifact. The `v0.2.0` bump (minor, not patch) signals to consumers that there are new features (like `WithOAuthDBPath`) alongside the security fixes.
`─────────────────────────────────────────────────`
---
_2026-04-13 21:22_

`★ Insight ─────────────────────────────────────`
- **`http.MaxBytesReader` vs just limiting at the reverse proxy**: Defense in depth matters. Even behind Traefik, the Go server should enforce its own limits — proxies can be bypassed, misconfigured, or removed. The `MaxBytesReader` approach also returns a proper 413 status automatically.
- **OAuth metadata from request headers is a classic footgun**: RFC 8414 discovery docs are cached by clients. If an attacker can poison the `issuer` field once, the victim client may trust the attacker's authorization server for the lifetime of the cache. This is why production OAuth servers should always use a hardcoded base URL.
- **Rate limiters that check but never record**: This is a subtle bug pattern — the code *looks* protected because `IsRateLimited()` is called, but the state machine is never advanced. Code review should always trace the full lifecycle of stateful checks.
`─────────────────────────────────────────────────`
---
_2026-04-13 21:37_

`★ Insight ─────────────────────────────────────`
- **Threat model matters**: A server with one trusted client (claude.ai) has a very different attack surface than a public OAuth provider. The DoS vectors are still real because they target the *transport layer*, not the *OAuth flow*. But the OAuth-specific attacks (redirect manipulation, metadata poisoning) require a malicious client that doesn't exist in your setup.
- **Defense in depth still applies**: Even with Traefik in front, adding `http.MaxBytesReader` and server timeouts is cheap insurance — Traefik config can drift, and these are one-liners in Go.
`─────────────────────────────────────────────────`
---
_2026-04-13 21:41_

`★ Insight ─────────────────────────────────────`
- **`WriteTimeout` is set to `s.timeout + 10s`** because MCP tool calls can legitimately take up to `s.timeout` (default 120s) to execute. The extra 10 seconds gives headroom for serialization and network flushing. If `WriteTimeout` were shorter than `s.timeout`, long-running tool calls would get killed mid-response.
- **The redirect URI validation allows `127.0.0.1` and `::1` alongside `localhost`** — this matters for OAuth clients that bind to IP literals rather than hostnames during local development (common with CLI tools like claude.ai's desktop app).
- **The rate limiter fix counts *all* registration attempts, not just failures** — this is intentional. Registration is a heavyweight operation (creates a DB row, generates secrets), so even successful requests should be metered to prevent resource exhaustion from a flood of valid registrations.
`─────────────────────────────────────────────────`
---
_2026-04-13 22:11_

`★ Insight ─────────────────────────────────────`
**Why these matter together:** Issues 1, 2, and 3 all stem from the same architectural pattern — using a Go mutex as the sole concurrency guard over a SQL database, without SQL-level transactions. This is fragile because: (a) Go mutexes don't protect against connection-pool interleaving in `database/sql`, (b) they're easy to accidentally omit (as in issue 1), and (c) they don't survive refactoring to multi-process deployments. The fix for all three is to push atomicity guarantees down to the database layer with proper transactions, and treat the mutex as a secondary safety net.
`─────────────────────────────────────────────────`
---
_2026-04-13 22:15_

`★ Insight ─────────────────────────────────────`
**Fix #5 tradeoff:** Rather than making `ExternalURL` a hard requirement (which would break the zero-config local dev experience), the fix pins the fallback to `http://localhost`. This means a production deployment without `ExternalURL` will emit broken OAuth discovery URLs that point to localhost — which is a loud, obvious failure rather than a silent, exploitable one. The warning log makes it easy to diagnose.
`─────────────────────────────────────────────────`
---
_2026-04-13 22:22_

`★ Insight ─────────────────────────────────────`
This is a common Go/SQLite pitfall. `database/sql` abstracts a connection pool — raw `BEGIN`/`COMMIT` statements via `db.Exec` are "fire and forget" on arbitrary connections. Only `db.BeginTx()` returns a `*sql.Tx` that guarantees all operations share one connection. Additionally, setting `db.SetMaxOpenConns(1)` is best practice for SQLite since it only supports one writer.
`─────────────────────────────────────────────────`
---
_2026-04-13 22:26_

`★ Insight ─────────────────────────────────────`
**The redirect_uri fixes (#1 and #2) are the most impactful.** Together they close a classic OAuth authorization code interception attack. Without #1, an attacker crafts a phishing link with a malicious `redirect_uri` and a valid `client_id` — the user sees a legitimate-looking consent page. Without #2, even if the code leaks via a Referer header, anyone can exchange it. These two checks are independent defense layers that RFC 6749 requires precisely because either one alone can be bypassed under certain conditions.
`─────────────────────────────────────────────────`
---
_2026-04-13 22:33_

`★ Insight ─────────────────────────────────────`
**Scope enforcement is a common OAuth blind spot.** Many implementations store the scope at issuance time but never check it during token verification — the column exists for audit/logging but doesn't actually gate access. This is particularly deceptive because the OAuth discovery document advertises `scopes_supported`, leading clients to believe scope restrictions are meaningful. The fix adds enforcement at the middleware layer, which is where it belongs — the store verifies the token carries the right scope, and the middleware decides what scope to require.
`─────────────────────────────────────────────────`
---
_2026-04-14 09:37_

`★ Insight ─────────────────────────────────────`
- Three agents independently flagged the same scope-equality bug (`store.go:323`), and two flagged the plaintext-token/timing issue. Cross-confirmation across agents with different primary focus is strong evidence these are real — contrast with a finding only one agent saw, which deserves more skepticism.
- The elevation agent caught the most alarming finding (dead `IsElevated` context flag + bootstrap race) — a reminder that newest code, no matter how carefully written, needs the most scrutiny.
`─────────────────────────────────────────────────`
---
_2026-04-14 09:50_

`★ Insight ─────────────────────────────────────`
- **The audit was wrong about M7 (go.mod).** The agent claimed Go 1.25 didn't exist; the user's environment has Go 1.26. `go mod tidy` reverted the change. A good reminder that audit findings need a sanity check against the running environment before applying — rubber-stamping every finding can introduce bugs.
- **Hashing tokens at the store layer was transparent to most callers** because the existing API already took the raw token in/out; only the one-line SQL lookup needed to wrap with `hashSecret()`. The only breaking API was `ConsumeRefreshToken` (needed a new `expectedClientID` parameter for M2). When a security fix requires a breaking change, bundling it with the closest-in-spirit change (token binding + token storage) is a nicer upgrade story than shipping two separate breaks.
- **The bootstrap-token design** generates the token at `NewPasswordStore` time and logs it via `LogBootstrapBanner`, not at every IsSet check — so it survives across all paths to set_elevation_password and clears itself atomically on success. This is strictly better than the audit's "authenticate bootstrap caller by static bearer" suggestion, which would have coupled elevation to transport auth.
`─────────────────────────────────────────────────`
---
_2026-04-14 09:56_

`★ Insight ─────────────────────────────────────`
- Cross-agent confirmation again proves useful: the regression-hunter and the deep-safety agent both flagged `SafeEqual`-related misuse (regression M4-r + deep H1-d), and the deep agent correctly identified the timing-oracle corollary — `VerifyClientSecret` skips the hash entirely when the `client_id` is unknown, enabling client-ID enumeration via timing. That's the sharpest new finding.
- Several items that sound scary (M4-r "expired refresh tokens deleted before check", M3-d "120s post-revocation window") turned out to be pre-existing design decisions, not regressions. Second-pass audits need to distinguish "new problem from the fix" vs "unchanged behavior the first audit didn't highlight."
- The unaudited-surface agent found genuine fresh issues by looking OUTSIDE the auth package: graceful-shutdown goroutine leak, `req.ID` unbounded echo in JSON-RPC. First-pass audits had zero coverage on the transport's JSON parsing depth.
`─────────────────────────────────────────────────`
---
_2026-04-14 10:04_

`★ Insight ─────────────────────────────────────`
- The **timing oracle fix on `VerifyClientSecret`** is the one worth remembering. The pattern "DB miss fast-returns, hit runs crypto" is almost universal in auth code and it's a real enumeration vector when timed over many requests (~µs difference per call, trivially measurable on a LAN). The general cure is "always do the crypto, then compare" — a discipline every auth primitive should enforce.
- The **elevationTools `ListTools()` per-dispatch probe** had a subtle TOCTOU bug I missed in v0.7.0: if the user's `ListTools` returned one set at probe time and the `Call` routed to `e.inner.Call` on a name that no longer existed, we'd get an application "unknown tool" error while the library's shadow tool stayed silent. Precomputing at wrap time is strictly better — user shadowing is a construction-time decision, not a per-request one.
- Most interesting pattern across both audit rounds: **second-pass found the bugs that first-pass created.** `parseBearer`'s `TrimSpace` (my fix for L2 in v0.7.0) accidentally accepted multi-space; `VerifyClientSecret`'s use of `SafeEqual` (helpful-looking) introduced the timing oracle because I didn't notice the DB-miss fast path. Fixes are themselves code and need their own review.
`─────────────────────────────────────────────────`
---
_2026-04-14 10:14_

`★ Insight ─────────────────────────────────────`
- The red-team agent's methodology (attacker-goal-first) found the **best real finding of this round**: the `http://localhost` fallback in `baseURLFromConfig`. Under a misconfigured deployment, the server's OAuth discovery metadata advertises `http://localhost/authorize` to real clients — silently bricking the flow and sending authorization requests to localhost. The first two audit rounds missed this because they looked at `baseURLFromConfig` for timing/CRLF issues, not for "what does this actually return under misconfiguration?"
- The concurrent-load agent inflated some findings (rating `s.mu` bottleneck as "Critical" when `SetMaxOpenConns(1)` makes the mutex almost redundant at the DB level), but its H1 (RateLimiter has no background pruning) is genuine and none of the prior rounds caught it.
- Docstring-drift turned up a **real fix buried in a compliment**: my v0.7.1 `VerifyClientSecret` timing fix uses `ConstantTimeCompare(presented, presented)` on the miss path — comparing a value to itself. A sufficiently smart compiler can optimize self-compare to a trivial true, defeating the timing equalization. Should compare against a fixed dummy hash instead.
`─────────────────────────────────────────────────`
---
_2026-04-14 10:21_

`★ Insight ─────────────────────────────────────`
- The **500-on-discovery change (A2)** is the most interesting one here. It's a behavioral change with the potential to be "breaking" — but the old behavior was actively harmful (silently broken production flows with a single log line) while the new behavior is noisily broken (clear HTTP 500 with an error description). Noisily-broken is almost always better than silently-broken for deployment bugs: the operator fixes it once and it's done, vs debugging why OAuth clients can't complete the flow.
- **A5's batched cleanup pattern** (`DELETE ... rowid IN (SELECT rowid ... LIMIT N)` with lock release between batches) is a generally useful pattern for any "serialized-mutex + unbounded-delete" code. Plus the new indexes: without them the inner `SELECT` is still a table scan, so both fixes need to land together or neither really helps.
- Adding explicit `panic()` recovery to long-lived goroutines like the cleanup ticker is cheap insurance. The stdlib HTTP server recovers per-request panics; anything you `go func()` yourself is on its own, and one unrecovered panic kills the process. Worth auditing any long-lived goroutine in any codebase.
`─────────────────────────────────────────────────`
---
_2026-04-14 10:28_

`★ Insight ─────────────────────────────────────`
- **The PR-review agent's "critical" findings on `ConsumeAuthCode` and `ConsumeRefreshToken` are false positives.** The agent read "delete before checking expiry" as a regression, but the behavior is intentional: **a single-use credential that got presented and is expired MUST be deleted** — otherwise replay protection breaks. If an expired auth code were preserved for retry, it would be reusable indefinitely until cleanup. Deletion of an expired code with an error return is correct. Agents will sometimes find things that LOOK LIKE bugs because they match a bug pattern without checking the invariant the pattern is meant to protect.
- **Same flavor of misread on the "scope newline" finding** (fuzz #4) — agent suggested newlines in a client's registered scope could bypass validation, but client-registered scope isn't consulted at authorize time; only `h.config.Scope` is. Dead end.
- **Both length-mismatch findings from fuzzing and crypto converged on the same real issue** (pkceVerify). Two independent agents flagging the same thing is strong signal — worth fixing.
- **The cleanest finding of round 4** is the XFF canonicalization gap — both fuzz#3 and PR#3 hit it independently. When a trusted proxy is configured, the left-most XFF entry is treated as a rate-limit key without parsing. An attacker behind the proxy can spray synthetic values to fill the limiter's 100k cap and defeat per-IP limiting.
`─────────────────────────────────────────────────`
---
_2026-04-14 10:35_

`★ Insight ─────────────────────────────────────`
- **The best fix of this round (R1) came from a convergent finding**: the fuzzing agent and the PR-review agent independently flagged unvalidated `X-Forwarded-For` as a real issue. Convergence across methodologies is the strongest possible signal that a finding is real. Contrast with the two "critical" PR-review findings (ConsumeAuthCode / ConsumeRefreshToken) that came from one agent, one methodology, and turned out to be misreads.
- **R2's pkceVerify length guard** is an instructive example of constant-time in practice. `subtle.ConstantTimeCompare` is only constant-time when inputs are equal-length — otherwise it short-circuits. Putting an explicit length check AFTER the verifier-side hash preserves the desired timing property on the verifier (the expensive secret-dependent work) while making the post-hash comparison's behavior explicit and clear.
- **Yield per round**: 17 → 16 → 12 → 7 (real items, 5-round smoothed). False-positive rate shot from ~0% in round 1 to ~40% in round 4. These are the classic signs of a maturing audit converging on actual code quality. **Recommend stopping here**; the next round would likely produce 1-3 real items and lots of noise, with diminishing marginal value.
`─────────────────────────────────────────────────`
---
_2026-04-14 15:23_

`★ Insight ─────────────────────────────────────`
Two things made this audit efficient: (1) auth is consolidated in a single package (`auth/`) with clean responsibility split — middleware/oauth/store/context — so I could read ~2000 LOC and have the complete surface. (2) Prior rounds had already fixed the common footguns (constant-time compares, hashed-at-rest, PKCE-mandatory, XFF canonicalization). The remaining findings cluster around *operator-facing affordances* (showing the user what they're consenting to, warning on weak PINs, revocation) rather than crypto primitives — a sign the substrate has matured.
`─────────────────────────────────────────────────`
---
_2026-04-14 15:38_

`★ Insight ─────────────────────────────────────`
I chose a struct (`PINPageData`) over a longer positional signature because the error paths don't know the client identity yet — passing six positional args with three empty strings every time would be ugly and error-prone. The helper method `h.renderPINErr` shrank ~20 call sites to one-liners and made the happy path the obviously-distinct one (it's the only site that builds a full `PINPageData`). The redirect host shown on the page is the *validated* registered value, not the raw query param, which matters: an attacker can't inject a fake-looking host via the URL because the comparison against `client.RedirectURIs` runs first.
`─────────────────────────────────────────────────`
---
_2026-04-14 16:00_

`★ Insight ─────────────────────────────────────`
The two thresholds (6 = hard refuse, 8 = soft warn) are deliberately asymmetric. Refusing at <6 stops the obvious 4-digit PIN footgun dead — no operator can accidentally ship it. The 6–7 char band warns but doesn't block, because in that band a *random* mixed-case alphanumeric PIN is still ~36 bits (strong enough against rate-limited attacks), while a 6-digit numeric PIN is only 20 bits. The library can't distinguish those at startup, so it errs on the warning side rather than rejecting legitimate-but-short-ish PINs. The empty-PIN case is untouched — static-bearer-only deployments are a legitimate mode already covered by an existing warning banner.
`─────────────────────────────────────────────────`
---
_2026-04-14 16:03_

`★ Insight ─────────────────────────────────────`
Two non-obvious design calls here worth flagging: (1) I deviated from RFC 7009 on store-failure handling — the RFC says respond 200 on any non-client-auth failure to avoid token probing, but I return 503 because a "successful" revocation that didn't actually delete anything is the exact failure mode the endpoint exists to prevent. A loud 503 tells the operator "try again or go do manual SQL" whereas a quiet 200 hides the problem. (2) The cross-client test (`TestRevokeCannotTouchOtherClientsTokens`) is the interesting security test: without the `AND client_id = ?` predicate in the SQL, one DCR'd client could revoke another's tokens. The test proves both that the predicate works *and* that the response is indistinguishable from a successful revoke (so an attacker can't probe which client a token belongs to by flipping client_ids).
`─────────────────────────────────────────────────`
---
_2026-04-14 16:06_

`★ Insight ─────────────────────────────────────`
Subtle detail: the `u.Host == ""` check catches a class of URL typos that `url.Parse` would otherwise accept — e.g., `"https:/example.com"` (one slash) parses with no error and an empty Host. Without that check, we'd accept a malformed URL and emit broken discovery metadata anyway. Also, I deliberately check `u.Scheme != "https"` before the `http + loopback` allowance so that an empty scheme (e.g., `"localhost:8080"` as a value) fails loudly instead of being silently promoted to http-localhost.
`─────────────────────────────────────────────────`
---
_2026-04-14 16:08_

`★ Insight ─────────────────────────────────────`
The other test (`TestGenerateDockerfileCustom` at line 91) was left as-is — it explicitly passes `GoVersion: "1.24"` to exercise the *override* path, which is what it's testing. That test isn't about the default; it's about "does a caller-supplied version flow through correctly?" Changing it would have reduced coverage of the override path for no reason. The default-version test was the only one that needed updating.
`─────────────────────────────────────────────────`
---
_2026-04-14 16:12_

`★ Insight ─────────────────────────────────────`
The first attempt failed because SQLite creates the DB file **lazily** — `sql.Open` only validates the DSN, the actual file appears when the first query runs. This is a classic gotcha that also explains why you sometimes see empty DB paths "work" silently in integration tests that never execute a query. The fix was to move the chmod after `createTables()`, which guarantees the file exists. The WAL and SHM sidecar files appear after the `journal_mode=WAL` PRAGMA, but they're ephemeral — best-effort chmod is fine because the 0700 directory mode is the real access barrier; the file chmods are belt-and-suspenders for volume-copy / bind-mount scenarios.
`─────────────────────────────────────────────────`
---
_2026-04-14 16:14_

`★ Insight ─────────────────────────────────────`
The subtle asymmetry worth pointing out: the fix changes behavior for *untracked* IPs at saturation but leaves *tracked* IPs untouched. A legitimate user whose IP is already in the map stays within their normal per-IP budget during an attack. Only fresh IPs get rejected. That minimizes legitimate-user impact of the fail-closed mode — a valid operator who authenticated before the attack began isn't locked out. Also, I didn't change `RecordFailure`'s no-op behavior at cap because doing so would invert the relationship: if we *did* start adding IPs past the cap, we'd need a full eviction strategy. Keeping RecordFailure as a no-op while IsRateLimited fail-closes is the minimum-change fix that solves the attack.
`─────────────────────────────────────────────────`
---
_2026-04-14 22:36_

`★ Insight ─────────────────────────────────────`
The Node server is a case study in accretion: every feature lives *inside* the `atlassian_execute` tool handler in `mux-tools.mjs` because the Node MCP SDK, like the current Go one, has no middleware seam. Lines 619–692 of that file are a 70-line inlined pipeline — alias resolution → validation → dispatch → compaction → logging. The Go v0.8.0 plan is essentially "extract each stripe of that sandwich into a composable middleware."
`─────────────────────────────────────────────────`

`★ Insight ─────────────────────────────────────`
The plan's § 3.3 (split `err` from `isError`) is the most important design decision — Node paid for conflating them via brittle magic strings. Separately, watch § 9 open question #2: elevation is currently an *HTTP-layer* middleware, so per-tool elevation (e.g. `config_set` requires PIN) needs a `Tag` convention like `"requiresElevation"` that a built-in middleware enforces. The Node server has the same concept wired ad-hoc inside each mutating tool — the Go registry's `Tags []string` is the cleaner place to land it.
`─────────────────────────────────────────────────`
---
_2026-04-14 22:46_

`★ Insight ─────────────────────────────────────`
The tradeoff is "simple code, easy to get wrong" vs "clever code, always in sync." The Node server has the first problem — I've seen the schemas and docstrings disagree multiple times in that codebase. But JSON Schema has `$ref`, `oneOf`, and `allOf`, which make "just pull out the names" trickier than it sounds. Worth a decision before we ship.
`─────────────────────────────────────────────────`
---
_2026-04-15 09:08_

`★ Insight ─────────────────────────────────────`
The schema-parse choice quietly deletes a future drift problem. The Node server has two places that describe each tool's parameters (the JS builder's `.parameters` metadata and the Zod schema in `index.js`) and they visibly diverge over time. By making the Go library parse the *validation* schema to produce the *display* signature, you get single-source-of-truth forever — at the cost of a ~30 LOC JSON walk we'd have written anyway for the validator.
`─────────────────────────────────────────────────`
---
_2026-04-15 09:16_

`★ Insight ─────────────────────────────────────`
Two conflict sources dominate Go feature parallelism: centralised options structs and the transport-layer hot path. Handling both in Phase 0 — freeze every option signature upfront, declare every field on `Server`, pre-allocate the middleware insertion point — lets six agents work on six subpackages without ever touching each other's branches. The phased gates then exist only where real semantic dependencies live (Mux needs a suggester; validator needs a schema parser), not where file layout artificially couples things.
`─────────────────────────────────────────────────`
---
_2026-04-15 09:22_

`★ Insight ─────────────────────────────────────`
Option 1 is the quiet winner. The reason it works is that most of what Phase 1/2 tracks do is *add behavior* (thread-safety, duplicate-name detection, error-category contract, category grouping) on top of an interface that's already correct. A registry that's a `map[string]Tool` protected by a mutex is 10 LOC and passes half the Phase 1A tests out of the box; Phase 1A's job becomes "make the other half pass," not "write the thing."
`─────────────────────────────────────────────────`
---
_2026-04-15 09:36_

`★ Insight ─────────────────────────────────────`
The reason this works is that most "real" behavior in each track is additive to a correct minimal impl. A Registry that's a mutex-protected map already satisfies `Register`/`Lookup`/`All`/`AsToolHandler` — Session 1's job on track 1A is to bolt on stable sort, duplicate detection, and the start-gate guard. Each of those is a single PR that replaces a few lines; none of them break the compile for other sessions depending on Registry. Same pattern for every other track.
`─────────────────────────────────────────────────`
---
_2026-04-15 10:09_

`★ Insight ─────────────────────────────────────`
- Using worktree isolation for parallel sub-agents gives each one its own filesystem view — no cross-agent contamination of `go test` state, no git-index races. Each returns a branch + PR for me to review before merging to master.
- 3A is deliberately deferred: the plan says it can develop against Phase 0's empty `ExtractParams`, but its happy-path tests need real canonical-name lookup to verify alias→canonical rewrites and collision detection. Spawning it after 2C lets us write tighter tests immediately rather than loosening them and revisiting.
- The "no other session touches transport.go" rule means our three files (registry, schema, aliases) all stop short of wiring themselves into the request path — Session 2's track 1B owns the integration seam. We only expose correct public APIs; the chain wiring happens elsewhere.
`─────────────────────────────────────────────────`
---
_2026-04-15 10:12_

`★ Insight ─────────────────────────────────────`
- **Worktree isolation as merge insurance**: Each sub-agent gets its own git worktree, so file-ownership discipline (§8.3) is enforced by filesystem, not willpower. Track 4B can't accidentally edit `webhook/webhook.go` because it's on a different branch. This is the mechanical backstop for the human coordination rule.
- **`t.Skip` as a living todo list**: Track 4B's composition test writes the assertions as they'd look against production code, then annotates subtests that depend on not-yet-merged tracks with `t.Skip("tightens after track XX merges")`. The Skip messages double as a merge checklist — when Session 1's alias middleware lands, you grep for `Skip.*3A` and delete those lines one by one. Tests become the source of truth for "what still needs to land," which is exactly how Phase 0 scaffolding was designed to be consumed.
- **Subtest ordering matters in integration tests**: I asked 4B to run subtest (6) — the webhook HMAC one — first, because it depends only on sibling track 2D. If 2D merges and (6) goes green, that's the first tangible proof that Session 4's output composes with the rest of the server. The other five subtests come online as upstream sessions merge.
`─────────────────────────────────────────────────`
---
_2026-04-15 10:23_

`★ Insight ─────────────────────────────────────`
- The stacked-PR pattern worked cleanly here: 3A's PR shows "Phase 0 + 2C + 3A" commits against unpushed master, but GitHub auto-narrows the diff as upstream PRs merge — no rebasing dance needed, no coordination overhead between sub-agents.
- The §3.9 design decision (aliases as their own middleware, not a validator quirk) paid off during 3A's implementation: the constructor takes `*Registry` + `suggest.Hook` as explicit params rather than pulling from Server state, which made the test surface tiny — the middleware is fully exercised without any HTTP/Server plumbing.
- Full `-race` integration pass across test-merges of 1A+2C+3A without a single conflict confirms the "one track = one file set" discipline held end-to-end. This is exactly what §8.3's file-ownership rule is designed to deliver.
`─────────────────────────────────────────────────`
---
_2026-04-15 10:48_

`★ Insight ─────────────────────────────────────`
Every integration issue was at a *hand-off boundary* between sessions — signature changes, semantic assumptions (duplicate registration allowed?), and a layering question (outer chain vs. mux-internal dispatch). The minimal-working Phase 0 approach caught zero of these at compile time because each session's changes compiled against its own local expectations. This is where a post-merge integration pass earns its keep — the phased plan assumed this work would exist, it just lives here rather than inside any single session.
`─────────────────────────────────────────────────`
---
_2026-04-15 11:06_

`★ Insight ─────────────────────────────────────`
C-1 is a classic "track-handoff" bug: the v0.8.0 work was split across parallel tracks (1A/1B/2A–F/3A/3B/4A/4B), and the validator's own comment anticipated this exact wiring step. Parallel merges are fast but the integration seam — "who actually calls `buildValidationMiddleware`?" — was nobody's track. The six-point composition_test.go was supposed to catch this but asserts wiring, not rejection, so the stub slipped through green tests.
`─────────────────────────────────────────────────`
---
_2026-04-15 11:49_

`★ Insight ─────────────────────────────────────`
The M-C fix is worth a second look from a design angle: Go's stack overflow is a *fatal* runtime error, not a recoverable panic, so the idiomatic "defer recover()" guard you might reach for from Node/Python muscle memory does nothing here. The only way to avoid it is to count at the recursion site itself. This is a recurring gotcha for teams coming from stacks with unlimited or recoverable stacks — worth knowing before you hit the crash in production.
`─────────────────────────────────────────────────`
---
_2026-04-15 12:04_

`★ Insight ─────────────────────────────────────`
C (the notification fix) is a great illustration of why "spec compliance" and "client compat" sometimes pull in different directions. The right spec fix is "absent id = no reply, always." But MCP clients in the wild send `notifications/initialized` with an id because the method name has "notifications/" in it and they assume that's enough. Keeping the whitelist as a compat pragma alongside the correct §4.1 rule gives you both: strict spec behaviour for new clients, graceful tolerance for legacy ones. The comment at that site flags it as a pragma so future maintainers don't silently "clean up" the whitelist and break real clients.
`─────────────────────────────────────────────────`
---
_2026-04-15 12:27_

`★ Insight ─────────────────────────────────────`
The skill.go sanitiser is worth a note on *threat model surface shift*. The library's original trust model was "registered tools are trusted code" — which is true when you hand-write `reg.Register(...)`. But the moment a consumer wires a mux around a 3rd-party API whose tool names come from that API (GitHub's GraphQL schema, Atlassian's REST catalogue), tool metadata is no longer fully consumer-controlled. The sanitiser moves the library's trust boundary from "all registered strings are safe" to "all registered strings are rendered safely." Small scope change, meaningful blast-radius reduction.
`─────────────────────────────────────────────────`
---
_2026-04-15 12:49_

`★ Insight ─────────────────────────────────────`
- The mux is itself just a `*Registry` — `NewMux` at `mux.go:77` returns a *fresh* registry populated with 4 synthesized dispatcher tools whose handlers close over the underlying registry. So "bypass the mux" isn't a special mode; it's just "don't call `NewMux`."
- The sealing cascade (`registry.go:173`) is the one subtle coupling: when the mux wraps an underlying registry, `markStarted` walks `parent` so sealing the outer seals the inner. Direct-registry consumers skip this entirely — only their own registry gets sealed on `ListenAndServe`.
- Middleware (aliases, validation, compaction) lives on the `Server`, not the `Registry`, which is why it works uniformly on both paths. The mux's *internal* alias rewriter at `mux.go:195` exists only because outer-chain middleware can't see the nested `args` payload that `<prefix>_execute` unwraps — a detail that vanishes when you bypass the mux.
`─────────────────────────────────────────────────`
---
_2026-04-15 12:50_

`★ Insight ─────────────────────────────────────`
- The three channels have different failure modes. `CLAUDE.md` is read by every session in the repo — including sessions run by collaborators — so it's the right place for *shared* architectural invariants. Memory is yours alone; it travels with your machine, not the repo. `INSIGHTS.md` is a timeline, so entries decay in relevance and readers don't treat old ones as load-bearing.
- For the specific class of fact "X is already supported, don't rebuild it," `CLAUDE.md` wins decisively — the failure mode you're preventing (an agent reinventing the direct-exposure path) is exactly what a session-start preamble catches. A memory entry would protect future *you*, but not a collaborator's session or a fresh clone.
- One tradeoff: `CLAUDE.md` becomes a budget-consumed context cost on every session in this repo, so it should stay tight — a one-liner pointing at `README.md:321-355` is better than a duplicated explanation.
`─────────────────────────────────────────────────`
---
_2026-04-17 16:04_

`★ Insight ─────────────────────────────────────`
- The `SELECT *` + positional `Scan` in `GetClient` at `auth/store.go:275-283` is coupled to the exact column order in `createTables`. As soon as a future schema change adds or reorders a column, `Scan` reads `client_secret` (or some other TEXT) into `ClientIDIssuedAt` (INTEGER), returning a scan error — which `oauth.go:262` then displays to end users as "Unknown client_id." That's three bugs chained: schema fragility → silent scan error → misleading user message.
- Adding a `schema_version` table is the standard idiom, but for a library shipping across multiple consumer databases, the migration logic has to be idempotent AND detect "table already has the new columns from an ad-hoc manual migration" — otherwise you brick a database on restart. A safer v1 is to only *record* the version (no migrations yet) so future versions have a checkpoint to migrate FROM.
- For the middleware-validation-path signal, the cleanest Go idiom is a typed context value (not a stringly-typed tag) so callers get compile-time safety. The existing `tokenHashKeyType struct{}` pattern in `auth/context.go:10` is the template to mirror.
`─────────────────────────────────────────────────`
---
_2026-04-17 16:08_

`★ Insight ─────────────────────────────────────`
- The `schema_version` table uses `CREATE TABLE IF NOT EXISTS` + a separate seed-if-empty check rather than `INSERT OR IGNORE` with a hardcoded primary key. The reason: future migrations will need to UPDATE the row, and having a PK means picking a magic value (always id=1?) that leaks into migration SQL. A single-row table with no PK is uglier but carries no embedded assumption future code has to honor.
- The authorize-POST `GetClient` log keeps `sql.ErrNoRows` (unlike authorize-GET) because at that point the client_id came from `auth_requests` — a table we just wrote 10s ago. "Row disappeared" there means either someone is racing deletion or the DB is unhappy, both of which operators want to see.
- `AuthPath` is a named `string` type, not a raw `string`. This gives callers a compile-time error if they pass a typo'd literal into `GetAuthPath`'s comparand — the common footgun when context values are stringly-typed.
`─────────────────────────────────────────────────`
