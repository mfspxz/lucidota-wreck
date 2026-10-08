# Artifacts Adapter Spec — wreck substrate port

**Date:** 2026-10-08 · **Source:** official Cloudflare docs (verified 2026-10-08) unless marked [3P].
**Purpose:** implementation-ready reference for the Artifacts `MergePort`/adapter.
No implementation code here — endpoints, shapes, semantics, gotchas only.

Conventions: `$AID` = account ID, `$NS` = namespace (e.g. `wreck`), `$CF` = API token
with **Artifacts Read + Artifacts Edit** permissions.

---

## 0. Base URLs & auth planes

Three planes, three credentials. Never mix them.

| Plane | Base | Auth |
|---|---|---|
| REST control plane | `https://api.cloudflare.com/client/v4/accounts/$AID/artifacts/namespaces/$NS` | `Authorization: Bearer $CF` (API token) |
| Account-level REST | `https://api.cloudflare.com/client/v4/accounts/$AID/artifacts` | same |
| Git data plane | `https://$AID.artifacts.cloudflare.net/git/$NS/$REPO.git` | repo-scoped `art_v1_…` token (see §5) |
| Workers binding | `env.ARTIFACTS` (bound to one namespace) | none (platform identity) |

All REST JSON responses use the standard v4 envelope:
`{ result, success, errors[], messages[], result_info? }`.
Blob/file/raw routes return raw bytes instead of JSON; errors still use the envelope.

---

## 1. Namespaces & jurisdiction

- `POST /accounts/$AID/artifacts/namespaces` — body `{ "namespace": $NS, "jurisdiction"? }`.
  `jurisdiction`: `"us" | "eu"`; omitted = unrestricted. **Immutable after creation.**
- `GET /accounts/$AID/artifacts/namespaces?limit=&cursor=`
- `GET /accounts/$AID/artifacts/namespaces/$NS`
- Wrangler: `wrangler artifacts namespaces list|get <NAME> [--json]`
- Names: 2–63 chars; start with letter/digit; rest `[A-Za-z0-9._-]` (repos: same charset rule).
- Namespace = control-plane rate-limit boundary.

**Adapter choice:** namespace `wreck`, jurisdiction `us` (or omit). One-time setup.

---

## 2. Repos

### REST
- `POST $BASE/repos` — body `{ name*, description?, default_branch?, read_only? }`.
  → `result: { id, name, description, default_branch, remote, token }`.
  `remote` = git URL. `token` = initial repo token **shown once**.
- `GET $BASE/repos?limit=&cursor=&search=&sort=&direction=` (limit default 50, max 200; sort: created_at|updated_at|last_push_at|name)
- `GET $BASE/repos/:name` → `{ id, name, description, default_branch, created_at, updated_at, last_push_at, source, read_only, remote }`
- `DELETE $BASE/repos/:name` → **202 Accepted**, `result: { id }` (async delete).

### Binding (`env.ARTIFACTS`, namespace-scoped)
- `create(name, opts?)` → `{ name, remote, defaultBranch, token }`; opts `{ readOnly?, description?, setDefaultBranch? }`
- `get(name)` → disposable `ArtifactsRepo` handle. **Throws if missing or not ready.**
- `list(opts?)` → `{ repos: [{ name, status }], cursor? }`; status `ready|importing|forking`
- `import({ source: { url*, branch?, depth? }, target: { name*, opts? } })`
- `delete(name)` → `boolean`

### Wrangler
- `wrangler artifacts repos create <NAME> --namespace $NS [--description] [--default-branch] [--read-only] [--json]`
- `wrangler artifacts repos list --namespace $NS [--json]`
- `wrangler artifacts repos get <NAME> --namespace $NS [--json]`
- `wrangler artifacts repos delete <NAME> --namespace $NS [--force] [--json]`

**Gotcha:** after create/fork, the repo may be `importing`/`forking`; `get()` throws until `ready`.
Poll `list()` and check `status === "ready"` before minting tokens or reading.

---

## 3. Fork

- `POST $BASE/repos/:name/fork` — body `{ name*, description?, read_only?, default_branch_only? }`.
  → `CreateRepoResult` + `objects: number` (server-side fast fork, no clone-push).
- Binding: `repo.fork(name, { description?, readOnly?, defaultBranchOnly? })` → same result shape.
- 409 Conflict if the repo is still importing/forking — **retriable**, back off and retry.
- Fork = **independent repo** (own tokens, routing, lifecycle), not a branch pointer.

**Adapter choice:** `default_branch_only: true` for agent workspaces (smaller, faster).

---

## 4. Repo content reads (review loop)

### REST
- `GET $BASE/repos/:name/log?ref=&limit=&offset=` — commit history
- `GET $BASE/repos/:name/commit/:hash` — commit metadata
- `GET $BASE/repos/:name/tree/:hash` — tree entries (immediate children)
- `GET $BASE/repos/:name/blob/:hash` — raw blob bytes
- `GET $BASE/repos/:name/file?ref=&path=` — raw file bytes, `application/octet-stream`
- `GET $BASE/repos/:name/raw/:ref/:path` — file bytes, sniffed Content-Type

### Binding (repo handle)
- `info()` → fresh repo metadata (throws `NOT_FOUND` if deleted)
- `log({ ref? = "HEAD", limit? = 50 (max 1000), offset? = 0 })` → commit metadata[], **first-parent chain only**, newest-first; `[]` if ref unresolvable
- `readCommit(hash)` → metadata | `null`
- `readTree(hash)` → entries[] | `null` (immediate children only)
- `readBlob(hash)` → untyped `Blob` | `null` (hash must be lowercase 40-hex)
- `readFile({ ref*, path* })` → MIME-typed `Blob` | `null` (null if missing or is a dir; throws `INVALID_INPUT` on empty ref/path)

**Diff strategy (no server-side diff endpoint):** from the push event take `before`/`after`;
`readTree` both roots, walk recursively, compare entry hashes, `readFile` changed paths.
For line-level ranges the adapter needs blob bytes — `readBlob`/`readFile` return `Blob`;
use `await blob.text()` then diff locally. This is the review loop's core; budget subrequests.

**No write path exists** in binding or REST. All mutations are git pushes (§5).

---

## 5. Tokens (the trust boundary)

### Semantics
- Format: `art_v1_<40 hex>?expires=<unix>` — expiry self-describing in the string.
- Scopes: `"read" | "write"` (default `write`). Repo-scoped: touches only its own repo.
- TTL seconds: min 60, max 31,536,000 (1 yr), default 86,400 (24 h).
- **Git routes only — never authenticate REST.**
- Plaintext shown **once** (create/fork/import response `token`, or `POST /tokens` `plaintext`).

### REST
- `POST $BASE/tokens` — body `{ repo*, scope?, ttl? }` → `{ id, plaintext, scope, expires_at }`
- `GET $BASE/repos/:name/tokens?state=&per_page=&page=` — state `active|expired|revoked|all`
- `DELETE $BASE/tokens/:id` — revoke by **token ID**, never by plaintext.

### Binding
- `repo.createToken(scope?, ttl?)` → `{ plaintext, expiresAt }`
- `repo.listTokens()` → `{ total, tokens }`
- `repo.revokeToken(tokenOrId)` → `boolean`
- ⚠️ `validateToken()` is **NOT in the official binding docs** — do not depend on it (see §11).

### Wrangler
- `wrangler artifacts repos issue-token <REPO> --namespace $NS [--scope] [--ttl] [--json]`

### Git-over-HTTPS auth
- Header form (recommended, keeps secrets out of `.git/config`):
  `git -c http.extraHeader="Authorization: Bearer $TOKEN" clone|push …`
- Basic form: `https://x:<token-secret>@<host>/…` — username ignored;
  `<token-secret>` = token string **before** `?expires=`.
- Protocol: clone/fetch v1+v2 (`filter`, `include-tag` NOT supported); **push = receive-pack v1 only**.

**Adapter pattern:** per task → `createToken("write", 900)` → hand `{ remote, plaintext }` to the agent
→ agent pushes → on verdict, `revokeToken(id)` + `delete(repo)`.

---

## 6. Event subscriptions (the wake layer)

Events flow: **Artifacts → event subscription → Workers Queue → consumer Worker**.
(No webhooks.)

### Create a subscription (platform Event Subscriptions API)
`POST https://api.cloudflare.com/client/v4/accounts/$AID/event_subscriptions/subscriptions`
```json
{
  "name": "wreck-push-<repo>",
  "enabled": true,
  "source": { "type": "artifacts.repo", "namespace": "wreck", "repo_name": "task-0042" },
  "destination": { "type": "queues.queue", "queue_id": "<QUEUE_ID>" },
  "events": ["pushed"]
}
```
- Account-level source `"type": "artifacts"` (no namespace/repo) → lifecycle events for all repos:
  `repo.created`, `repo.deleted`, `repo.forked`, `repo.imported`.
- Repo-level source `"type": "artifacts.repo"` + exact `namespace` + `repo_name` →
  `pushed`, `cloned`, `fetched`, `token.created`, `token.revoked`.
- ⚠️ `repo_name: "*"` is **accepted but silently matches nothing** [reported; verify live].
  Subscribe the exact repo name at fork time.
- ⚠️ One account-level subscription + strict repo-name filtering in the consumer is the
  scalable shape; per-repo subscriptions' account cap is **undocumented** [verify live].

### `cf.artifacts.repo.pushed` payload (official shape)
- `type`: `"cf.artifacts.repo.pushed"`
- `source`: `{ type: "artifacts.repo", namespace, repoName }`
- `payload`: `{ ref, before, after, commits[], totalCommitsCount, commitsTruncated }`
  - `ref`: e.g. `"refs/heads/main"`; `before`/`after`: full SHAs
  - `commits[]`: `{ id, message, messageTruncated, timestamp, author: { name, email }, committer: { name, email }, parents[] }`
- `metadata`: `{ accountId, eventSubscriptionId, eventSchemaVersion, eventTimestamp }`

### Consumer contract
- **At-least-once, unordered, no documented dedup** → idempotency key
  `(namespace, repo, ref, before, after)`; drop duplicates.
- Event may arrive **before the pushed commit is readable** → retry-read with backoff
  until `after` resolves via `readCommit`/`log`.
- The governor's own merge push fires `pushed` on the baseline repo → **exclude the
  baseline repo** (name/prefix filter) or the system reviews its own merges forever.
- Git author/committer fields are **unauthenticated** — never use for authorization.
- Other events: `token.created` payload `{ tokenId, scope, expiresAt }`;
  `token.revoked` payload `{ tokenId }`; `cloned`/`fetched` payloads are `{}`.

---

## 7. Workers Builds (deploy-on-decision)

- Dashboard only: Workers & Pages → Create application → **Continue with Artifacts**
  (or existing Worker → Settings → Builds → Connect → pick namespace + repo).
- Requirements: account role needs Artifacts Read + Artifacts Edit; push code **before**
  connecting (empty repo → first build fails).
- **Production branch is `main` only.** No other branch can be production.
- Non-`main` pushes → Preview URLs when **Builds for Preview branches** is on
  (Settings → Builds → Previews Base); default commands `npx wrangler deploy` / `npx wrangler preview`.
- **Adapter implication:** the governor merges to `main` on the baseline repo;
  the merge push itself triggers the production build. Agent forks never build
  (only the connected baseline repo builds).

---

## 8. Rate limits & backoff

| Plane | Limit |
|---|---|
| Control plane (REST + binding) | 2,000 req / 10 s **per namespace** |
| Git plane | 2,000 req / 10 s **per repo** |
| Storage | 1 GB / repo · 32 MB / file·blob · 1 TB / account (raisable) |
| Repos / namespaces | unlimited |

- **No documented `Retry-After` header or backoff shape.** Treat 429/rate-limit errors
  with exponential backoff + jitter client-side.
- Observability: GraphQL dataset `artifactsEventsAdaptiveGroups` (31-day retention)
  exposes a `rateLimited` event type — use it to detect pressure, not to react in-band.
- Concurrency math: per-repo git limits mean each agent fork has its own 2,000/10s
  budget; only the merge-target baseline repo is contended → serialize merges there
  (single-writer lease; never parallel pushes to `main`).
- Billing: 10k ops + 1 GB-month free on Workers Paid, then $0.15/1k ops, $0.50/GB-month.
  Storage bills on average daily peak; repos bill until **explicitly deleted** → delete forks on verdict.

---

## 9. Jurisdiction

- Set once at namespace creation (`"us" | "eu"`), immutable, applies to all repos in it.
- Omitted = unrestricted. No FedRAMP for Artifacts.
- **Adapter choice:** create the `wreck` namespace with `"jurisdiction": "us"` (or omit);
  record the choice — it can never change.

---

## 10. Gotchas checklist (all doc-grounded)

1. Binding `get()` **throws** until repo status is `ready` — poll after fork.
2. Fork/create `409 Conflict` while provisioning — retriable.
3. `DELETE` repo returns **202 Accepted** (async) — the name may linger briefly.
4. `log()` is first-parent only; merge commits hide side-branch history from the binding.
5. No server-side diff — the adapter walks trees (budget subrequests; cache trees by hash).
6. Repo tokens never touch REST; API tokens never touch git.
7. `readFile` throws `INVALID_INPUT` on empty ref/path; returns `null` for dirs.
8. Basic-auth git form needs the token **without** the `?expires=` suffix.
9. Push is receive-pack **v1 only** — no shallow/partial-clone tricks on push paths.
10. Connecting Builds does **not** copy source — push code to Artifacts first.

---

## 11. Third-party claims NOT in official docs — do not depend on these

1. **`repo.validateToken()`** — appeared in our earlier playbook as "binding only";
   **absent from the official binding reference** (verified full page 2026-10-08).
   Treat as nonexistent until proven live.
2. **Direct `cf.artifacts.repo.pushed` → Workflows trigger** (third-party ADR) —
   not in official docs. Official path is subscription → Queue → consumer Worker
   (which may then start a Workflow).
3. **Automatic retries + DLQs per subscription** (dev.to analysis) — not documented
   officially; design the consumer as if redelivery is best-effort.
4. **Git LFS support** — absent from docs; treat as unsupported (32 MB/blob cap stands).
5. **`repo_name: "*"` wildcard semantics** — reported as "silently matches nothing";
   behavior is undocumented either way. Use exact repo names.
6. **Max event-subscription count per account** — undocumented; verify live before
   building per-repo subscriptions at scale (prefer one account-level subscription).
7. **Fork-vs-parent storage sharing** — undocumented; assume forks bill full size.
8. **Read-visibility lag after push** (event before commit readable) — reported from
   experiments, not documented; the retry-read pattern is defensive, keep it.

---

## 12. Minimal adapter operation sequence

1. (once) `POST /artifacts/namespaces` `{ "namespace": "wreck", "jurisdiction": "us" }`
2. `ARTIFACTS.create("baseline", { setDefaultBranch: "main" })` → push initial code via git
3. Connect baseline repo to Workers Builds (dashboard, one-time) — `main` → production
4. Per task: `repo.fork("task-<id>", { defaultBranchOnly: true })` → poll `list()` until `ready`
5. `repo.createToken("write", 900)` → hand `{ remote, plaintext }` to agent
6. Create event subscription for `task-<id>` (`artifacts.repo` source, `pushed` event → Queue)
   — or rely on one account-level subscription + consumer-side repo filtering
7. Agent pushes → consumer gets `cf.artifacts.repo.pushed` → idempotency check →
   retry-read `after` → tree-walk diff (`before` vs `after`) → build ChangeView →
   governor decides
8. Accept → merge into baseline `main` via git (single-writer) → production build fires
9. Always → `revokeToken(id)` + `delete("task-<id>")` (cost control)

## Doc URLs (all official, verified 2026-10-08)
- https://developers.cloudflare.com/artifacts/api/workers-binding/
- https://developers.cloudflare.com/artifacts/api/rest-api/
- https://developers.cloudflare.com/artifacts/api/wrangler/
- https://developers.cloudflare.com/artifacts/api/git-protocol/
- https://developers.cloudflare.com/artifacts/guides/event-subscriptions/
- https://developers.cloudflare.com/artifacts/guides/data-localization/
- https://developers.cloudflare.com/artifacts/platform/limits/
- https://developers.cloudflare.com/artifacts/platform/pricing/
- https://developers.cloudflare.com/workers/ci-cd/builds/git-integration/artifacts-integration/
- https://developers.cloudflare.com/artifacts/get-started/workers/
