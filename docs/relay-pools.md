# Dynamic relay pools, single-port 24000 EIH, and interactive topology

Related issue: #240.

Glivela supports named, ordered dynamic relay pools (`RelayPool`) for three-hop
server forwarding toward fixed landings. A logical pooled route binds an
account, an entry, a `RelayPool`, and a fixed landing (with an explicit public
landing address and fixed egress policy) without duplicating transport records
for every relay or rotating client subscription identities.

## Architecture

### Decoupled logical routes and physical relay edges

- **Logical pooled routes (`PooledRoute`)**: Each enabled pooled `RouteGrant`
  renders an independent `EntryRelayPool` balancer (`strategy.type = "leastLoad"`)
  on the entry, keyed by grant ID (`poolKey`). Multiple grants sharing the same
  entry, pool, and fixed landing with different `egressIp` or UDP settings keep
  distinct logical selectors and downstream landing credentials.
- **Deduplicated physical edges (`EntryRelayEdge`)**: Entry-to-relay SS2022 EIH
  dialers are deduplicated per `(entry, account, relay, entrySource, relayIngress,
  relayEgress, udp)` tuple. TCP-only and UDP-enabled grants never share a `uPSK`.
- **Single-port 24000 SS2022 EIH (`2022-blake3-aes-128-gcm`)**: Relays and fixed
  landings share port `24000` using Xray's `2022-blake3-aes-128-gcm` multi-user
  EIH inbound (`server-iPSK:user-uPSK`). Each user carries an exact source
  constraint, an explicit role (`relay` or `landing`), an explicit egress source
  IP, and—for relay users—an exact allowlist of `landing:24000` targets.
- **Direct relay forwarding without blackhole**: Relay users route exclusively to
  their authorized `landing:24000` targets through Xray `freedom` with
  `finalRules` (`destOverride` / exact target allowlist). Relays never forward to
  arbitrary Internet destinations, never fall back to direct egress, and never
  terminate the inner landing SS2022 layer.
- **Dual-role hosts and `ServerFirewall` v4**: A single enrolled landing host can
  simultaneously serve as a relay member for one route and as a fixed landing for
  another. `ServerFirewall` v4 enforces exact ingress source allowlists on port
  `24000`, strict relay-to-landing destination restrictions, and fixed egress
  isolation without breaking existing two-hop or native paths.
- **Fail-Closed empty pool (`blocked`) vs. retained candidate fallback**:
  When a pooled route has zero admitted relay candidates (empty pool, all
  members drained or node-suspended, no compatible address family, or members
  that were never admitted because they remained offline without applied EIH
  receipts), the entry routes that grant to `blocked` and never falls back to
  direct entry egress or an unauthorized two-hop path. Conversely, candidates
  that were **already admitted** onto an entry remain admitted across transient
  heartbeat blips or offline periods as long as their desired credentials and
  certificates still match (`control/relay_pool.go`), avoiding unnecessary
  worker restarts. If every admitted candidate simultaneously fails
  `burstObservatory` probes, Xray's `leastLoad` balancer falls back to the
  first admitted candidate in pool order rather than switching the route to
  direct egress.

### Control-plane admission vs. data-plane failover

Glivela intentionally separates three independent concerns:

1. **Desired configuration (`business.json`)**: Pool membership, member order,
   `leastLoad` parameters (`expected >= 1`, `maxRttMs`, `tolerance`), member
   drain metadata, entry `burstObservatory` parameters, and pooled route grants.
2. **Control-plane admission and applied receipts (`nodes.json`)**: A new or
   rotated relay candidate is admitted into an entry's desired `EntryRelayPool`
   only after both the relay and the downstream fixed landing report fresh mTLS
   applied receipts (`AppliedReceipt` + `ManagementIdentity`) confirming the
   exact `uPSK` and listener revision. An already active candidate remains
   admitted across transient heartbeat blips while desired credentials and
   certificates still match, avoiding unnecessary entry restarts.
3. **Data-plane selection and low-frequency telemetry (`burstObservatory`)**:
   Each entry runs one process-level `burstObservatory` (`intervalSec >= 10`)
   probing full `(entry -> relay -> fixed landing)` outbound chains. When a relay
   or path degrades, Xray's `leastLoad` balancer automatically shifts **new
   connections** to healthy admitted candidates without controller intervention
   or worker restart. The native entry driver polls local Xray Observatory status
   at most once every 15 seconds and piggybacks snapshots onto the existing node
   `Exchange` heartbeat. Telemetry read failures or stale samples never degrade
   `RuntimeReady` and never trigger config reloads or process restarts.

> **Connection boundary across structural changes**: Data-plane failover shifts
> new connections without restarting Xray. Structural control-plane mutations
> that revise an entry or landing Xray configuration (such as editing pool
> membership, draining/resuming a member, changing `leastLoad` or Observatory
> settings, or completing a socket cutover) still reload/restart the affected
> worker process; existing in-flight TCP/XUDP connections on that worker are not
> guaranteed to survive a worker restart.

## Migration (`v1 → v2` and Option A port-24000 cutover)

### Schema version 2 upgrade (`ServerTransportVersion = 2`)

- Loading owned v1 business state upgrades `ServerTransportVersion` to `2`
  non-destructively. Historical accounts, credentials, traffic counters,
  two-hop server transports, and legacy v1 read-only snapshots remain compatible.
- Existing single-relay three-hop `ServerTransports` are migrated into staged
  `RelayPool` + `PooledRoute` records with `pendingLegacyCutover: true`.
  Existing traffic remains on the retained legacy three-hop runtime until
  downstream EIH `24000` receipts are confirmed and an administrator explicitly
  executes `POST /v1/admin/socket-cutover` with `{"action":"cutover-legacy","grantId":"..."}`
  (also available in the panel's **中转池与拓扑 → 端口 24000 切窗与迁移** view
  and in the route inspector).
- After explicit cutover, the route enters `retiringLegacyTransport: true` until
  the cut-over entry confirms its applied `RelayPool` receipt, at which point
  controller reconciliation retires the legacy single-relay transport cleanly.
- Before any authorized production upgrade, retain a consistent controller
  backup (`POST /v1/admin/backup`) covering state, business encryption key, and
  node identities. An older controller must not open v2 business state.

### Option A controlled port-24000 socket cutover

When a landing or relay already runs a single-user SS2022 listener on port
`24000` at a public IP address, EIH `24000` cannot bind the same socket at the
same time. Glivela uses a write-ahead, crash-recoverable controlled cutover
(`socket-cutovers.json`) via `POST /v1/admin/socket-cutover`:

1. **Inspect (`action: "inspect"`)**: Provide `targetNodeId` and `address` to
   review whether port `24000` is occupied by a single-user listener, list
   all affected consumers (`two-hop-source`, `two-hop-transport`,
   `legacy-three-hop-landing`, or blocking consumers), and obtain the canonical
   `scopeDigest` for that exact consumer/blocker inventory.
2. **Start (`action: "start"`)**: Requires `targetNodeId`, `address`, exact
   `expectedTargetRevision`, and `expectedScopeDigest` from `inspect`. Under
   the store lock, the controller re-inspects the live socket and rejects the
   request if either the target revision or consumer scope changed since the
   preview. On match, it persists write-ahead cutover intent (`starting` →
   `listener-pending`), switches the target landing's socket to multi-user EIH
   `24000` with targeted rollback metadata, and waits for the landing's exact
   applied receipt.
3. **Advance Stage 1 → Stage 2 (`action: "advance"` during `listener-pending`)**:
   Requires `cutoverId`. Once the target landing reports its applied EIH `24000`
   receipt, invoking `advance` transitions all migratable consumer entries
   (`entries-applying` → `entries-pending`) onto their exact `TwoHopEIHBinding`
   or pooled EIH credentials.
4. **Advance Stage 2 → Complete (`action: "advance"` during `entries-pending`)**:
   Requires `cutoverId`. Once every affected consumer entry reports its matching
   applied receipt for the cut-over revision, invoking `advance` again completes
   and clears the active cutover record (`completed`).
5. **Rollback (`action: "rollback"`)**: Requires `cutoverId`. Restores only the
   exact single-user socket and consumer peer fields recorded in the cutover's
   targeted rollback snapshot (`rollback-applying` → `rollback-pending` →
   `rolled-back`), without clobbering unrelated concurrent edits. On controller
   restart mid-transition, `recoverSocketCutoversLocked` replays interrupted
   write-ahead phases deterministically.

## Operations

### Management API endpoints

All endpoints require an enrolled management mTLS certificate on the existing
`POST /v1/admin/*` same-origin JSON listener (node and subscription credentials
are denied):

- `POST /v1/admin/business`: Returns the secret-free `BusinessInventory`,
  including `relayPools` (with per-pool `revocation` receipt status),
  `entryRelayConfigs`, `observatoryPaths` (per-grant full-path telemetry),
  `socketCutovers`, pooled route metadata (`activeRelayIds`, `landingAddress`,
  `egressIp`, `pendingLegacyCutover`), and runtime metadata (`appliedRevision`,
  `relayPoolCapable`, non-secret public address hints, `occupiedPort24000`).
- `POST /v1/admin/relay-pools`: Create, update, reorder members, tune
  `leastLoad` (`expected: 1..64`, `maxRttMs: 50..30000`, `tolerance: 0..1`),
  drain/resume a member, remove an online or offline member, or delete an
  unreferenced pool (`expectedRevision` optimistic concurrency). Returns `202`
  with `revocation` (`pendingEntries`, `pendingLandings`, `complete`).
- `POST /v1/admin/entry-observatory`: Update an entry's explicit `sourceIpv4`,
  `sourceIpv6`, and/or process-level `observatory` (`destination` HTTP/HTTPS URL,
  `intervalSec: 10..300`, `sampling: 1..10`, `timeoutSec: 1..30` and
  `<= intervalSec`) using the entry's current `expectedRevision` and monotonic
  `expectedConfigRevision` CAS token (prevents concurrent silent overwrites even
  before any pooled route binds the entry, without restarting the entry worker).
- `POST /v1/admin/routes`: Create, enable/disable, toggle UDP/hideNative, or
  delete pooled routes (`relayPoolId`, optional `landingAddress`, `expectedExit`,
  `egressIp`, `ingressFamily`, `name`) using the account's `expectedRevision`.
- `POST /v1/admin/socket-cutover`: Inspect, start, advance, or roll back an
  Option A port-24000 socket cutover, or execute `cutover-legacy` for a staged
  v1 three-hop grant.

### Member drain vs. node-level temporary suspension

- **Member-level drain (`RelayPoolMember.drained`)**: Removes the node only from
  a specific `RelayPool`'s active candidates, with an optional `drainReason`
  (up to 128 characters) and optional future `drainResumeAt` (RFC3339; omitted
  for manual recovery). On a dual-role host, draining the host from a relay pool
  **does not** withdraw or suspend its fixed-landing routes.
- **Node-level temporary suspension (`/v1/admin/availability`)**: Suspends the
  entire node across both fixed-landing routes and all relay pools it belongs
  to. See [temporary node availability](temporary-availability.md).

### Offline member removal and receipt-gated revocation

Removing a relay member via `POST /v1/admin/relay-pools` is explicitly allowed
even when that relay is offline (`runtimeReady: false`). The controller
immediately projects updated configurations to every affected online entry and
downstream fixed landing to drop the removed member's candidates and revoke its
downstream `uPSK`s. Revocation completion (`revocation.complete`) tracks only
affected entries and downstream landings; the offline removed relay never blocks
revocation completion.

### Management panel and three-column interactive topology

Open the **中转池与拓扑** tab in the Glivela management panel (built with React
and native SVG using the panel's existing semantic theme tokens and zero
additional frontend dependencies):

- **Three columns**: Entries (left) → Relay Pools rendered as dashed container
  cards with ordered member pills (center) → Fixed Landings (right).
- **Two-hop vs. three-hop paths**: Two-hop direct routes arch across the middle
  column directly from Entry to Fixed Landing using TCP latency diagnostics.
  Three-hop pooled routes traverse their Relay Pool card and fan out per member
  to each bound Fixed Landing.
- **Three-layer status separation**: Every node, card, curve, and detail table
  explicitly separates **期望配置** (desired config & drain flags),
  **节点回执** (`appliedRevision / desiredRevision` and control-plane admission),
  and **低频探测采样** (`burstObservatory` full-path health, RTT, sample counts,
  `尚无样本`, and `样本过期`).
- **Stale sample threshold**: Samples older than `max(60s, max(15s, intervalSec) * 3)`
  are explicitly labeled `样本过期` rather than healthy or failed.
- **Interactive inspection**: Select any entry, pool, ordered member, fixed
  landing, or path curve (click or keyboard Enter/Space) to spotlight connected
  paths and inspect full-path telemetry alongside quick edit actions.

### Verification and rollout boundaries

Source implementation, automated Go/UI CI checks, release publication,
controller/node upgrades, staged migration/cutover execution, and real-client
subscription verification are distinct stages. Passing unit or CI checks does
not substitute for a separately authorized rollout, backup checkpoint, or live
path acceptance.
