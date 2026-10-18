# Petauron Glivela

## Landing ownership migration (#54, in progress)

The target boundary is a Glivela controller communicating **directly** with a
Glivela node process. Glivela owns proxy configuration, component compatibility,
migration and business health. Vastora installs, updates and uninstalls the
application; it is not a command broker for this channel. No generic host hook
or application capability negotiation is introduced.

`control/` implements the first isolated part of this migration: mutually
authenticated HTTPS exchanges, certificate-bound node isolation, revision/hash
receipts, private durable controller state and bounded node reconciliation.
It uses Go's TLS/HTTP implementation and existing Glivela artifact contracts.
Certificate enrollment is a Glivela management operation, not a node API.
Run only one controller per state directory; use a private, operator-owned
directory and independently provisioned CA/server/node identities.

`cmd/glivela` now supplies controller/node modes from a private bootstrap JSON
file. Both hold a kernel-backed exclusive state-directory lease. The node uses
the native runtime journal and the hash-pinned Xray/systemd adapter, validating
before activation, preserving revisioned configuration backups and recovering
an interrupted or failed activation before polling. A failed health check of
an unchanged revision does not restart the service. The controller bootstrap
contains transport/storage settings and an `administrators` list of SHA-256
leaf-certificate fingerprints. It does not contain node business state. Existing
`nodes.json` remains authoritative across restarts; the obsolete bootstrap
`nodes` field is rejected, not replayed over managed updates.

For a staged legacy import, controller bootstrap must also reference its
independent raw 32-byte storage key using `businessKey` (an absolute private
file path, never the key contents). Controller startup decrypts and validates
the complete `business.pending.json` under the existing directory lease before
opening its listener. A missing/wrong/unsafe key or corrupt checkpoint aborts
startup instead of creating an empty inventory. Node and verifier bootstraps
cannot select a business key. With no checkpoint and no key, a new controller
starts empty. Loading does not rewrite the checkpoint or activate subscriptions.

An enrolled administrator can POST `{}` to `/v1/admin/business` on the same
private mTLS listener to inspect the original accounts, reset schedules, quota
watermarks, directional counters and endpoint/node bindings. This detached view
excludes protocol secrets, subscription tokens, private keys and the raw source
archive. 64-bit quota, revision and traffic values use decimal strings in this
API to avoid browser-number rounding; persisted typed values remain unchanged.
Staged data remains `awaiting-handover`: historical status and successful
decryption do not prove that the old business writer is fenced, that final usage
is reconciled, or that all routes passed. This read-only slice is not the complete
business UI/API replacement or permission to clear migration/health alerts.

The separate one-time offline tool can commit data ownership from the final
stopped-writer snapshot (`adopt-final`; see its README). It creates encrypted
`business.json` as the sole current business source while retaining the staged
checkpoint only for private recovery. The controller reports `owned-unverified`,
not ready/healthy. Owned-state corruption never falls back to staging, and
reimport cannot overwrite owned accounts or ledger values. This does not yet
complete the runtime/business UI migration or authorize restoring an old proxy
writer; runtime acceptance and removal of replaced paths remain required.

On the same private mTLS listener, a separately authorized management identity
can POST `/v1/admin/landings` with `id`, `certificateId`, `plan` and
`routeEntries` (entry ID to `{certificateId,address}`). A configured entry
inventory must cover every exact source in the landing plan, with distinct
entry certificates. Provisioning without that inventory cannot pass route
acceptance. Glivela
validates the plan and generates the exact Xray artifact itself. The response
is HTTP 202 with `revision` and `configSha256`, not a health success. Node
identities cannot use management endpoints; management identities cannot submit
node or verifier reports. This API is not yet a replacement business UI or a
complete legacy-data importer.

The same administrator can POST `/v1/admin/entries` with `id`,
`certificateId`, a Glivela `XrayPlan` as `plan`, and explicit `network` policy.
Here `id` is the existing entry
application ID; its physical host relationship stays in the business references.
Exactly one entry application may appear in its endpoints, credentials and
grants. REALITY private/public keys must form the same X25519 pair. The controller
renders and binds the configuration/revision itself; arbitrary standalone core
configuration is not accepted. Entry and landing plans are mutually exclusive,
and an enrolled identity cannot silently change role. Entry certificates may
also verify that same entry, but cannot obtain another node configuration or
administrative access. Rotation updates the linked verifier identity atomically
and invalidates route proofs. Desired entry configuration is sensitive: keep
the private `nodes.json` and runtime journals out of public logs and artifacts.

`network` is an `EntryNetwork`, not a platform capability description. A pure
native entry supplies an empty object and does not need a private-link monitor.
A routed entry supplies its recorded private source identity and exactly the
peers used by its routes (including an existing composite route's second exit).
Each peer binds `egressId` separately from its private node ID/key/address, plus
a controlled HTTPS `target` and public `expectedExit`. The actual SOCKS address
and port must agree with the generated plan; duplicate, missing, unrelated,
self-targeting or wrong-family peers are rejected. No identity is inferred from
an IP or a display name. These records still require fresh node-local evidence
before any gate may open.

Changes to source/peer identity, probe target or expected exit require a new
revision even when the Xray configuration bytes/hash are unchanged. A previous
runtime receipt cannot acknowledge that new policy; it must go through actual
application/verification. Real mTLS/journal regression covers this delivery and
deduplication boundary with a test worker, not an actual container or gate.

Entry desired state can now use the direct channel and the shared revision/
recovery journal. **The entry container execution adapter is still incomplete.**
The existing `node` bootstrap uses the native landing/systemd driver, which
explicitly refuses entry plans before service start/stop. Do not deploy an entry
enrollment through that driver or claim these tests prove container takeover.
Entry execution must retain the current Docker read-only mount/user/network
ownership and peer firewall boundaries; it must not become an easier native
replacement or a blind container restart. In particular, actual 26.7.28
post-resolution/address-family enforcement still needs installed acceptance;
successful parsing does not prove that newer JSON options are honored.

The Glivela-owned `landing.TrafficGate` and `Monitor` preserve peer-scoped
runtime fencing for host-GID and retained-bridge entry containers. Each new
revision starts closed. Only fresh, identity-bound direct transport checks
around a successful business probe for the exact expected exit can renew a
15-second maximum kernel lease. Cancellation, failed checks and expired proof
close that peer only; the monitor has no shared Xray process lifecycle methods.
Xray UDP relay ports are per-association, so UDP fencing binds the dedicated
runtime GID/bridge and exact private peer rather than Dante's old fixed range.
Policy read-back, expiry, closed-revision cleanup and unrelated-peer preservation
are tested separately. These primitives are not yet wired into the unfinished
entry container adapter or its boot fence; they do not authorize deployment.

`control.EntryContainer` adds read-only ownership checks for the new owned
entry profile: immutable full container/image IDs, the pinned official image,
exact command/entrypoint/environment, a single read-only private config mount,
minimal capabilities and private PID/IPC isolation. Host mode binds the
dedicated GID; retained bridge mode binds the exact network ID and bridge name,
not a reusable display name. Inspection uses only the fixed local Docker socket,
with bounded output/time and no inherited Docker context or diagnostic dumps.
Old Vastora labels do not count as ownership. This is not a lifecycle driver or
legacy adopter: conversion of the frozen legacy resource inventory, config-byte
and listener verification, boot fencing and activation/recovery are still needed.
The current tests mutate anonymous inspect snapshots; they do not create a real
container or prove actual installed Docker acceptance.

The `verifier` mode runs on an enrolled entry using its own private bootstrap,
state-directory lease and mTLS identity. It polls `/v1/route-checks`, performs
one bounded SOCKS/TLS/observed-exit check at a time, and reports success or
failure directly to Glivela. It cannot enroll nodes, listen for commands or
control Xray. Management can POST the complete `checks` batch to
`/v1/admin/route-checks`, then POST `landingId`, `snapshotId`, `revision` and
`configSha256` to `/v1/admin/route-acceptance` for a read-only decision. These
checks must match the independently enrolled entry inventory in full; submitting
only passing entries or reusing one entry certificate for another is refused.
Changing the enrolled inventory invalidates the old route proofs. These
endpoints do not commit a migration or remove backups. Each retry has a new attempt ID; reports are bound to
that attempt, snapshot, entry certificate, landing and desired revision/hash.
Completed reports are durable, and a lost acknowledgement does not cause the
entry to repeat a completed attempt. This channel does not by itself complete
legacy ownership transfer or authorize clearing a runtime-health alert.

Once an entry is enrolled as an owned runtime, route acceptance also requires
its current applied receipt. Diagnostics may still test a reachable route while
that receipt is missing: network observations are not blocked or promoted to
runtime success. Entry configuration/certificate changes and readiness
transitions invalidate linked route proofs, so a check performed before a new
entry configuration was applied cannot later clear its warning.

`landing/` renders the official Xray 26.7.28 SOCKS configuration and dedicated
UID-scoped nftables policy from one explicit plan. The node channel binds this
plan to the exact configuration digest. The runtime journals both together,
stops the worker during rule replacement, installs/read-backs the new rules
before starting, and retains the previous complete plan for recovery. Changes
to the local worker UID or mesh interface require explicit handover. Only
exact authorized mesh sources are granted access; TCP-only grants stay TCP-only.

Local readiness checks the service and rules; it **does not** mean an end-to-end
route passed. The local process is not allowed to bypass source restrictions
to probe its own SOCKS listener. Authorized entry-side route acceptance is
still required before exposing a route as healthy.

On a Linux landing host, the root-only local preparation command
`glivela backup-legacy-landing -node-id <existing-id> -directory <private-directory>`
reads only the fixed previous managed installation and writes a fresh recovery
checkpoint into an existing private directory. It validates ownership and file
digests, retains the exact recovery executable, then reopens and verifies the
checkpoint and compares it with the current source. Its JSON result is explicitly
`backup-only`, never a migration or health success. It does not stop services,
change firewall rules, fence writers or activate Xray. Failed partial checkpoints
are retained for diagnosis. The private output path and checkpoint contents must
not be published. A subsequent cutover still requires a writer fence and fresh
validation; this read-only source snapshot is not that fence.

The root-only offline command
`glivela switch-legacy-landing -config <node-bootstrap> -node-id <existing-id> -checkpoint <snapshot.json>`
requires an unused native runtime and a persistently stopped/masked old Agent.
It revalidates the backup, exact old firewall, source/interface policy, installed
candidate service and official Xray configuration before stopping Dante. A
durable pending record precedes service changes. The old service is disabled
for boot, its exact firewall is withdrawn, and the native runtime activates the
candidate. Failure attempts bounded recovery through the retained executable;
failed recovery retains its pending record. Node startup handles interrupted
first switches before normal runtime recovery. A rolled-back switch blocks
automatic retries. The command returns `awaiting-routes`; later revisions remain
blocked until the remaining controller-side acceptance/authority handover is
implemented. This command path is not yet accepted for production: real systemd
first-cutover/recovery integration and complete data/control handover remain
outstanding.

This is **not yet an installable landing replacement**. The installer still
needs to provision the dedicated Xray unit and its enforced firewall dependency;
this code refuses an unknown unit rather than installing an unsafe substitute.
Existing-data handover, catalog packaging and removal of the old Vastora
business path remain incomplete. The optional official-binary test verifies
actual Xray configuration validation and SOCKS/TLS forwarding on loopback,
including certificate rejection and HTTP 404 handling. Runtime recovery tests
use a fake systemd driver. Real Linux nftables lifecycle tests cover IPv4/IPv6
install/read-back/remove, idempotence, drift rejection and unrelated-table
preservation in an isolated network namespace, and run in CI. Packet-level
enforcement tests additionally cover actual rendered IPv4/IPv6 DNS/TLS policy
and literal-IPv4 SOCKS UDP request/reply, target-observed egress and source/UID
denials with the official core. Full migration systemd recovery, QUIC and
independent kernel ingress isolation for dynamic UDP sockets remain unaccepted.
Do not deploy or close #54 based on these tests. The existing
architecture below stays active until the complete migration is accepted.

Formerly Meridian. See [the in-place brand migration](BRANDING.md) for stable
installation identities and coordinated release steps.

Glivela is Petauron's access and subscription domain for managed proxy
entries. It owns account plans, stable access credentials, route grants,
shared usage accounting, and deterministic subscription rendering.

Glivela is not a general-purpose proxy panel and does not fork 3x-ui. Vastora
remains the desired-state control plane and its Agent remains responsible for
validating and atomically applying Xray configurations on managed nodes.
Glivela supplies the authoritative, runtime-independent domain rules that
both sides share.

## Product boundary

- **Vastora** deploys applications, selects nodes, authorizes operations, and
  records desired/applied revisions.
- **Glivela** defines accounts, credentials, route grants, shared quotas, and
  subscription output.
- **Vastora Agent** applies the resulting Xray identities and routes, reports
  monotonic counters, and confirms runtime health.
- **Senulun** observes infrastructure health.

There is one writer for each credential. A migration may import an existing
3x-ui identity once, but released runtime code must not retain dual reads,
dual writes, aliases, or a 3x-ui fallback after cutover.

## Protocol scope

The first complete vertical slice supports managed VLESS/REALITY and native
Hysteria2/TLS entries, VLESS fixed entry-to-egress route credentials,
conventional base64 subscriptions, Mihomo YAML, and one shared account quota
across both protocols and all route credentials. A native Glivela credential
owns a VLESS UUID and, when Hysteria2 is enabled for the entry, a separate
Hysteria2 authentication secret. Both runtime clients use the same Xray user
label, so their counters contribute to the same account ledger instead of
creating a second account or quota. Routed credentials remain VLESS-only:
current Xray Hysteria inbounds do not provide a trustworthy per-user routing
boundary, so Glivela never publishes a routed Hysteria credential that could
silently escape through the native exit.

The APIs are pure and deterministic so callers can persist state in their own
forward-only schema and compare desired output before applying a runtime
revision.

## Security model

Persisted domain records refer to credential fingerprints and caller-owned
encrypted secrets. Xray rendering necessarily receives decrypted protocol
credentials, the REALITY private key, and the Hysteria2 TLS key for the
duration of one in-process projection; these secret-bearing values must stay
in encrypted task/state envelopes and are never included in errors, receipts,
or event text. Raw subscription links are accepted only as bounded renderer
input and are never suitable for logs. Subscription rendering rejects
cross-account routes, duplicate identities, ambiguous names, unsupported
transports, and mismatched protocol material.

## Core API

- `PlanImport` validates and fingerprints a complete one-time authority
  transfer before callers mutate durable state. A legacy VLESS identity may
  be preserved across different entries, while duplicate VLESS identities
  within one entry remain invalid. Hysteria2 authentication identities follow
  the same boundary: they must be unique inside one entry runtime, while a
  migrated account may preserve the same authentication secret on independent
  entries. An empty account inventory is valid when an installation has entry
  runtimes but no subscribers yet.
- `ProjectQuota` applies one shared account allowance across native and routed
  credentials without splitting or duplicating the allowance.
- `RenderLinks` and `RenderMihomo` produce deterministic subscriptions from
  applied, healthy route receipts.
- `BuildDesiredArtifact` creates a complete Xray candidate and binds it to a
  revision and SHA-256 digest.
- `VerifyAppliedReceipt` prevents a stale or different runtime from being
  reported as the desired state.
- `ParseXrayUserCounters` maps exact Xray user counters back to credential IDs
  without relying on delimiter splitting.

Vastora's migration adapter rejects legacy per-entry traffic ceilings and
per-client simultaneous-IP limits before import. Those policies do not have an
equivalent in Glivela's account-wide quota model and current Xray runtime, so
they must never be silently weakened during replacement.

## Status

This public module is the reusable Glivela domain authority. Vastora is its
first control-plane integration and owns persistence, operator APIs, UI, and
Agent orchestration; no separate mutable panel or node-side service is part of
the architecture. The first release remains in pre-release integration until
the forward cutover and runtime receipts have been verified on the managed
fleet.
