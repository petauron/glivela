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
