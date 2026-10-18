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
Certificate enrollment is a local administrative operation, not a node API.
Run only one controller per state directory; use a private, operator-owned
directory and independently provisioned CA/server/node identities.

This is **not yet an installable landing replacement**. The production runtime
adapter, controller/node executables, existing-data handover, catalog packaging,
and removal of the old Vastora business path are not implemented by this slice.
The Runtime tests use a fake executor and do not prove real Xray, DNS, firewall,
TLS forwarding or QUIC behavior. Do not deploy this slice or close #54 based on
its tests. The existing architecture described below remains active until the
complete migration is implemented and independently accepted.

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
