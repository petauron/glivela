# IPv6-priority composite route

Issue 32 introduces one grant with a strict IPv6 primary and an independently
authorized IPv4 landing. `IPv4EgressID` is the optional secondary stable ID;
the route's client identity and account remain unchanged between families.
`RoutePeer.ExitFamily` describes the FINAL exit, not its private SOCKS transport
address family. Both peers must be ready, distinct, and match the grant.

`SelectCompositeDestination` is pure. Public AAAA wins, including dual-stack
targets. Only successful confirmed AAAA NODATA plus public A permits IPv4.
DNS errors, missing/blocked answers, private/Fake-IP literals, and management
ports fail. A failed IPv6 connection never retries through IPv4. There is no
native/direct fallback, nested landing, UDP enablement, NAT64, or HTTP replay.

Projection produces deterministic config plus one digest-addressed routing
script. It requires the reviewed target-selection runtime described in
[`runtime/README.md`](../runtime/README.md). The first outbound is blocked so a
script error cannot escape. Validated original literals or resolved addresses
are pinned directly; final SOCKS never re-resolves their domains. Original
domain requests preserve payload/SNI, and raw Fake-IPs are rejected.

Only composite routing queries the managed DNS server; native/fixed DNS
retains its existing resolver and is not intercepted by a global DNS script.
Composite queries are sequential with an exact successful-empty discriminator.
Their host adapter supplies CNAME/positive/negative TTL and public-target
validation. Zero-TTL results can serve the current connection but are not
cached. A change from A-only to AAAA between queries produces an empty A result
and fails closed, rather than merging different generations. Selection metadata
records the chosen family and literal/AAAA/NODATA reason without credentials.

A subscription presents one combination, labeled with both exit regions and
`IPv6优先+IPv4`, while retaining native/single-exit choices. Repeated same-label
combinations get deterministic readable sequence marks, not secret hashes.
Both families share the ONE existing routed credential and quota member.

The UI reuses the host's existing React/shadcn controls and compact visual
style. It selects only ready, independent family-appropriate exits and states
the TCP-only and no-connect-failure-fallback constraints explicitly.

The Vastora integration is maintained as a separate dependent change; it owns
schema 111, precise desired/applied source authorization, task orchestration,
Agent DNS and atomic files, dual verified leases, and snapshot filtering.
Pin that integration to the actual merged Glivela commit before its standalone
CI review. There is no local-path module fallback for releases.

Domain, UI, migration, DNS, identity, snapshot, runtime-file, and controlled
actual-core tests are provided. Their source being present does not mean they
have run. A skipped opt-in runtime lab, a successful config parse, or healthy
peer probes alone are NOT issue acceptance. Runtime image publication, signed
catalog changes, and production deployment each require separate authorization.
