# Retained operator configuration

These files belong in the existing private Glivela state directory. They contain
operator choices, not built-in vendor aliases or permission inferred from a node.
Keep them private (0600), back them up for the specific change, and retain them
across ordinary program updates. The installer does not need a new capability.

## Issued subscription names

Before replacing a program which transformed names, capture the actual issued
VLESS display name for each retained entry through its authenticated existing
subscription. Stage `subscription-names.json` in the controller state directory
before the managed upgrade, owned/readable by the controller's configured UID:

```json
{"version":1,"names":{"entry-example":"Example entrance"}}
```

Use entry IDs matched by the complete existing connection identity, not by guessed
names or address alone. Include the full issued label, including its existing
region prefix. Helpers and route names then derive from the same explicit label;
client chains retain their separately saved names. URLs, keys and UUIDs do not
belong in this file. The program validates entries, unique labels and private
file permissions before binding subscriptions; malformed input stops startup.
There is no vendor-name inference, alternative endpoint or direct fallback.

An authenticated administrator can update existing entry labels and explicit
IPv6 client-chain labels without editing the business ledger through
`POST /v1/admin/subscription-names`. Send `expected` and `names` maps keyed by
retained entry or IPv6 chain ID; use an empty expected value when no override exists.
The controller validates ownership, stale values, uniqueness and generated
subscriptions before atomically saving. Explicit names are presentation only;
clients using names in saved policies may need to select the renamed entry again.
An older controller that does not support chain labels requires the prior names
file from the pre-change recovery point before rollback; never restore an old
business ledger merely to undo names.

The controller's encrypted consistent backups include this optional file, and
reject a file changed behind the running controller. Restore only to an offline
new private destination. Configuration recovery never restores an old ledger.
Ordinary absence uses the retained service's own display name.

## Landing subscription regions

`POST /v1/admin/subscription-landing` reads one enrolled landing's effective
presentation with `{ "id": "landing-example" }`. To save, send `id`, an exact
`expected` object from that read, and `value`, for example
`{ "regionCode": "US", "nameSuffix": "" }`. The region is a two-letter uppercase
code; the optional suffix follows existing route-name rules. An empty suffix
keeps the normal double-hop label. This private administration operation uses
the existing mTLS boundary; it does not enroll a node or authorize a route.

The same `subscription-names.json` file stores explicit `landings` values keyed
by landing ID. Existing imported regions remain effective until explicitly
changed. Saving validates generated subscriptions and preserves selectable
identities and ordering before the atomic write. Both ordinary name edits and
consistent backups retain the region values. No account/node revision, proxy
policy, key, subscription URL or traffic ledger is rewritten. IPv6 chains with
explicit issued labels retain those labels. Refresh client subscriptions to
receive changed names and their matching group/dependency references.

## Independently managed host firewall

A native node with a separately managed input DROP guard may explicitly identify
that existing table in `host-firewall.json` in its node state directory:

```json
{"version":1,"table":"operator_guard"}
```

Only a root-owned private regular file is accepted. Family `inet`, chain `input`,
input hook and DROP policy stay fixed. Glivela-owned tables cannot be selected.
Without this file the documented table is `host_guard`. An unknown additional
DROP policy is still refused; the program never searches for a permissive table.
This setting does not create, rename or flush a table, persist a port exception,
change production proxy grants or relax the exact peer-source/time-limit checks.
It applies only to the existing temporary speed-test exception and its recovery.
Retain the configured table and this file while recovery resources still exist.

## Shared client landing cutover

Upgrade the controller and one selected landing through the existing signed
catalog before applying shared listeners. Back up only the required private
configuration/state and current source rules; reuse a verified pre-change recovery
point on retries. Preserve server forwarding on 1080, DNS, exits and all account
and node identities. Keep subscriptions on their original origin/token.

The authenticated `client-chains` operation accepts `shareLanding:true`,
`accountId`, `egressId`, and current decimal-string `expectedRevision`. It selects
one independent client-only SS2022 AES-128-GCM key per single-account landing on
TCP 24000. Existing IPv4 and explicitly authorized IPv6 sources retain their exact
addresses. Keys are not shared with server forwarding, management or another
landing/account. UDP remains disabled.

Preserve the old precise rules until acceptance. Add only the existing authorized
sources on TCP 24000 in the host/provider policies. Apply the transaction, wait
for its matching fresh landing receipt, refresh the real subscription and verify
each enabled chain through its original VLESS dependency and original exit before
continuing. Retained names/references and monotonic entry-side accounting must
match. Remove superseded client-port rules only after that landing passes.

On failure, stop the batch. `restoreLanding:true` with the same landing/account
and current revision restores the retained original per-chain configuration
through a forward revision. Never restore an older ledger, loosen source checks,
change the exit or fabricate health to continue.

## IPv6-only entry DNS

New entry render policy 15 uses the existing public resolvers over IPv6 when the native exit is explicitly `ipv6_only`. The DNS servers, resolver outbound family and exact port-53 destination rules select the same addresses; composite local DoH uses those IPv6 endpoints too. Private/control-address isolation and proxy readiness checks remain mandatory. IPv4-only and automatic policies retain their existing resolver configuration.

Historical render policies, including 7, retain their original bytes for ownership and recovery checks. Controller startup does not rewrite retained nodes. Upgrade the controller and selected entry first, then apply that entry's existing plan through the normal administrator entry update with an advancing revision. Other node assignments, credentials, subscriptions and counters are unchanged. A program installation alone is not proxy or subscription acceptance.

## IPv6 fixed-exit landing DNS

Landing render policy 2 uses IPv6 literals over TCP for built-in DNS when the fixed exit is IPv6, with the resolver socket bound to that same exit. DNS routing stays limited to those resolver addresses and TCP port 53; business traffic keeps its existing source and address-family restrictions. IPv4 landings retain their resolver configuration. No UDP allowance or system DNS fallback is added.

Historical landing policies 0 and 1 retain their original configuration bytes and validation. Controller startup does not activate this DNS policy on retained nodes. Upgrade the controller and selected landing program, then explicitly apply that landing's existing plan through the normal administrator update with an advancing revision. Preserve its exact sources, credentials and fixed exit; verify domain-based HTTPS through the published chain before treating the update as accepted.


## Explicit client-only IPv6 landing

An operator may set a landing plan's `ipv6OnlyAddress` to one exact, locally
assigned public IPv6 address. This requires the new landing render format 3 and
a fixed IPv6 egress source. Upgrade the selected controller and landing program
before treating the new revision as accepted; ordinary landings retain format 2.
Controller startup never activates this mode automatically.

The landing retains its old transport, source grants and IPv4 client records as
configuration/history. It activates only IPv6 client listeners at the explicit
address, with their original SS2022 credentials, TCP ports and exact IPv6 sources.
No base IPv4/mesh listener or IPv4 DNS exception is installed. IPv4 client chains
and server-forwarding publication are unavailable in this mode; credentials,
account policy, counters and subscription order slots remain stored. The client
chain view reports `landing_ipv6_only`, rather than substituting a new IPv4
address or a direct connection. An address change remains an explicit operation.

A failed pending transaction may be superseded only by a strictly higher
assignment received through the existing authenticated controller channel.
The runtime verifies its retained configuration, validates the new candidate,
keeps the previous candidate as a private recovery file and stops its owned
worker/table before persisting the replacement. Unresolved commit intents,
reused revisions, corrupt state or failed ownership checks remain closed.
This does not authorize editing journals, replaying an old ledger or changing
unrelated nodes. Installation success is distinct from fresh runtime receipts
and a real subscription client request through the expected exit.
