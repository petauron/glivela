# Server forwarding through the shared public SS2022 listener

Related issue: #94.

Server forwarding can explicitly set `PrivateTransport.port` to `24000` on an
already authorized IPv4 SS2022 landing and each enrolled entry peer. The address,
port and credential must agree with the existing shared listener. The retained
1080 policy is unchanged when this field is absent; a failed 24000 connection
never tries 1080, a management address or direct Internet access.

The shared server listener is TCP-only. A client listener on the same socket is
accepted only if its SS2022 method/key, source grant and fixed egress agree. The
renderer emits one authenticated inbound. Kernel source isolation uses the full
server source inventory, so removing the old client subscription cannot close
an already migrated server route. Mismatched keys, non-shared collisions,
different exits, UDP grants, private endpoints and arbitrary ports are rejected.

The explicit port is used by the native worker gate and its immutable identity,
post-resolution output filter, landing source/reply filter, readiness listener
checks, startup probe, route acceptance, subscription authorization, latency,
speed authorization and path MTU lookup. The UI reads the actual main/IPv4 peer
ports from the controller instead of assuming 1080. No new dependency, public
management service or DNS policy is introduced.

## Ordered migration

1. Preserve a valid consistent controller recovery point and the required node
   identities/configuration. Upgrade only explicitly authorized components to a
   build that understands the shared server listener; released alpha.122 does
   not contain this feature.
2. Preserve the existing client listener key and exact source rules. Set the
   landing's server transport to the same public address, port 24000 and issued
   key. Read back one owned listener, TCP-only source filtering and unchanged
   existing client access. Do not open 1080 or widen cloud firewall sources.
3. Enroll one entry's matching peer and exact management identity. Create an
   independent routed VLESS credential through the existing route API; keep the
   native VLESS credential and native egress unchanged.
4. Require current runtime receipts and a real published-subscription HTTPS
   request with the expected landing exit. Only then disable the corresponding
   client chain and replace its subscription-order reference. Keep credentials,
   counters and history. Repeat for the next authorized entry.
5. On a failure, keep or restore that client chain's publication and stop the
   next switch. Do not downgrade the business schema or overwrite live counters.

A client that cached the previous subscription must refresh it; disabling its
publication does not erase an already downloaded configuration. Reusing that
same listener/key deliberately keeps the old path available during acceptance.
Implementation, local verification, CI, release/catalog publication, deployment
and real-client acceptance must be reported separately.


Public startup identity is verified through the existing node mTLS control
channel, without opening overlay TCP/UDP access or requiring the two nodes to
appear in each other's network map. The landing reports its own local
ID/key/address read-back with its current runtime receipt. The controller
requires the exact enrolled entry certificate, mutually assigned source,
public TCP-only transport and target, fresh ready landing receipt, and the
originally recorded peer identity. Both identity checks around the real public
SS2022/exit probe must succeed. Missing, stale, changed or foreign evidence
leaves the owned peer fence closed; there is no direct or overlay fallback.
Private transports retain their direct-link checks.

A retained client-managed landing can back the same account/entry pair's new
server route without inventing an imported host reference. The existing shared
credential and retained chain association remain authoritative, including
after that old client chain is disabled. Other accounts and unregistered exits
are rejected. Normal node enrollment and exact-source enforcement still apply.

## Reuse an enrolled client listener

An entry may explicitly bind `transport.clientListenerId` to an existing direct
client chain owned by the same account and entry. The peer must use that
listener's exact public IPv4/IPv6 address, port (24000–24999), canonical key,
SS2022 cipher and configured exit. The controller verifies the original mTLS
entry/landing enrollment and the current source-restricted listener; a reachable
socket alone does not authorize a route. Relay chains are not eligible.

Create and verify the server grant before disabling the client publication.
An effective server grant retains the original listener after that publication
is disabled. Account or server-grant revocation withdraws its retained listener
when no enabled client publication still needs it. This does not install a
second listener, widen its sources, expose server credentials in subscriptions,
or create a direct fallback. Native entry filtering and probes use the same
IPv6 family and exact destination port as the worker.
