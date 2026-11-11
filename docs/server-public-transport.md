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
