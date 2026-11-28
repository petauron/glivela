# Managed UDP forwarding

Server routes can opt into UDP in their route details. This requires an enrolled
SS2022 transport and compatible controller, entry and landing programs. Existing
routes remain TCP-only until the operator enables UDP.

Datagrams use Xray XUDP inside the existing SS2022 TCP connection. TCP streams
are not multiplexed. The public listener, issued key, exact source authorization,
account credentials, subscription token and traffic history stay unchanged. A
three-hop route carries the final SS2022 stream through its existing TCP relay;
for pooled three-hop routes on port 24000 EIH, UDP-enabled grants receive
isolated `uPSK`s separate from TCP-only grants on the same relay and landing.
See [dynamic relay pools and topology](relay-pools.md).
No public UDP listener, dynamic UDP port range or additional runtime is created.

The authenticated `routes` operation accepts `udp: true` or `udp: false` with its
existing identifiers and current `expectedRevision`. Landing authorization is
derived from active grants and bound listeners; it cannot create a source or
adopt a different transport. Unsupported transport selections fail without saving.

URI, Mihomo/OpenClash and Shadowrocket subscriptions advertise UDP only after
matching applied configuration receipts from the entry, landing and any relay.
Pending UDP application keeps the authorized route visible with UDP disabled.
Health observations do not withdraw the route. Refresh subscriptions after the
nodes apply the change. Disable UDP through the same operation to revoke its
inner routing and selected egress authorization without rotating identities.

UDP destination port 443 remains blocked, including through XUDP. Private,
metadata and control destinations, source authorization and fixed egress-family
restrictions remain enforced. UDP support does not imply unrestricted QUIC,
unsolicited inbound traffic or Full Cone NAT. UDP-over-TCP also inherits TCP's
head-of-line blocking and does not remove upstream UDP restrictions at the exit.

Validation covers deterministic policy rendering, default TCP-only behavior,
persistence/revocation, and aligned subscription capability. The existing native
CI job runs the bundled core in fresh unrouted Linux network namespaces: IPv4
and IPv6 UDP request/reply at 64/512/1200 bytes with the rendered landing and UID
firewall, with private destinations and UDP 443 denied. Production deployment
and client acceptance remain separate from these synthetic checks.
