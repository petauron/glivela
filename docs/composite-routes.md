# IPv6-priority composite route: official Xray MVP

One grant has a strictly IPv6 primary landing and an independently authorized
IPv4 landing, identified by optional `IPv4EgressID`. Both peers must be ready,
distinct from each other and the entry, and match the grant. `ExitFamily`
describes the FINAL exit, not the private SOCKS transport's address family.

The artifact is one deterministic official Xray JSON configuration. There is
no custom core, Lua script, auxiliary runtime file, or Agent DNS daemon:

- Built-in DNS uses `UseIP` to query A/AAAA through explicit local DoH servers.
- Routing uses `IPOnDemand`, with the scoped `::/0` rule before `0.0.0.0/0`.
- The two SOCKS outbounds use `targetStrategy: ForceIPv6` and `ForceIPv4` to
  resolve the DESTINATION to their respective families, not the SOCKS server.
- Routed UDP, management ports, and private/reserved destinations are blocked
  before family selection. A user-wide final block prevents unresolved or
  incorrectly scoped routed credentials from escaping to native/direct traffic.

This is DNS-result-based IPv6 preference, not a strict AAAA-evidence protocol.
No available IPv6 result plus an IPv4 result selects the IPv4 exit; an empty
result is blocked. It does not prove confirmed AAAA NODATA separately from a
partial DNS failure, bind routing and outbound lookups into one atomic DNS
snapshot, or promise original-target precedence over a sniffed hostname.
Existing HTTP/TLS hostname recovery remains enabled. An unrecovered raw
Fake-IP/reserved destination is blocked; there is no server-side FakeDNS map.
The landing's existing public-target and final-family restrictions remain
required, including after a DNS answer changes between lookups.

Connection failure never retries through another landing. There is no nested
proxy, loopback redispatch, HTTP replay, UDP/QUIC enablement, or NAT64.
Existing native and fixed single-exit routing/credentials remain available.
Only configurations containing a combination add the built-in DNS settings;
any explicit native family-resolution policy shares those settings too.

A subscription presents one combination labeled with both exit regions and
`IPv6优先+IPv4`. Both families share ONE routed credential and quota member.
Repeated same-label combinations retain deterministic readable sequence marks.
The UI keeps the existing compact React/shadcn controls and states these MVP
constraints without promising the removed strict DNS behavior.

Vastora owns schema 111, desired/applied authorization, atomic JSON deployment,
dual verified leases, and snapshot filtering. Pin its dependency to the actual
immutable Glivela commit before standalone CI/release; use only an external
`go.work` during joint development, never a committed local-path fallback.
Official Xray 26.7.28 already supports these routing/outbound settings. Native
family policies may independently require the host's newer official core.

Configuration, UI, authority, subscription identity, quota, and opt-in official
core lab tests are provided. CI's configuration gate invokes the pinned
official image without a custom build; it does not prove traffic reachability.
Present test source is not proof of execution or
acceptance. Signed catalog publication, managed application upgrades, program
releases, and production deployment remain separately authorized operations.

Official references: [routing](https://xtls.github.io/config/routing.html),
[DNS](https://xtls.github.io/config/dns.html),
[outbound targetStrategy](https://xtls.github.io/config/outbound.html).
