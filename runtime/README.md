# Auditable target-selection runtime

Composite routes require the immutable Xray v26.10.10 source
`701af60772cda123492f86e383e1fdba066614a9` plus
`xray-target-selection.patch`. The patch changes no protocol, authentication,
listener, counter, dialer, TLS validation, or retry implementation. It adds:

- Lua access to the original target before HTTP/TLS sniffing;
- an explicit setter that pins the session's destination to a native IP slice,
  preserving its port, network, authenticated user, and original destination;
- an exact native successful-empty DNS predicate, distinct from NXDOMAIN,
  SERVFAIL, timeout, and combined errors;
- revision 1 of the target-selection capability and focused upstream tests;
- an exact capability marker in version/config-preflight output;
- routing Lua initialization in `run -test`, without opening inbound sockets.

These interfaces are missing from the reviewed upstream core. Merely upgrading
an official image to the same version does not supply them. Generated scripts
assert the capabilities during config preflight, before Vastora switches the
active config. The host also requires the exact capability marker: an official
image with an equal or newer version is rejected. The CLI regression proves
that an initialization error fails preflight without starting listeners.
There is no alternative routing implementation or compatibility fallback.

Why not loopback? Xray `DispatchLink` wraps the existing link's user counters
again, duplicating accounting. A routing-only lookup also does not pin the
actual SOCKS destination. The setter selects exactly one outbound without a
second dispatch, a second DNS lookup, or a second counter wrapper.

Why not parallel A/AAAA? Successful A can hide an AAAA error, and separate
responses can straddle a cache generation. Generated routing Lua performs one AAAA
query first; only the exact successful-empty result permits its A query. The
Agent's A response is empty if fresh evidence now selects IPv6. This race fails
closed rather than changing exit families. TTL-zero answers are usable for the
current selection but are not cached by the Agent.

The existing per-server Lua DNS API is reused directly. The managed server is
excluded from ordinary DNS fallback, so native and fixed-exit resolver behavior
is not changed. There is no extra global DNS script or DNS-policy interpreter.

`Dockerfile` builds and tests this source; it does not publish an image. No
workflow in this change releases or deploys it. Before managed deployment,
independently review the source, pass the controlled host runtime lab, build
and attest an immutable image, and publish a separately authorized signed
application catalog revision referencing that digest. Never rewrite a reviewed
catalog fixture or use an unreviewed mutable tag.

The changed Xray files retain their upstream MPL-2.0 license. Their complete
corresponding source is reconstructible from the pinned public upstream commit
and the source-distributed patch. The runtime includes the upstream license.
The Glivela project license does not replace Xray's license.
