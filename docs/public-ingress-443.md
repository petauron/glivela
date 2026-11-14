# Managed public REALITY 443 and dual-stack ingress

One owned public IPv6 endpoint can use TCP443 directly. An optional exact public
IPv4 socket uses the same443, credentials, REALITY keys, route authorization and
user counters. Its advertised hostname remains the original independent ingress
name, with managed AAAA/A records. SNI and egress address-family policy do not change.
SS24000 and UDP443 policy are outside this operation.

## Preparation and transition

1. Keep a consistent pre-change controller recovery point and record the current
   endpoint revision and website mode. Do not copy live databases directly.
2. The website manager explicitly delegates its public TLS socket while retaining
   the existing certificate, content and loopback TLS backend127.0.0.1:24483.
   The existing REALITY target must already use that backend. Unauthenticated
   HTTPS then falls through Xray to the same owned Caddy site.
3. Prepare the exact existing ingress DNS resource. For dual stack, add only the
   confirmed same-host IPv4 address to its IPv6 AAAA resource. Wait until both
   records are ready, then pass the public resource object to Glivela. Glivela
   receives no DNS provider credential and calls no platform business API.
4. Use administrator-only `POST /v1/admin/public-ingress` with `entryId`,
   `action: apply`, `expectedRevision` (decimal string), and `resource` containing
   `id`, `hostname`, `address`, `type`, optional `secondaryAddress`, `revision`,
   `appliedRevision` and `status: ready`. Both DNS families must resolve exactly
   to this resource. Omitted secondary address means IPv6 only.
5. Await the normal node receipt and startup warmup. Check the actual retained
   subscription and real proxy access through each family, plus ordinary HTTPS.
   Inspect uses the same endpoint with `action: inspect` and `entryId`.

The apply operation is revision checked and retryable after a lost response.
It retains account plans, tokens, protocol IDs, REALITY keys, resets and usage.
The node verifies ownership of both sockets and warms both before readiness.
This does not add runtime periodic end-to-end probes or automatic withdrawal.

## Forward recovery

Stop the unsuccessful candidate through the existing managed node lifecycle.
Restore DNS to the previously recorded address set and wait for its ready resource.
Use `action: revert` with the current revision and that exact resource; this
creates a new revision restoring only the previous port/socket tuple. Restore
Caddy public TLS through its explicit managed mode if needed. Never downgrade a
database or manually edit generated configuration, credentials or traffic data.

The optional Linux real-engine lab uses synthetic state in a NIC-free container
and a separate network namespace. It is opt-in; never enable its lab flags on a
production host. Installed service lifecycle and external network reachability
still require separately authorized deployment acceptance.
