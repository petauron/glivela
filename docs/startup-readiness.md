# Startup-only route readiness

Activation, upgrade and a new Xray worker generation require the entry's own
REALITY warmup and authenticated direct HTTPS acceptance. Configured landing
peers are then checked independently within a maximum 20-second startup budget, reserving time to confirm closed
fences before the unchanged overall startup deadline.
A failed or unverified peer retains its exact owned closed fence and reports
blocked startup status; it does not reject the direct entry or another accepted
peer. Entry process/identity changes, cancellation and unconfirmed firewall
ownership remain activation failures. Overall entry readiness remains bounded to 25 seconds.
Peers that fail this initial budget remain fenced and retry startup acceptance
serially in the background, starting after 5 seconds and backing off to at most
60 seconds between rounds. Each attempt has a 20-second check budget and repeats
the enrolled identity, exact worker generation/configuration, authorized transport
and real exit checks. Only successful acceptance removes that peer's owned
closed fence. Accepted peers leave the retry list; no worker is created when all
peers pass. Stop or reconfiguration cancels and joins the old retry worker before
changing its gates. No configuration revision, credential or ledger is rewritten.

Glivela caches acceptance for the exact process, configuration and revision.
The legacy Agent landing executor also checks once at activation. Closed startup
fences are removed only after that peer's acceptance; static peer/source firewall
isolation stays.

Running workers do not periodically probe external HTTPS targets, renew timed
permissions, or interrupt traffic because a test target fails. Completed route
challenges do not expire or automatically retry by age. Explicit diagnostic
requests remain possible; pending challenge admission keeps its bounded replay
window. Heartbeats still validate local process/configuration state.

Subscriptions follow configured authorization: account expiry/quota, credential
revocation, manual disable/suspension, endpoint retirement and exact enrolled
configuration/transport identity still apply. Missing/stale runtime receipts,
probe failure and changed observed exits do not hide authorized entries or client
chains. Route health remains visible as verified/unverified in the business view;
publication never manufactures a successful health receipt. Runtime activation
and cutover acceptance remain separate and keep their existing security gates.
Saved snapshots cannot override authorization rules. Center schema 120 invalidates old timed
route authorizations once, preserving configuration, credentials and accounting;
compatible upgraded nodes must send new startup acceptance. The existing
forward-only migration path backs up first and fails closed on errors.

Manual firewall confirmation remains separate: it requires nonempty recent
startup evidence obtained after the firewall application. Diagnostic retention
never launches probes. Glivela and Center releases/deployment require separate
authorization.

This document supersedes earlier descriptions of periodic health leases,
success/failure streaks and probe-triggered withdrawal in existing documents.

Native REALITY initialization uses the exact locally bound worker listener after
process/listener ownership verification. Published host ports may not support
self-connections (NAT reflection or Docker hairpinning). The installed plan and
advertised addresses are unchanged; deployment acceptance verifies public ingress
from an external client. Startup still authenticates REALITY and target HTTPS and
retains all fixed-route exit and peer checks. There is no periodic runtime probe or automatic configuration fallback.

IPv4 worker listeners require PROXY v2. The temporary readiness client uses the bundled Xray Freedom transport dialer to send that header before REALITY; IPv6 listeners retain their direct transport. No extra dependency, relay service or production listener is introduced.

The authenticated native HTTPS response must contain a public observed exit.
For explicit `ipv4_only` or `ipv6_only`, its address family must match the plan.
For `auto`, acceptance proves a working exit, not that both IPv4 and IPv6 work;
the new TCP dialer handles unavailable address candidates during actual requests.
This adds no periodic connectivity probe or node capability cache.
