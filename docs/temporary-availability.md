# Temporary node availability

Glivela administrators may temporarily withhold a known node using the existing
management mTLS UI/API. This is distinct from a network failure and from
permanent retirement. No source authorization, subscription identity, DNS,
configuration, counter, quota or historical record is deleted or reset.

Use the existing control page's temporary availability form. Select traffic
exhaustion or maintenance, and either the configured next reset time, an explicit
future time (displayed in the browser's timezone), or manual recovery. The API
`POST /v1/admin/availability` with `{}` reads the revision. Mutations require
`id`, `reason`, optional RFC3339 `resumeAt`, and `expectedRevision` as a decimal
string. `reason=resume` starts fresh verification; it does not assert success.
Only an enrolled node, enrolled route source, or retained business identity is
eligible. Nodes cannot grant themselves an exemption.

Existing quota enforcement remains authoritative and disables credentials when
the recorded period allowance is exhausted. Temporary manual suspension is
publication/acceptance policy, not a remote power-off or guaranteed termination
of already cached client connections. It withholds subscription publication and
route-check dispatch for that source. Existing automatic quota reset still only
resets period usage; lifetime counters and forwarding watermarks remain intact.
Do not infer traffic exhaustion merely from a missing heartbeat.

Landing acceptance retains the complete source allowlist. Explicitly suspended
sources are returned as `deferredEntries`, never as passing probes. At least one
active source and every active source's fresh successful authenticated check are
required. The cutover journal retains the deferred IDs and availability revision.
Unexplained offline/failing sources still block acceptance. Before cutover, review
the exact deferred inventory; do not mark unrelated failures as maintenance.

At the scheduled time, probing becomes eligible again. Publication still needs
fresh runtime/route evidence after the recovery barrier and the existing security
and policy checks. An expired suspension cannot authorize a missing route check.
If the provider has not restored networking, the route remains unavailable. A
legacy source not yet enrolled in Glivela still needs its ordinary enrollment;
time alone never invents that identity or imports its old ledger.

Availability is persisted atomically in private `availability.json` alongside
the controller state and included in encrypted controller backups/restores.
Keep it with the state directory during upgrades. Invalid files fail startup.
Restored cached runtime observations remain invalid until fresh reports arrive.
No platform installer change or new dependency is required.
