# REALITY target changes and forward recovery

This application-owned operation changes one existing
owned VLESS endpoint's target, reviewed public IP pin and exact SNI. It preserves
REALITY keys/short IDs, accounts, routes, subscription tokens and live ledgers.
It never selects or downloads another core. The installed hash-pinned Xray still
validates the complete configuration and performs native startup acceptance.

Open **REALITY target and SNI** in the independent Glivela panel. Read the current
endpoint before submitting. An authenticated administrator supplies the hostname,
reviewed public IP and SNI; ordinary TLS validation is not acceptance. Only an
active native identity and a current healthy runtime may start a new change.
The encrypted business source retains a bounded field-only transition record
(up to 32 per endpoint), not a copy of the database, credentials or accounting.
A failed or uncertain submission must be inspected, not blindly retried.

For a website hosted on the same entry, first upgrade the Vastora gateway and
Glivela runtime, then publish the site's public HTTPS route. Select **Use the
same-host Vastora managed site** and supply its exact SNI. The API accepts
`localTlsOrigin: true` with an identical `targetHost` and `serverName`, and an
empty `targetIp`. It pins the executable target to `127.0.0.1:24483`, retaining
the hostname in business/history records. Other local addresses and ports are
rejected. The trusted-certificate/TLS 1.3/X25519/H2 checks remain mandatory.
Vastora reuses Caddy's certificates on this loopback-only TLS listener, serves
only already-public websites, rejects unknown SNI and mismatched HTTP Host, and
excludes private/system routes. Normal proxied private destinations remain
blocked. This prevents the shared public 443 target from looping back to Xray.

For a shared 443 entry, explicitly prepare the new SNI route with Vastora's
existing publication workflow before applying. Preserve the old route for
recovery. This is not an atomic cross-application operation and Glivela does not
modify HAProxy, DNS or Vastora storage. After node startup acceptance, finish the
formal publication check and use the private candidate link in a trusted client
to test actual public HTTPS and the expected exit. The private Mihomo candidate
configuration reuses the normal subscription renderer, including its current
REALITY handshake options; importing a bare URI may not retain those options. Pure IPv6 direct entries do
not need a shared HAProxy route. Never publish the candidate link or screenshot
it: it contains an existing user's protocol identity.

During a pending change or recovery the endpoint and its dependent routes are
excluded from new subscriptions. Cached client configurations cannot be revoked
by hiding a subscription item; connections may briefly reconnect. Record the
SHA256 and actual time of privately retained acceptance evidence, confirming the
applicable publication check. This is explicitly **operator-attested public
acceptance**, not an independent server verification of the external evidence.
An exact fresh node receipt and valid entry health are still required; a manual
statement cannot override them. Evidence must follow the change, the current
worker generation start and be at most 15 minutes old.

A pending change can be cancelled with a reason. Cancellation restores only the
previous target/SNI/pin at a new forward revision; it never restores an old ledger,
changes a key or lowers a revision. Restore the original shared SNI route through
Vastora when applicable, wait for node acceptance, test the candidate link, then
record public acceptance before official subscription publication resumes. The
failed candidate and cancellation reason remain in encrypted history.

Interrupted controller projection writes rebuild only the explicitly recorded
latest target transition. Unknown identity/config drift remains refused. Native
activation recovery uses its existing checked Current/Candidate journal; manual
runtime-file tampering is not silently adopted or repaired by this operation.
No changes are made to UDP policies. The fixed local TLS exception applies only
to the native worker with that explicit target; it does not permit a subnet.

## Correct an invalid first local-origin registration

Fresh registration rejects target addresses or ports that the native worker
cannot use. Existing imported endpoints are not silently rewritten.

The panel exposes **Correct first registration port** only for an initial,
unlimited, unused native VLESS entry with one exact SNI and a wrong port pinned
to loopback. The entry must have no applied/historical runtime, traffic samples
or watermarks, previous target changes, forwarding routes or client chains. The
only allowed correction retains the original hostname/SNI and changes the local
TLS target to `127.0.0.1:24483`. Existing healthy entries still use normal changes.

These controller fields alone do **not** prove the worker never ran. Before
correction, the administrator must use an authenticated connection to the exact
host, verify its installed native worker and certificate/configuration identity,
stop its Glivela management process, and inspect the existing activation state
under its exclusive lock. There must be no Current or in-flight activation or
recovery journal, active core process, or proxy listener. A rejected standalone
candidate configuration is not an applied runtime and must not be fabricated or
removed to pass this check. Keep this node stopped until the correction is
confirmed. Do not stop or change any other node.

Retain the full evidence privately, without keys or subscription URLs, and submit
its SHA256 and actual verification time (at most 15 minutes old). The panel binds
this **operator attestation** to the inspected node certificate, desired config
hash and expected revision. The API action is `repair-initial`, with
`initialRepair: {certificateId, configSha256, evidenceSha256, verifiedAt}` and the
usual `entryId`/`expectedRevision`. It does not accept a general replacement
address, credentials or configuration. A stale identity, revision or hash fails
closed; refresh and recheck instead of repeating an uncertain submission.

The encrypted target history retains this attestation separately from subsequent
public-client acceptance. The ordinary forward revision/projection recovery path
is reused, so an interrupted projection write can recover the exact committed
change. Resume the worker only after reading back the recorded correction. A
lost response requires inspection first; do not restore a database backup over
live accounting. The invalid old port cannot be restored through `revert`.

Node TLS, certificate, configuration and authenticated proxy checks remain
mandatory. Use the existing private candidate, formal public-ingress checks and
actual HTTPS client acceptance before `accept` enables subscription publication.
A correction or administrative attestation does not assert a working node.

Source delivery and CI are separate from publication and production acceptance.
Existing required CI remains the source verification gate. Deployment must still
verify a real authenticated client and retained identities/accounting before
continuing to the next entry.
