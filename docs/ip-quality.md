# IP quality, unlock and assessment diagnostics

The **诊断 → IP 质量与解锁** section reads Glivela's own authenticated
`POST /v1/admin/ip-quality` API. Reports, provider scores, IPPure evidence,
per-service region/unlock results and the original versioned IPv4/IPv6 assessment
rules are owned by this repository. There are no live reads of Center's database,
Vastora `/api/v1/ip-quality`, or its task broker. The existing optional panel
transport is only an authenticated reverse proxy, not a business API.

## Historical data and preservation

Reports are stored separately in private `quality.json` (0600, atomic replacement,
32 MiB / 4096 exact host-address records maximum). This is the same latest-per-IP
retention model as the old table. Rechecks retain the previous report and its
original acquisition time until a valid replacement is received. Failures and
missing evidence never become zero risk or successful unlock. Retired/unmapped
addresses remain visible as history, without permission to run a new probe.
Reports older than the existing 24-hour evidence window remain inspectable and
are marked expired; they cannot be mistaken for current measurements.

The existing encrypted controller backup/restore includes the quality file.
Restore marks captured pending/running diagnostics interrupted instead of resuming them.
This does not change accounts, credentials, subscriptions, route permissions,
usage counters, accounting baselines or desired node state.

### Offline export and explicit import

Use the existing isolated SQLite module; SQLite is not a runtime dependency:

```sh
cd tools/legacy-export
go run . quality -database /private/path/center.db -output /private/path/quality-import.json
```

Prefer an already verified consistent backup covering the needed history. The
export command can also read a live WAL database through a read-only SQLite
transaction; it does not use `immutable=1`, copy a live database file, or modify
the source. Output is created exclusively with mode 0600; it contains private
host/IP/report data and must not be committed, logged or sent to a public issue.
It includes all rows, normalizes abandoned in-flight work to `failed/interrupted`,
and preserves reports/timestamps without creating execution authority.

Send that file as the JSON body of an explicitly authorized authenticated
`POST /v1/admin/ip-quality` request. The importer validates the complete batch
and atomically adds missing exact host/address pairs. Existing pairs win and are
not overwritten, including newer independent reports. Repeat import is safe;
compare the returned report identities/timestamps/counts privately before
retiring the source. Import never enrolls a node or changes business ownership.

## Manual node measurement

An administrator selects an enrolled host's exact public exit identity. Entry
advertisements may be DNS names; public interface hints and prior report IPs
remain selectable under that same host/runtime binding. A hint is an expected
result constraint, never a network destination or business configuration grant.
A changed/stale IP fails report matching and keeps the previous report intact.
Only a recently polling diagnostic worker enables the check button; older node
programs and offline hosts cannot queue a job they cannot execute. The controller
creates one bounded job per node and binds it to the enrolled leaf certificate,
configuration revision, exact address and five-minute expiry. A node cannot
nominate a target or read other nodes' reports. The node polls its own
`/v1/ip-quality` channel; polling itself never triggers measurements. Old or
replayed reports cannot update a newer job, refresh timestamps or cross identity
boundaries. A result must match the expected public exit IP.

The original reviewed xykt/IPQuality image digest and script commit/hash are
retained. There are no new Go/npm packages. The Linux executor requires Docker access. It first checks the local image and
only pulls the exact approved digest when missing, within the job deadline.
Container execution itself uses `--pull=never`; no mutable tag is resolved.
A failed download remains a failed diagnostic, never a clean/zero result.
The detector runs as UID 65534, without capabilities, with a read-only rootfs,
32 MiB tmpfs, 128 MiB RAM, 0.5 CPU, PID and timeout limits and no host mounts.
It uses the host network to measure the selected host exit; IP mismatch fails
closed. Container cleanup is limited to its generated job name and must succeed
before a successful result is returned. This is a direct exit diagnostic, not
proof that a client-to-entry or chained proxy route is working.

Only explicit user-triggered checks contact upstream providers. There are no
scheduled end-to-end checks, no automatic withdrawal/disconnection, and no
changes to quota, credential revocation or manual suspension policy.

## Quality list and unlock details

The controller navigation exposes **质量与解锁** directly. Node rows show a
separate summary for each bound public exit address and open that runtime's
quality records. The list retains historical/unbound addresses; expanding a
record shows its score, evidence, check time and manual measurement control.

Unlock details group the existing seven supported services into streaming,
AI and other categories. Only an explicit `yes` counts as unlocked. Limited
availability, failed detection and unknown results retain their own labels;
no missing result implies an IP ban. Expired, detached or unsuccessful-check
reports are marked historical. Address families and exact node/address matches
remain separate, so a healthy report for one exit never fills another exit.

The interaction was researched against the MeowX provider badges documentation
and `mmwx-group/meowC`'s unlock badge/catalog. No third-party source was copied
or dependency introduced. Additional services supported by that project are
outside this display-only change.
