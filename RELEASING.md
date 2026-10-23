# Version releases

## Private landing SS2022 cutover

Only the private entry-to-landing transport changes. Keep listener addresses,
ports, source policies, resolver configuration, public exits, account identities,
subscriptions and the existing cumulative ledger. SS2022 uses the bundled core
and `2022-blake3-aes-128-gcm`; keys remain in private configuration, never logs,
command-line arguments or release artifacts. There is no protocol fallback.

For each landing, back up controller/node state and the installed programs first.
Hold the existing node-directory lease by stopping the entry management loop;
do not independently restart its Xray. Run `prepare-private-transport --config
<owned-bootstrap>` for each participating entry. Preparation removes its owned
proxy listeners, requires established sockets to drain, installs an exact
temporary client-ingress exclusion, samples the same process, saves the private
checkpoint, obtains controller accounting acknowledgement, and only then stops
the worker. Neither a quiet counter interval nor a periodic report proves drainage.

The administrator's private transport transaction must include every participating
entry and the landing's exact revision/hash. Final samples older than one minute
are rejected. Explicitly deferred sources remain deferred, not marked tested.
After the paired desired-state transaction, use `complete-private-transport
--config <owned-bootstrap>` on each entry. The node rechecks freshness before
activation, keeps ingress excluded through failure recovery and accounting
acknowledgement, and archives the checkpoint before normal management resumes.
Verify the landing, the public subscription and actual double-hop traffic before
moving to the next landing. The temporary exclusion never permits new ingress.

If preparation expires before the paired commit, use `cancel-private-transport
--config <owned-bootstrap>`. An expired sample can cancel its already-accounted
preparation, but cannot authorize a switch. Lost acknowledgements do not justify
resetting counters: an unacknowledged original process is retained and its
listeners restored in that same generation. Controller acknowledgement of the
restored worker is required before client ingress is restored.

After a paired commit, recovery is a new monotonic transaction using retained
execution configuration and fresh final samples, never a database restore. Keep
the failed checkpoint and ingress exclusion. Collect actual counters again from
any restored old generation; never relabel an expired sample with a new timestamp.
Use the recovery transaction only for the retained transport. Every completed
entry that has resumed traffic must be prepared again before reversing the pair.
Do not remove checkpoints, force old revisions, fabricate health, relax ownership
checks or clear accounting to unblock a failed operation.

## Preserving an existing local resolver

New native entries permit only TCP/UDP destination port 53 to nameservers read
from the root-owned effective resolver file (the checked override below, or
the host resolver). Other private destinations remain blocked. No DNS value is
accepted from a remote desired document. Resolver changes after activation fail
exact firewall verification; this release does not silently replace existing
firewall policy or migrate already-active entries. Roll out to new takeovers
only and verify DNS plus real routes before activating traffic.

Native Xray services accept one narrowly checked administrator-owned drop-in:
`/etc/systemd/system/<owned-unit>.d/90-preserve-dns.conf`. Its entire content
must be `[Service]` followed by a single `BindReadOnlyPaths` line mapping
`<installation-directory>/<logical-service>/reality-resolv.conf` to
`/etc/resolv.conf`, with a newline after each line. Both files and all parent
directories must be root-owned, not symlinks, and not group/other writable.
The loaded read-only mount must match exactly. Other drop-ins and additional
directives remain rejected, as do changes to the installer-owned unit hash,
worker identity or stale systemd state. This does not change system DNS or
configure a resolver automatically; existing resolver content is retained.

Before migrating a locally repaired unit, back up its program, configuration
and state. Move only its existing resolver mount to the checked drop-in and
restore original installer-owned files from hash-verified backups. Do not
rewrite ownership receipts to bless local modifications. Upgrade through the
normal signed package flow; verify the effective resolver, subscription and
actual proxy route before accepting success. On failure retain the failed
task and restore working program/service files without rewinding live state
or usage counters. No platform installer change is needed.

## Runtime roles

The controller and its management UI remain a nonroot Docker application,
without a Docker socket or host-network privileges. Both entry and landing
machines install the Glivela node and official Xray as native systemd services;
new nodes do not require Docker. There is no Docker entry runtime fallback.

The signed native namespace produces `vastora-pkg-glivela-node.service` and
`vastora-pkg-glivela-xray.service`. Application IDs, private configuration and
state directories remain instance-scoped; readable unit names do not authorize
adoption or overwrite. An existing foreign unit is a collision, not an alias.
The manual nonroot worker receives only its configuration credential snapshot.
The entry declaration grants CAP_NET_BIND_SERVICE for existing low-port HY2
listeners, not root, NET_ADMIN or arbitrary capabilities. The root node owns
firewall changes and direct controller communication for both roles.

Existing Docker entries require an explicit backup-first native handover of
installation ownership and private backend bindings before activation. Preserve
public subscription identity, credentials, ports and history. Keep stopped old
resources solely as recovery evidence; source CI or a running new service is
not successful migration. The full installed handover remains a release gate.

The existing release job packages both verified architecture bundles into the
scratch controller image at `ghcr.io/petauron/glivela`, with source provenance.
No new Actions artifacts or container acceptance tests are introduced. The
draft Release includes `glivela-controller-image.json` containing the immutable
image digest; the signed catalog must use that digest, not a floating tag.
The image contains no shell, package manager, Docker socket or systemd; packaging
the bundled core does not grant the controller host execution permissions.

Controller bootstrap and state use retained volumes; certificate files also
use a retained private volume so offline administration can reuse the same
paths while the controller is stopped. Generic upgrades preserve these files,
not regenerate credentials or initialize application data. The control listener
remains private mTLS, and subscription traffic uses its separate private origin.

The controller runs as `65532:65532` on an ordinary bridge. Port publication is
restricted by the existing installer to the approved private host address; the
controller binds a concrete private container address, not every interface.
The state volume must remain private (`0700`) and writable by that UID. Bootstrap
and TLS files are private (`0600`) and readable by that UID; their parent paths
must be traversable. The image's initial ownership is not proof of an existing
volume's ownership. Inspect the actual retained volumes and imported files
before starting; do not recursively chown an unknown volume to force startup.
Wrong ownership must remain a failed startup/installation, not be acknowledged
as successful migration. Initial staged installation checks the control port
only; a subscription origin is not expected until owned data is activated.

If image publication succeeds but a later draft-release step fails, do not
overwrite the existing version image. First independently inspect that image's
immutable digest, source provenance and both platforms against the exact checked
release SHA and retained draft assets. Recover the image metadata asset and
checksums in the still-private draft only after that verification; then resume
the existing draft-asset verification/publication steps. A mismatched image or
already public release must never be repaired by moving tags or replacing assets.

## Native uninstall boundary (MVP)

### Staged entry quotas

For sequential handover with the existing subscription/ledger owner retained,
the authenticated entry enrollment accepts a `quota` seed: exact total bytes,
current period usage, reset day/timezone, last/next reset timestamps and final
drained sample time. Back up and stop the old writer first. Do not replace the
seed with zero usage or unlimited policy. The controller persists enforcement
and sampled cumulative forwarding counters atomically with desired policy;
period resets never reset these cumulative forwarding counters. The original
account ledger remains authoritative, and must consume the staged receipt
projection with its matching transition adapter before migration is accepted.

Quota exhaustion removes native and routed credentials through the existing
Xray configuration application; the next calendar cycle restores the retained
authorization flags. This is sampled enforcement, not an exact per-byte cutoff.
Samples spanning a reset are conservatively charged to the new period; lifetime
sampled bytes are retained. A staged entry cannot be overwritten through ordinary
enrollment or loaded alongside a second owned-business ledger. Existing entries
without a quota projection are unchanged. Do not seed an already exhausted old
projection: its disabled credentials do not prove the original enabled inventory.

Local official-core acceptance checks authentication denial/recovery using
anonymous loopback VLESS and verified HTTPS. It is not proof of deployed REALITY,
systemd/firewall enforcement or full subscription/double-hop acceptance; verify
those on each separately authorized entry before moving to the next.

For the one-time entry migration, the installed native node must remain stopped
while the original writer is stopped and the exact source container is verified
stopped with restart disabled. `stage-native-entry -config <persistent-owned-bootstrap>
-checkpoint <private-source-snapshot> -desired <private-typed-desired>` verifies
the original application identity, source configuration snapshot and loaded
installer-owned native unit before staging its initial revision. It never
installs units, changes public bindings, starts Xray, or modifies source data.
Repeated staging accepts only the same source proof and initial revision;
pending recovery or an existing different revision cannot be reset. Keep both
node and old writer stopped until the separate installation/ingress ownership
handover is complete. Staging is not route acceptance or a successful upgrade.

Both native services are declared installer-owned resources. The generic
uninstaller verifies ownership and backs up/stops their running set before
removing declared files. It does not need proxy semantics or a lifecycle RPC.
Use data-retaining uninstall: configuration, identity, history and recovery
backups must not be purged as part of migration.

First stop the Glivela node service, then run the installed Glivela binary as
root with `retire-node -config <persistent-owned-bootstrap>`. The node directory
lease rejects a still-running writer. Retirement verifies the owned worker,
backs up its committed configuration and persists retirement before stopping
Xray. Only after independent stopped-process readback does it remove the exact
Glivela-owned firewall/gate rules. Unknown or modified rules fail closed. A
failed command must be retried and inspected, not followed by uninstall.
Retirement retains all node data and prevents automatic startup/reconciliation
from reviving the worker. Then use Vastora's data-retaining uninstall. This
two-step boundary keeps proxy cleanup in Glivela, not the platform.

The offline `retire-entry` command applies only to an old Docker checkpoint,
not a new native installation. Retained old containers are one-time migration
recovery resources; their retirement requires independent stop/read-back and
route acceptance before separately authorized cleanup. They are not discovered
or deleted implicitly by uninstalling the new native service.

Release Please v5 is pinned to 45996ed1f6d02564a971a2fa1b5860e934307cf7.
Like Vastora, it uses only the built-in GITHUB_TOKEN; no extra release secret or
personal token is needed. Repository settings must allow Actions to create pull
requests. Existing branch protection and required CI remain mandatory.

After a push to main, the release workflow waits (at most 30 minutes) for the
exact commit's normal CI to succeed. It then creates the release, finishes
publication, and maintains the next version PR. Review and merge that PR rather
than bumping versions or creating tags manually.

GITHUB_TOKEN-created tags do not start another release workflow, and generated
PR workflows can require manual approval. The release workflow explicitly
dispatches ci.yml on the version PR branch to run the existing checks.

These are source-code releases, not automatic production deployments.

Native runtime distributions are also built from the exact Release Please SHA
for Linux amd64/arm64. They contain Glivela, the unmodified official Xray
26.7.28 executable, licenses and runtime source/digest metadata. Upstream ZIP
SHA256 values are pinned in `scripts/build-native-release.sh`; version changes
require review of those pins. No build downloads or executes an unpinned core.
CI builds twice, compares the outputs and tests bundled amd64 Xray with a local
TLS fixture. It retains no downloadable Actions artifacts.

Publication builds twice, uploads only the two runtime distribution archives,
the two separate offline migration-tool archives, and
`SHA256SUMS` directly to the draft Release, downloads and compares every asset,
then publishes the draft. On a failed upload retry, existing draft assets must
match exactly; they are never overwritten. A mismatch requires investigation,
not moving a tag or replacing a published asset. Source publication does not
change signed catalog pins or install/upgrade any running instance.

The offline archives contain the already-approved isolated legacy export module,
source/schema metadata and dependency license notices. They are not installed in
controller/node runtime bundles. SQLite remains absent from both runtime roles;
the one-time export reads only a frozen backup, never a live Center database.
Its separately invoked local capture/adoption commands require explicit stopped-
writer evidence; archived tasks are never re-enqueued.

Runtime distributions also include the reviewed UI bundle and CSS, whose
digests are recorded in runtime.json. A controller configured with
managementUI=true serves them on its existing private mTLS listener. Only
enrolled administrator certificates can open the UI/API; node certificates and
the public subscription listener cannot. Browser use requires the same trusted
client certificate/CA, not a Vastora session or credentials stored in JavaScript.
Publishing source/runtime assets still does not update the signed catalog or
upgrade production; those remain separately reviewed operations.

Local workflow edits alone do not activate releases. Push/review the changes,
then verify the first version PR CI and release run before calling the migration
complete. No local builds or tests are implied by this configuration change.

CI builds and checks the UI but does not upload its bundle as an Actions
artifact. The signed application catalog remains the publication channel.

## Independent UI catalog build

When the catalog first selects a released commit containing the independent UI,
remove its Vastora source checkout, Vastora npm installation and
`VASTORA_WEB_SOURCE` setup from both reproducibility build passes. Each pass
must build only that immutable Glivela commit with `ui/package-lock.json`.
Keep existing integrity, reproducibility, signing and revision gates.

Do not remove those inputs from a catalog still pinned to an older Glivela
commit that requires them. Advancing the catalog pin and its build recipe is a
separate reviewed publication; installed applications are not upgraded by this
source change. No Vastora program release is required for this UI build change.
