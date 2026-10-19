# Version releases

## Runtime roles

The controller and its management UI remain a Docker application. Only the
host-side node executor and landing Xray use native services; there is no
controller systemd variant or Docker-to-systemd installation-record migration.
Entry Xray retains its existing container topology during takeover.

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

## Entry uninstall boundary (MVP)

Uninstall is deliberately two steps, not a Vastora lifecycle RPC. First retire
the entry in Glivela: stop its installed Glivela node service, then invoke that
installation's `glivela retire-entry -directory <private-node-journal>` locally.
The command requires the exclusive node lease, verifies exact container
ownership and a completed runtime journal, persists retirement intent, and
independently reads back the stopped container before reporting
`entry-retired-stop-confirmed`. A failed or interrupted command is not stop
confirmation; retry retirement before uninstalling. Node startup and provisioning
reject retired installation records.

Only after this confirmation may Vastora uninstall the declared application
services/files. Vastora neither discovers nor manages Glivela's containers.
Retirement retains the stopped container, private configuration, identity,
history and recovery records; it does not purge them or claim route success.
Do not use a data-purge option during this two-step uninstall. Cleanup of
retained resources is separate and must not be inferred from application removal.

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
