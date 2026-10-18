# Version releases

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

Publication builds twice, uploads only the two distribution archives and
`SHA256SUMS` directly to the draft Release, downloads and compares every asset,
then publishes the draft. On a failed upload retry, existing draft assets must
match exactly; they are never overwritten. A mismatch requires investigation,
not moving a tag or replacing a published asset. Source publication does not
change signed catalog pins or install/upgrade any running instance.

Glivela source releases do not automatically package or deploy the UI in the
production catalog. That remains a separately reviewed catalog operation.

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
