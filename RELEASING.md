# Releasing Glivela

## Source and version

Use the existing Release Please workflow and generated version PR. Keep
`.release-please-manifest.json`, `ui/package.json` and both package-lock version
fields aligned. Do not manually move tags, overwrite published assets or bypass
required checks.

## Automated version PRs

The `release-pr` job in `.github/workflows/release-please.yml` mints a
short-lived, repository-scoped installation token from the minimal-permission
organization GitHub App (`petauron-nova`: `contents: write` and
`pull-requests: write`, configured via organization variable `RELEASE_APP_ID`
and organization secret `RELEASE_APP_PRIVATE_KEY`). Because the version PR is
created and updated by `petauron-nova[bot]` rather than `GITHUB_TOKEN`, GitHub
automatically triggers the existing `pull_request` CI and CodeQL checks without
requiring manual workflow approval or local version-PR scripts.

Wait for all required checks on the actual version PR head and merge through
the existing branch rules. Do not manually bump versions, close/reopen PRs, or
manufacture status checks to bypass approval.

After the version PR is merged, actual CI and draft-release publication retain
the built-in `GITHUB_TOKEN`, reviewed Action SHA and minimal permissions. Existing
CI jobs, code scanning, branch protection and immutable publication checks remain
in force. This workflow change does not authorize an application upgrade.

## First publication from a clean repository

The tracked manifest uses standard pre-1.0 semantic versioning (`0.x`, graduated from the earlier `0.1.0-alpha.*` prerelease baseline). `bootstrap-sha`
points only to this repository's clean root, so Release Please calculates its
next version from newly reviewed releasable commits. Do not import historical
refs or recreate an earlier version: the existing OCI namespace and tags remain
immutable. The first authenticated image push must use this repository's normal
GITHUB_TOKEN and existing package Write grant; no PAT is required.

Before an authorized managed upgrade, retain issued subscription labels and any
explicit existing host firewall selection as described in
[operator-owned configuration](docs/operator-configuration.md). No installation
identity, program storage, subscription origin or ledger is reinitialized.

## Required checks

Preserve the existing CI jobs: backend verification, UI/dependency checks, native
runtime distributions and official-core configuration acceptance. Preserve code
scanning and required branch gates. CI uses loopback or isolated synthetic
fixtures, never production routes.

CI retains bounded build/dependency caches and no downloadable Actions artifacts.
Docker build records remain disabled. Source CI success does not deploy anything.

## Immutable distribution

Publish only from the immutable, checked Release Please commit on protected
`main`. Use that SHA/tag consistently for checkout, builds and provenance.

`scripts/build-native-release.sh` packages Linux amd64/arm64 Glivela, the pinned
official Xray core, the reviewed iperf3 binary, UI assets, metadata and licenses.
The offline migration-tool module is distributed separately and is not a runtime
dependency. Core changes require reviewed architecture digests and matching
existing acceptance inputs.

Build twice and compare outputs. Stage distribution archives, image metadata and
checksums in the draft GitHub Release, download and verify the assets, emit SLSA
build provenance attestations (`actions/attest`) for the distribution archives,
image metadata and multi-platform controller image, then publish the draft. A
retry may reuse an exact verified draft asset; it must not replace a mismatched
file or modify a published release.

The controller image at `ghcr.io/petauron/glivela` must match the source SHA and
both supported platforms. Use its verified immutable digest in the signed catalog.
Failed image publication requires inspection and recovery of the existing draft,
not moving an image tag or claiming that a skipped publish job succeeded.

## Catalog and installed applications

After the source release publishes on protected `main`, the non-blocking
`notify-catalog` job mints a short-lived `petauron-nova` installation token
scoped solely to `petauron/catalog` (`contents: write`) and sends a zero-payload
`repository_dispatch` (`catalog-reconcile`) wakeup signal. That signal carries
no download URLs, digests or signing authority: `petauron/catalog` independently
discovers the release, verifies its protected source commit, CI, SLSA
attestations and `iperf3`/runtime contracts, mirrors the native archives, builds
the independent UI from the exact verified commit and lockfile, and signs the
monotonic `catalog-rN` revision under its own protected environment. Upgrading
an installed controller or node remains a separate operator action.

For an authorized upgrade, protect the necessary private state and installation
identity, upgrade one applicable pair, and verify actual client access and
subscriptions before continuing. Preserve account identities, credentials,
configuration and live traffic counters. Do not restore an old ledger or downgrade
a database to recover a program update.

Operational node inventories, installation receipts, private addresses, recovery
files and production acceptance evidence stay outside this public source tree.

## Runtime boundaries

- The controller/panel is a nonroot Docker application without a Docker socket or
  host execution privileges.
- Entry and landing services use native Glivela/Xray units and private state.
- Management remains authenticated and private; subscriptions use their separate
  origin and original account identities.
- Ordinary updates do not initialize empty business state, regenerate identities
  or automatically adopt an unrelated service.
- Stop and verify the old writer before an explicitly authorized ownership
  migration. Keep runtime data separate from source/distribution files.

See [controller safety](docs/controller-safety.md),
[landing handover](docs/landing-handover.md),
[public egress](docs/public-egress.md) and
[startup readiness](docs/startup-readiness.md) for the relevant operation.

## Core security updates

The baseline uses official Xray 26.10.31 and defaults Glivela's Go listeners to
MPTCP disabled. This mitigation does not fix CVE-2026-98432 in a host kernel.
Operators need a vendor-confirmed fixed running kernel; a container update does
not update the host kernel. Inspect applicable network namespaces and preserve
normal managed-upgrade and acceptance checks.
