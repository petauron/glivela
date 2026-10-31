# Releasing Glivela

## Source and version

Use the existing Release Please workflow and generated version PR. Keep
`.release-please-manifest.json`, `ui/package.json` and both package-lock version
fields aligned. Do not manually move tags, overwrite published assets or bypass
required checks.

The release workflow uses the built-in `GITHUB_TOKEN`, minimal job permissions and
a reviewed full SHA for Release Please. Actions must be allowed to create PRs.
Generated version PRs need real CI checks on their exact head; dispatch the
existing workflow only when those checks did not start.

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
checksums in the draft GitHub Release, download and verify the assets, then
publish the draft. A retry may reuse an exact verified draft asset; it must not
replace a mismatched file or modify a published release.

The controller image at `ghcr.io/petauron/glivela` must match the source SHA and
both supported platforms. Use its verified immutable digest in the signed catalog.
Failed image publication requires inspection and recovery of the existing draft,
not moving an image tag or claiming that a skipped publish job succeeded.

## Catalog and installed applications

A Glivela source release does not publish the signed application catalog or
upgrade an installed controller/node. Those are separate authorized operations.
Build the independent UI from the immutable Glivela source and its lockfile;
preserve catalog integrity, signing and monotonic revision checks.

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
