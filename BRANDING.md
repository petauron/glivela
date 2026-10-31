# Glivela product identity

Glivela is the new product name of Meridian. This is an in-place product rename,
not a new application or a fork. Vastora remains the control plane; Senulun is
the monitoring product.

## Stable installation identity

The catalog ID `meridian`, capability `meridian-runtime`, `/api/v1/meridian`
routes and persisted field names identify existing installations and records.
They are not reasons to retain obsolete source implementations. Changing a
name must not create new accounts, subscriptions, credentials or installations.
There is one implementation and one set of endpoints. Do not introduce a second
`glivela` application ID, shadow database or fallback API.

## Canonical source identity

The source repository is `petauron/glivela` and the Go module path is
`github.com/petauron/glivela`, with Go package name `glivela`. React components,
source directories, CSS classes and diagnostics use Glivela as well. Consumers
must update their imports and pin a
commit containing the new module declaration (or a later reviewed release).
Do not add an old-path module alias or `replace` fallback. A pinned pseudo-version
can integrate the source migration without publishing a version or catalog.

The rename preserves Git history, tags, issues and PRs. Historical tags still
contain their original module declaration; do not move them or republish old
assets under the new identity. The catalog's existing UI source SHA and signed
asset names remain unchanged. New builds emit `ui-glivela-<version>` assets;
the paired catalog change binds versions after alpha.21 to that name. Release
Please uses the `glivela` package name while retaining the root manifest key,
tag format and version history.

Route-user and outbound-tag derivations retain their original byte values:
they connect deployed Xray counters and grants to the existing quota ledger.
Renaming those values without a coordinated ledger migration would reset the
accounting baseline. Published signed asset names remain immutable. Upgrade the
paired catalog library in Center before publishing the first canonical UI;
the protected publication workflow must then pin the released Glivela source
and matching Center dependency. It must not publish this PR under alpha.21.

## Release and managed upgrade

1. Merge the reviewed source change, then let Release Please create the next
   version PR. Never edit the version solely to force this migration.
2. Verify the exact version commit's CI. Separately update the catalog's pinned
   UI source SHA and recipe version to that released commit. The renamed UI
   must get a new version; never replace an already signed UI target.
3. Publish a new signed catalog revision through its protected workflow, then
   explicitly refresh and upgrade the managed application in Vastora.
4. The Center's forward-only display-name migration renames only exact former
   defaults. Custom names, account IDs, quotas, URLs, route state, and runtime
   ownership remain unchanged. No node restart is needed just for a label.

Source PRs do not authorize catalog signing, publication or production upgrades.
