# Glivela product identity

Glivela is the new product name of Meridian. This is an in-place product rename,
not a new application or a fork. Vastora remains the control plane; Senulun is
the monitoring product.

## Stable installation identity

The following are permanent machine contracts, not old implementations or
runtime aliases: the Go module/package `github.com/petauron/meridian`, catalog
ID `meridian`, capability `meridian-runtime`, `/api/v1/meridian` routes, persisted
field names, and `ui-meridian-<version>` signed asset names. Changing a display
name must not create new accounts, subscriptions, credentials or installations.
There is one implementation and one set of endpoints. Do not introduce a second
`glivela` application ID, shadow database or fallback API.

The source repository keeps its existing URL while these PRs are reviewed.
Renaming GitHub repositories is a separate administrative operation: update and
verify module/source pins, CI source identities, documentation and provenance
consumers together before changing those coordinates. Do not republish old
assets or reuse old tags under new names.

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
