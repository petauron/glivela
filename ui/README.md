# Glivela application UI

## Independent build

All UI components, hooks, API clients, DTOs and tests live in this repository.
A checkout of Glivela and the locked npm dependencies are sufficient:

```sh
npm ci --prefix ui
npm run check --prefix ui
npm test --prefix ui
npm run build --prefix ui
```

No Vastora checkout, source symlink, environment variable or source revision is
required. The `@` alias resolves exclusively to `ui/src`. CI uses one checkout
and one npm installation. Dependencies are pinned by `package-lock.json`; CI
retains its dependency audit and bundle size/style checks.

## Runtime boundary

The new application-owned controller entrypoint is `mountControl`, served on
Glivela's private mTLS listener when `managementUI=true`. It uses only
`/v1/admin/*` on that same Glivela origin, never Vastora cookies or task APIs.
Its assets are included in the native distribution and bound by runtime.json
digests. Administrator client certificates must be enrolled; a node certificate
cannot access the page. Configuration-save feedback is distinct from applied
runtime and current route verification. The public subscription origin is
separate and cannot serve management pages.

`src/index.tsx` exports `apiVersion = 1`, `mount` and `mountManager`. Each mount
returns `update` and `unmount`, but mounts only an installation launcher. It
consumes generic application/service metadata and installation/update callbacks,
not account, route, diagnostic or traffic APIs or host business SSE. It opens the
private controller in a separate, explicitly labelled window; no token, host
cookie or credential is added to the URL. The existing host theme and application
window remain integration points. The controller itself serves the business UI
directly and authenticates it with its own administrator mTLS.

Unused legacy component/client sources and the superseded Center/Agent business
writer still require removal before #54 is complete. Do not treat a launcher or
standalone-page build as installed handover or production acceptance.

The tests cover page behavior, stream recovery, API transport and real page
mount/update/unmount. UI fixes and their regression tests are maintained here.
There is no recurring copy or synchronization from Vastora source.

## Publication

Build output is named from `package.json` and published through the separately
signed application catalog. Source CI does not deploy installed applications.
See `../RELEASING.md` for the catalog build transition.

## Source and license

The initial local component, model and test migration came from Vastora commit
`513d7bb0235e5cfdf8c112c5952b2aef32fee640`, under Apache-2.0, the same license as
this repository. This is provenance only, not an ongoing build pin.

The shared shadcn Tailwind utilities were ejected from `shadcn@4.21.0` into
`src/style.css`; their MIT notice remains in that file. Future style changes
are reviewed local source changes, not fetched through the generation CLI.
