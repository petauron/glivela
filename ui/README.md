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

`src/index.tsx` exports `apiVersion = 1`, `mount` and `mountManager`. Each mount
returns `update` and `unmount`. Glivela owns the React tree and its cleanup.
The host passes data and management callbacks described by
`src/app-workspaces/types.ts` and `src/host-contract.ts`. These are local wire
contracts, not imports of the host implementation. Changes to that interface
require coordinated contract review; a breaking change requires a new API
version.

This step separates **build ownership**, not backend ownership. Center still
provides authenticated same-origin APIs, SSE, host data and platform actions.
`src/api.ts` includes only operations used by this UI, preserving CSRF and
same-origin credential handling. Center must authorize every API request.
Host theme tokens and the application window remain runtime integration points.

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
