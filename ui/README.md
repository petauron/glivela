# Glivela UI

## Development

The UI is independent of a Vastora checkout. Use its locked dependencies:

```sh
npm ci --prefix ui
npm run check --prefix ui
npm test --prefix ui
npm run build --prefix ui
```

The `@` alias resolves to `ui/src`. Vite builds versioned JavaScript and CSS
bundles; existing CI checks types, tests, dependencies, bundle sizes and styles.

## Runtime

`src/index.tsx` exports the Vastora host mounts and the standalone control mount.
The managed panel uses Vastora's authenticated application transport and a
server-side mTLS identity. The standalone panel requires an enrolled administrator
identity. Node and subscription credentials do not grant administrative access.

`GlivelaLauncher` opens `GlivelaControl`; the panel's workspaces reuse the backend
API and existing diagnostic controls. Business state and mutations belong to
Glivela. No production data or environment-specific node labels belong in fixtures.

See [panel access](../docs/panel-access.md) and [releases](../RELEASING.md).
UI build output is distributed through the signed application catalog; source CI
does not update installed applications.

## License and provenance

The initial component, model and test migration came from Vastora commit
`513d7bb0235e5cfdf8c112c5952b2aef32fee640` under Apache-2.0. It is provenance, not an
ongoing build dependency. The shadcn Tailwind utilities were ejected from
`shadcn@4.21.0`; their MIT notice remains in `src/style.css`.
