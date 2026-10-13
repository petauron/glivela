# Glivela application UI

This directory owns Glivela's page composition and its independently signed
browser bundle. Center provides authenticated data, platform actions, and the
shared component library; it does not compile Glivela pages into its own web
application after the migration.

The build uses the reviewed Vastora UI source at commit
`583e2f23ae3fbc91671ed6633b8776dbce4f9b95`. Set `VASTORA_WEB_SOURCE` to
that checkout's `web/src` directory. The build fails if the checkout points to
a different commit. `src/index.tsx` exports the versioned `mount`/`update`/
`unmount` entry used by Center. The output filename is tied to this package
version and is published as a TUF target with the official app catalog.
`npm run check` validates the same pinned dependency and type-checks the
application-owned pages against its platform contract before publication. It
creates an ignored `.center-src` link to the reviewed checkout; CI uses the
same preparation step for both catalog build passes.

Center remains responsible for authentication and authorization on every API
request. Loading the UI bundle does not grant new permissions to an app or a
third-party catalog source.

The shared shadcn Tailwind utilities are ejected unchanged from the locked
`shadcn@4.21.0` stylesheet into `src/style.css`, with its MIT notice retained,
following the official [eject procedure](https://ui.shadcn.com/docs/changelog/2026-05-shadcn-eject).
The UI uses Center's existing component source, not the shadcn generation CLI.
Keeping that CLI as an application dependency unnecessarily included its MCP
server and unpatched `braces` dependency chain. Future shared-style changes must
be reviewed as source changes; they are not silently pulled in by CLI updates.
CI audits the complete UI lockfile and rejects high or critical advisories.
