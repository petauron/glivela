# Glivela

Glivela manages proxy entries, landings, routes and subscriptions through an
independent control panel. It integrates with Vastora for application installation,
updates and access to the panel.

## What it provides

- Account credentials, quotas and subscription generation.
- VLESS/REALITY entries, SS2022 forwarding and OpenClash/Mihomo client chains.
- Entry and landing inventory, route configuration and availability controls.
- IP quality and unlock results, route latency and node-to-node speed tests.
- Network-optimization status and explicitly requested configuration changes.

The controller and panel run as a nonroot Docker application. Entry and landing
roles run as native services with the reviewed official Xray core. Nodes use the
private authenticated control channel; proxy traffic stays on its configured path.

## Getting started

Install the controller and required node roles through Vastora, open the Glivela
application, initialize its business state, then configure an entry, landing and
subscription. Keep bootstrap files, certificates, protocol credentials and state
outside the source checkout.

- [Fresh installation](docs/fresh-install.md)
- [Panel access](docs/panel-access.md)
- [Entry and landing on one host](docs/node-pair.md)
- [Client chains and composite routes](docs/composite-routes.md)
- [REALITY target changes](docs/reality-target-change.md)
- [Startup readiness](docs/startup-readiness.md)

## Diagnostics

- [IP quality and unlock details](docs/ip-quality.md)
- [Node-to-node speed tests](docs/link-speed.md)
- [Network optimization](docs/network-optimization.md)
- [Public egress policy](docs/public-egress.md)
- [Temporary availability](docs/temporary-availability.md)

## Development

The Go module requires Go 1.26; the UI uses the locked dependencies in `ui/`.
See [UI development](ui/README.md) and [release publication](RELEASING.md).
Existing CI checks the backend, native distribution, UI and dependencies.

`control/` owns orchestration and the management API, `landing/` owns the landing
runtime, and `ui/` owns the panel. The offline tool in `tools/legacy-export/` is
separate from installed runtimes; see its README before importing existing data.

Public examples use synthetic node labels and documentation addresses. Operational
records, deployments, credentials, subscription URLs and real fleet inventory do
not belong in this repository. Node labels are operator-provided; Glivela does not
maintain a vendor-specific alias list.

## License

Apache-2.0. Bundled third-party programs retain their own licenses and notices.

Retaining issued subscription labels and an existing host guard during upgrades:
[operator-owned configuration](docs/operator-configuration.md).
