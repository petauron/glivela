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
- [Native init adapters](docs/native-init.md)
- [Panel access](docs/panel-access.md)
- [Entry and landing on one host](docs/node-pair.md)
- [Client chains and composite routes](docs/composite-routes.md)
- [Manual subscription order](docs/subscription-order.md)
- [REALITY target changes](docs/reality-target-change.md)
- [Startup readiness](docs/startup-readiness.md)

## Diagnostics

- [IP quality and unlock details](docs/ip-quality.md)
- [Node-to-node speed tests](docs/link-speed.md)
- [Network optimization](docs/network-optimization.md)
- [Path MTU](docs/path-mtu.md)
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

- [Server forwarding through a shared public SS2022 listener](docs/server-public-transport.md)


### Dedicated private IPv4 client links

For two enrolled native nodes with a verified provider LAN, choose **专属内网 IPv4 · SS2022** when creating a client chain, or use **修改落地传输** on its existing route details. Supply the entry source address/interface and landing listener address/interface. Both addresses must be single RFC1918 IPv4 addresses already assigned to the specified interfaces. Only the existing chain's TCP listener is authorized; no subnet access or automatic public fallback is created. Ordinary native traffic and all other public/shared listeners retain their existing policy.

The management `client-chains` request accepts `privateLink: {source, address, sourceInterface, interface}` with the existing chain/account/entry/egress identity and current `expectedRevision`. Omit `privateLink` to preserve an existing link; use `clearPrivateLink: true` explicitly to restore the original public transport. Existing chain credentials and subscription identity remain unchanged. Server-forwarding and three-hop private transport are outside this MVP. Upgrade the selected controller, native entry and landing before applying this policy. Refresh the original Mihomo/OpenClash subscription, verify HTTPS and the final exit, and confirm both-end traffic uses the private interfaces. Private-link web speed/latency measurements are not currently provided.
