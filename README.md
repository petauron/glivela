# Glivela

Glivela manages proxy entries, landings, routes and subscriptions through an
independent control panel. It integrates with Vastora for application installation,
updates and access to the panel.

## What it provides

- Account credentials, quotas and subscription generation.
- VLESS/REALITY entries, SS2022 forwarding, dynamic relay pools (port 24000 EIH) and three-column topology.
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
- [Server-owned transport resources](docs/server-transport-ownership.md)
- [Dynamic relay pools and topology](docs/relay-pools.md)
- [Managed UDP forwarding](docs/udp-forwarding.md)
- [Manual subscription order](docs/subscription-order.md)
- [REALITY target changes](docs/reality-target-change.md)
- [Startup readiness](docs/startup-readiness.md)
- [Public443 and dual-stack ingress](docs/public-ingress-443.md)

## Diagnostics

- [IP quality and unlock details](docs/ip-quality.md)
- [Node-to-node speed tests](docs/link-speed.md)
- [Network optimization](docs/network-optimization.md)
- [Path MTU](docs/path-mtu.md)
- [Public egress policy](docs/public-egress.md)
- [Temporary availability](docs/temporary-availability.md)
- [Controller ledger storage and recovery](docs/controller-ledger-storage.md)

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

### Retired client-side chains

Client-side chains (`POST /v1/admin/client-chains`, `dialer-proxy` / `chain=` subscription output, and the UI chain mode) have been retired. Subscriptions publish only direct native entries and server-forwarded routes (including server-owned two-hop, three-hop, and provider-LAN transports under `ServerTransports`). Historical ledger tombstones remain read-only compatible on controller load.

## Managed ingress DNS resources

An administrator may supply a non-secret DNS resource in the authenticated
`advertise-host` request's `resource` field, alongside `entryId`, `action: apply`
and the exact `expectedRevision` string. The resource contains `id`, `hostname`,
`address`, `type` (`A` or `AAAA`), `revision`, `appliedRevision`, and `status`.
It must be ready, fully applied, and resolve to the same public address as the
current entry. Exact successful retries are idempotent. SNI remains separate.

The host manager owns domain allocation and provider access. Glivela receives no
DNS-provider key or host-manager administrator session, does not read its database,
and retains its own identities, permissions and task state. This optional portable
provisioning input does not add a runtime dependency on Vastora. DNS propagation
and real subscription access must be verified before accepting a migration.

### Subscription profiles

The account panel offers **仅节点** (the existing format negotiation and node order) and **Aethersailor 重度分流** (OpenClash/Mihomo). Both links use the same subscription identity and published inventory. The optional profile uses `?format=mihomo&profile=aethersailor`; `profile=nodes` or no profile retains existing behavior. URI output with the Full profile is rejected.

The Full profile includes policy groups and rules, without DNS, TUN, listeners or local network settings. It does not edit installed client profiles. Keep local company/private-network overrides ahead of imported rules; clients need compatible geosite/geoip data and access to rule-provider downloads. See [template provenance and adaptation](subscription_profiles/README.md).

Shadowrocket 重度分流：在订阅类型选择 Aethersailor 后选择“小火箭”，先在首页导入配套节点订阅，再在配置页下载原生 `.conf`。保留原配置并合并已有 DNS、公司与内网优先规则后使用；下载配置不会自动完成本地合并。

小火箭原生兼容范围：保留分类、策略组及规则顺序；不支持上游 `DOMAIN-REGEX` 和 `SRC-PORT`。未匹配流量继续匹配后续规则或兜底策略，不保证与 OpenClash 完全等价。
