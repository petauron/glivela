# Aethersailor Full profile

Adapted from [Aethersailor/Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules), `cfg/Custom_Clash_Full.ini` at commit `882e404049f0cfce5d2438efb8943527f9284caf` (CC BY-SA 4.0; license included). The upstream template credits ACL4SSR. This adapted template data remains CC BY-SA 4.0.

Changes: normalized the active INI rules and groups into embedded JSON; pinned remote rule URLs to the same commit; translated PCRE-only name filters into Go-compatible expressions (Japanese/Russian country names use full names; low-rate matches use a preceding non-digit boundary). Other-region membership is the complement of the named filters. Empty groups and their references are omitted. Only published selectable nodes enter groups, in subscription order; chain dependency proxies remain hidden. Colliding generated group names receive a suffix, without renaming nodes.

This is routing data, not a DNS-leak-prevention setup. No DNS, TUN, listeners, LAN, firewall, geodata download settings or local overrides are emitted. The client's existing geosite/geoip database must contain the referenced categories. Remote rule providers require client network access. Importing a full profile changes routing; existing OpenClash custom company/private-network rules must retain their local precedence. Glivela never edits the client configuration.

## Shadowrocket native profile

`format=shadowrocket&profile=aethersailor` returns a native `.conf` with
`[Proxy Group]` and `[Rule]`. Import its matching `format=mihomo&profile=nodes`
subscription in Home first. Configuration groups refer to those exact names;
credentials and chain transports are not translated or reissued. Node order
remains the server's account order. This is a separate file, not an automatic
merge into an existing client configuration. Preserve local General/Host/DNS
and company/private rule overrides before activating it.

The six custom provider payloads are normalized from YAML at the same upstream
pin into `shadowrocket-custom-rules.json` (CC BY-SA 4.0). Domain payloads become
DOMAIN/DOMAIN-SUFFIX; IPv6 CIDRs use Shadowrocket's IP-CIDR keyword. The source-port
41641 bypass has no native UI rule type and is explicitly omitted, not converted
to a destination-port bypass. No device-specific settings are exported.

GEOSITE and non-country GEOIP categories use classical RULE-SET text from
MetaCubeX/meta-rules-dat commit `2963a49408bbc37f2c2ffa6e8329fe11076a816b`,
the native-text form of the same category data; no MRS binary is passed to the
client. These public rules contain no subscription credentials. Unsupported
policy-name delimiters fail the export rather than changing node identities.

小火箭原生兼容范围：保留分类、策略组及规则顺序；不支持上游 `DOMAIN-REGEX` 和 `SRC-PORT`。未匹配流量继续匹配后续规则或兜底策略，不保证与 OpenClash 完全等价。
