# Aethersailor Full profile

Adapted from [Aethersailor/Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules), `cfg/Custom_Clash_Full.ini` at commit `882e404049f0cfce5d2438efb8943527f9284caf` (CC BY-SA 4.0; license included). The upstream template credits ACL4SSR. This adapted template data remains CC BY-SA 4.0.

Changes: normalized the active INI rules and groups into embedded JSON; pinned remote rule URLs to the same commit; translated PCRE-only name filters into Go-compatible expressions (Japanese/Russian country names use full names; low-rate matches use a preceding non-digit boundary). Other-region membership is the complement of the named filters. Empty groups and their references are omitted. Only published selectable nodes enter groups, in subscription order; chain dependency proxies remain hidden. Colliding generated group names receive a suffix, without renaming nodes.

This is routing data, not a DNS-leak-prevention setup. No DNS, TUN, listeners, LAN, firewall, geodata download settings or local overrides are emitted. The client's existing geosite/geoip database must contain the referenced categories. Remote rule providers require client network access. Importing a full profile changes routing; existing OpenClash custom company/private-network rules must retain their local precedence. Glivela never edits the client configuration.
