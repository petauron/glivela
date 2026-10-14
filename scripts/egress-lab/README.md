# Isolated native egress lab

This focused test runs the `direct` outbound produced by Glivela against the
Xray 26.9.30 image pinned in the script. It tests real TCP and SOCKS5 UDP
traffic, including different families within one UDP association, IPv4-mapped
IPv6 literals, single-family DNS records and dual-stack DNS records. Peer-side
nonce receipts independently detect forbidden traffic even if its reply was lost.

Run on an authorized Linux development machine with Docker and Python 3.
The temporary internal dual-stack network uses `192.168.241.0/24` and
`fd00:397::/64`; both subnets must be unused. Nothing binds a host port or
changes the host firewall. The test creates only two temporary containers,
with one CPU and 64 MiB each, and removes them and its network on exit. Images
are pinned by digest and remain cached. Generated files contain no credentials.

Prepare from the repository root with Go 1.26:

```sh
lab=$(mktemp -d /tmp/meridian-egress.XXXXXX)
go run scripts/egress-lab/generate.go "$lab"
cp scripts/egress-lab/*.py "$lab/"
sh scripts/egress-lab/run.sh "$lab"
```

Preparation may run on another machine: copy the prepared directory and run
script to the Linux development machine. JSON results and logs remain in the
prepared directory. Do not commit generated results or real node information.

The existing Vastora runtime uses 26.7.28, which failed the strict IPv4 UDP
domain case in this lab: later packets in one association cannot resolve the
allowed IPv4 domain. The implementation requires the post-26.9.8 resolution
path and must not be enabled with the old runtime. See upstream
[Xray #6058](https://github.com/XTLS/Xray-core/pull/6058).

This proves core egress enforcement, not a deployed Center/Agent feature,
public-provider reachability or full REALITY/Hysteria acceptance. Automatic
mode's DNS behavior belongs to the system resolver and is not redirected to the
fixture DNS. Preferred-family modes are not implemented here: the core's TCP
Happy Eyeballs and UDP's DNS-family preference have different fallback semantics.
