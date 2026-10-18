# Disposable first-cutover test

This manual integration test needs a new Debian 13 guest with real systemd,
network namespace support, nftables, iproute2, Python 3, curl and OpenSSL.
The reviewed resource budget is 1 CPU, 512 MiB RAM, 256 MiB swap and 4 GiB disk.
No production enrollment, configuration or credentials are used.

Prepare `/opt/glivela-cutover-lab/` with:

- `glivela-bundle/glivela`: Linux amd64 build of the PR being tested.
- `xray.zip`: official 26.7.28 `Xray-linux-64.zip`; the script enforces the
  same archive SHA-256 as `build-native-release.sh`.
- `legacy-fixture`: build `landing-cutover-fixture.go.txt` as a temporary command
  within the retained legacy Vastora source tree, with its original Dante bundle.
  The reviewed source baseline is `fb4bd70ce7795d4832e18b8c030f21b3fdda212f`.

Debian 13 nftables 1.1 removes a redundant IPv4 family expression when an IPv4
source match already establishes that family. The old installer otherwise
rejects its own read-back before starting Dante. Apply the adjacent
`landing-cutover-legacy-readback.patch` **only to this fixture build**. It removes
that redundancy without changing accepted traffic, source restrictions, table
identity or UID. Record this fixture adaptation with the results; it is not a
production Vastora change or proof of every older binary/kernel combination.

After explicitly authorizing a disposable guest, create the local marker
`/run/glivela-54-disposable-lab`, set `GLIVELA_TEST_COMMIT` to the tested full SHA,
and run `python3 landing-cutover-lab.py` as root. The script refuses existing
legacy or test installations. All proxy, synthetic entry and HTTPS target
traffic stays within the guest's test interfaces/namespaces. TLS verification
remains enabled and the target reports its observed source address.

The three scenarios are a failing systemd start with verified Dante recovery,
a successful Xray switch with the original selected exit and TLS path, and a
real SIGKILL during pending activation followed by node-startup recovery.
`awaiting-routes` is checked explicitly; local activation never counts as
controller acceptance. `results.json` contains only anonymous boolean results.

On 2026-10-18 these scenarios passed in the disposable Debian 13 guest with
nftables 1.1.3, Dante 1.4.4 and official Xray 26.7.28. Each restored old runtime
was independently exercised through the synthetic entry over verified TLS.
The exercise found and fixed extensionless systemd credentials needing explicit
`-format json`, and process activation preceding actual listener readiness.
Both the new and restored old runtime now require the exact listener address,
port and dedicated UID. This is local runtime evidence; full legacy business
data, controller acceptance and old-writer retirement remain separate work.

The guest retains original resources, private recovery checkpoints and logs
for inspection. It must remain isolated; stopping or destroying it uses the
virtualization platform's normal guest lifecycle. Do not run this on an existing
node, infer complete business-data handover from it, or publish guest metadata.
