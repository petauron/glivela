#!/bin/sh
set -eu
lab=${1:?pass an absolute prepared lab directory}
case "$lab" in /*) ;; *) echo 'absolute lab directory required' >&2; exit 1;; esac
[ "$(uname -s)" = Linux ] || { echo 'Linux is required' >&2; exit 1; }
prefix=meridian-egress-$$
network=$prefix-network
xray=ghcr.io/xtls/xray-core:26.9.30@sha256:6d30597c3e729b5dc1faac8dbc0138fbbe6d4d787bfb54120ea48f14e2e7b5ca
python=python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0
for name in "$prefix-peer" "$prefix-xray"; do
 if docker container inspect "$name" >/dev/null 2>&1; then echo 'test container already exists' >&2; exit 1; fi
done
if docker network inspect "$network" >/dev/null 2>&1; then echo 'test network already exists' >&2; exit 1; fi
cleanup() {
 docker logs "$prefix-xray" >"$lab/xray.log" 2>&1 || true
 docker logs "$prefix-peer" >"$lab/peer.log" 2>&1 || true
 docker rm -f "$prefix-xray" "$prefix-peer" >/dev/null 2>&1 || true
 docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
chmod 755 "$lab"
chmod 644 "$lab"/*.json "$lab"/*.py
docker network create --internal --ipv6 --subnet 192.168.241.0/24 --subnet fd00:397::/64 "$network" >/dev/null
docker run -d --name "$prefix-peer" --network "$network" --ip 192.168.241.4 --ip6 fd00:397::4 \
 --cap-drop ALL --security-opt no-new-privileges:true --read-only --pids-limit 32 --memory 64m --cpus 1 \
 --mount "type=bind,src=$lab,dst=/lab,readonly" "$python" python /lab/peer.py >/dev/null
for policy in auto ipv4_only ipv6_only; do
 docker run --rm --network none --user 65532 --cap-drop ALL --security-opt no-new-privileges:true --read-only \
  --mount "type=bind,src=$lab/$policy.json,dst=/etc/xray/config.json,readonly" "$xray" run -test -c /etc/xray/config.json >"$lab/$policy-config.log" 2>&1
 docker run -d --name "$prefix-xray" --network "$network" --ip 192.168.241.2 --ip6 fd00:397::2 \
  --user 65532 --cap-drop ALL --security-opt no-new-privileges:true --read-only --pids-limit 64 --memory 64m --cpus 1 \
  --mount "type=bind,src=$lab/$policy.json,dst=/etc/xray/config.json,readonly" "$xray" run -c /etc/xray/config.json >/dev/null
 sleep 1
 docker exec "$prefix-peer" python /lab/probe.py "$policy" >"$lab/$policy-result.json"
 docker logs "$prefix-xray" >"$lab/$policy-xray.log" 2>&1
 docker rm -f "$prefix-xray" >/dev/null
done
docker logs "$prefix-peer" >"$lab/peer.log" 2>&1
# A blocked request must never arrive at either echo socket, even if no response
# made it back to the client. Correlate the peer's observations with every nonce.
python3 - "$lab" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
received = [json.loads(line) for line in (root/'peer.log').read_text().splitlines()]
expected_accepts = {'ipv4': 0, 'ipv6': 0}
for policy in ['auto', 'ipv4_only', 'ipv6_only']:
    result = json.loads((root/(policy+'-result.json')).read_text())
    for case in result['evidence']:
        observations = [r for r in received if r['nonce'] == case['nonce']]
        if case['expected'] == 'blocked':
            assert not observations, ('forbidden destination received a packet', case)
        else:
            assert observations and all(r['family'] == case['expected'] for r in observations), case
            if case['network'] == 'tcp':
                expected_accepts[case['expected']] += 1
    coverage = 'literal and mapped-literal' if policy == 'auto' else 'literal, mapped-literal and DNS-family'
    print(policy + ': TCP/UDP ' + coverage + ' checks passed')
for family, count in expected_accepts.items():
    actual = sum(r['family'] == family and r['network'] == 'tcp_accept' for r in received)
    assert actual == count, ('unexpected TCP connection reached peer', family, actual, count)
print('Peer observations confirm no forbidden TCP connection or UDP payload reached either family')
PY
