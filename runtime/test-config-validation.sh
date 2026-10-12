#!/bin/sh
# Anonymous CLI preflight fixture. No sockets, credentials, or external I/O.
set -eu
test "$#" = 1
core=$1
test -x "$core"
"$core" version | grep -Fx 'GlivelaTargetSelectionRevision: 1' >/dev/null
probe_dir=$(mktemp -d)
cleanup() {
  rm -f "$probe_dir/route.lua" "$probe_dir/config.json"
  rmdir "$probe_dir"
}
trap cleanup EXIT HUP INT TERM
# A nonlocal documentation address makes an accidental listener start fail.
printf '{"inbounds":[{"listen":"192.0.2.1","port":1080,"protocol":"dokodemo-door","settings":{"address":"192.0.2.2","port":80,"network":"tcp"}}],"routing":{"script":"%s/route.lua"}}\n' "$probe_dir" > "$probe_dir/config.json"
printf '%s\n' 'assert(require("xray.router").TargetSelectionRevision == 1)' 'function HandleRoute() return "blocked" end' > "$probe_dir/route.lua"
preflight=$("$core" run -test -c "$probe_dir/config.json" 2>/dev/null)
printf '%s\n' "$preflight" | grep -Fx 'GlivelaTargetSelectionRevision: 1' >/dev/null
printf '%s\n' 'error("anonymous initialization failure")' 'function HandleRoute() return "blocked" end' > "$probe_dir/route.lua"
if "$core" run -test -c "$probe_dir/config.json" >/dev/null 2>&1; then
  printf '%s\n' 'Core preflight accepted a failing script initialization.' >&2
  exit 1
fi
printf '%s\n' 'Core capability and no-socket script preflight passed.'
