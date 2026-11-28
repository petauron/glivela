#!/bin/sh
set -eu

# Build only distribution inputs; never install or start either executable.
# Linux/GNU tar is used for deterministic archive metadata.
if [ "$#" -ne 1 ]; then
  echo 'usage: build-native-release.sh NEW_OUTPUT_DIRECTORY' >&2
  exit 2
fi
output=$1
mkdir "$output"
output=$(CDPATH='' cd -- "$output" && pwd)
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
version=$(jq -er '.["."] | select(type == "string")' .release-please-manifest.json)
printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
commit=$(git rev-parse HEAD)
epoch=$(git show -s --format=%ct HEAD)
stage=$(mktemp -d)
cleanup_stage() {
  trap - EXIT HUP INT TERM
  if [ -n "$stage" ]; then
    for pid_file in "$stage"/worker-*.pid; do
      if [ -f "$pid_file" ]; then
        pid=$(cat "$pid_file")
        kill "$pid" 2>/dev/null || true
      fi
    done
    wait 2>/dev/null || true
    rm -rf -- "$stage"
  fi
}
trap cleanup_stage EXIT
trap 'cleanup_stage; exit 129' HUP
trap 'cleanup_stage; exit 130' INT
trap 'cleanup_stage; exit 143' TERM

upstream_cache="${GLIVELA_UPSTREAM_CACHE_DIR:-}"
if [ -n "$upstream_cache" ]; then
  mkdir -p "$upstream_cache"
  upstream_cache=$(CDPATH='' cd -- "$upstream_cache" && pwd)
fi

fetch_verified_asset() {
  _repo="$1"
  _tag="$2"
  _asset="$3"
  _digest="$4"
  _dest="$5"
  if [ -n "$upstream_cache" ]; then
    _cached="$upstream_cache/${_digest}-${_asset}"
    if [ -f "$_cached" ] && printf '%s  %s\n' "$_digest" "$_cached" | sha256sum --check --status 2>/dev/null; then
      cp "$_cached" "$_dest"
      printf '%s  %s\n' "$_digest" "$_dest" | sha256sum --check --status
      return 0
    fi
  fi
  gh release download "$_tag" --repo "$_repo" --pattern "$_asset" --output "$_dest"
  printf '%s  %s\n' "$_digest" "$_dest" | sha256sum --check --status
  if [ -n "$upstream_cache" ]; then
    _tmp_cache=$(mktemp "$upstream_cache/.${_digest}-${_asset}.XXXXXX")
    cp "$_dest" "$_tmp_cache"
    mv -f "$_tmp_cache" "$_cached"
  fi
}

# Reuse the reviewed UI toolchain/lockfile. Its bundle is served by Glivela's
# own management listener; no platform business API or remote UI fetch.
test "$(jq -er .version ui/package.json)" = "$version"
npm run build --prefix ui
test -s "ui/dist/ui-glivela-$version.js"
test -s "ui/dist/ui-glivela-$version.css"

go_root=$(go env GOROOT)

build_arch() {
  arch="$1"
  case "$arch" in
    amd64)
      asset=Xray-linux-64.zip
      digest=b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82
      iperf_asset=iperf3-amd64
      iperf_digest=ef4c89f3fc01c56cf00d34b900024c74f68e540dab452eef4fd902544d9c1c64 ;;
    arm64)
      asset=Xray-linux-arm64-v8a.zip
      digest=64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be
      iperf_asset=iperf3-arm64v8
      iperf_digest=34364466812357fe021a8647cb433c8006b0360e3b690ecda470a979a2601031 ;;
    *)
      echo "Unsupported architecture: $arch" >&2
      exit 2 ;;
  esac
  bundle="$stage/$arch"
  mkdir -p "$bundle" "$stage/xdg-data-$arch" "$stage/xdg-cache-$arch"
  # Resolve the exact official asset through GitHub's API after browser URL
  # downloads returned HTTP 504; the pinned bytes are unchanged.
  fetch_verified_asset XTLS/Xray-core v26.11.9 "$asset" "$digest" "$stage/$asset"
  unzip -p "$stage/$asset" xray > "$bundle/xray"
  unzip -p "$stage/$asset" LICENSE > "$bundle/LICENSE.xray"
  test -s "$bundle/xray"
  test -s "$bundle/LICENSE.xray"
  # The supplier build is separately pinned and attested; it is never fetched
  # by a running node and the attestation is not a reproducible-build claim.
  fetch_verified_asset userdocs/iperf3-static 3.22 "$iperf_asset" "$iperf_digest" "$bundle/iperf3"
  XDG_DATA_HOME="$stage/xdg-data-$arch" XDG_CACHE_HOME="$stage/xdg-cache-$arch" \
    gh attestation verify "$bundle/iperf3" --repo userdocs/iperf3-static \
    --signer-workflow userdocs/iperf3-static/.github/workflows/ci-linux-crossbuild.yml \
    --source-digest 7d71626b4364b6cc95b6611fa0d66a401d53fd07 --deny-self-hosted-runners
  cp licenses/iperf3-static.txt "$bundle/LICENSE.iperf3"
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -mod=readonly -trimpath -buildvcs=false \
    -ldflags='-s -w -buildid=' -o "$bundle/glivela" ./cmd/glivela
  cp LICENSE "$bundle/LICENSE.glivela"
  printf '\nAethersailor Full template (adapted routing data)\n' >> "$bundle/LICENSE.glivela"
  cat subscription_profiles/README.md subscription_profiles/LICENSE-CC-BY-SA-4.0.txt >> "$bundle/LICENSE.glivela"
  cp "ui/dist/ui-glivela-$version.js" "$bundle/glivela-ui.js"
  cp "ui/dist/ui-glivela-$version.css" "$bundle/glivela-ui.css"
  chmod 0755 "$bundle/glivela" "$bundle/xray" "$bundle/iperf3"
  xray_digest=$(sha256sum "$bundle/xray" | cut -d ' ' -f 1)
  ui_js_digest=$(sha256sum "$bundle/glivela-ui.js" | cut -d ' ' -f 1)
  ui_css_digest=$(sha256sum "$bundle/glivela-ui.css" | cut -d ' ' -f 1)
  jq -n --arg version "$version" --arg commit "$commit" --arg arch "$arch" \
    --arg xray "$xray_digest" --arg archive "$digest" --arg iperf "$iperf_digest" --arg uiJS "$ui_js_digest" --arg uiCSS "$ui_css_digest" \
    '{hostTCPBudget:"vastora-v1",version:$version,commit:$commit,os:"linux",architecture:$arch,xray:{version:"26.11.9",sha256:$xray,sourceArchiveSHA256:$archive},iperf3:{version:"3.22",sha256:$iperf},ui:{"glivela-ui.js":$uiJS,"glivela-ui.css":$uiCSS}}' > "$bundle/runtime.json"
  chmod 0644 "$bundle/LICENSE.glivela" "$bundle/LICENSE.xray" "$bundle/LICENSE.iperf3" "$bundle/runtime.json"
  archive="glivela-$version-linux-$arch.tar.gz"
  tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    --format=gnu -C "$bundle" -cf "$stage/$arch.tar" LICENSE.glivela LICENSE.xray LICENSE.iperf3 glivela glivela-ui.js glivela-ui.css iperf3 runtime.json xray
  gzip -n -c "$stage/$arch.tar" > "$output/$archive"

  # The approved SQLite dependency stays in a SEPARATE, one-time offline tool.
  # Never put this executable or its dependencies in a controller/node bundle.
  offline="$stage/offline-$arch"
  mkdir "$offline"
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go -C tools/legacy-export build -mod=readonly -trimpath -buildvcs=false \
    -ldflags='-s -w -buildid=' -o "$offline/glivela-legacy-export" .
  cp LICENSE "$offline/LICENSE.glivela"
  (
    cd tools/legacy-export
    GOWORK=off go list -mod=readonly -m -f '{{if and .Dir (not .Main)}}{{.Path}} {{.Dir}}{{end}}' all
  ) > "$stage/offline-modules-$arch"
  while read -r module directory; do
    if [ -z "$module" ] || [ -z "$directory" ]; then continue; fi
    found_license=false
    for license in LICENSE LICENSE.md LICENSE.txt LICENCE LICENCE.md COPYING COPYING.md NOTICE NOTICE.md LICENSE-3RD-PARTY.md LICENSE-SQLITE LICENSE-SQLITE_VEC; do
      if [ -f "$directory/$license" ]; then
        found_license=true
        printf '\n%s / %s\n\n' "$module" "$license"
        cat "$directory/$license"
      fi
    done
    test "$found_license" = true
  done < "$stage/offline-modules-$arch" > "$offline/THIRD-PARTY-LICENSES"
  printf '\nGo standard library / LICENSE\n\n' >> "$offline/THIRD-PARTY-LICENSES"
  cat "$go_root/LICENSE" >> "$offline/THIRD-PARTY-LICENSES"
  test -s "$offline/THIRD-PARTY-LICENSES"
  jq -n --arg version "$version" --arg commit "$commit" --arg arch "$arch" \
    '{version:$version,commit:$commit,os:"linux",architecture:$arch,sourceSchemas:[113,114,115,116],mode:"offline-read-only"}' > "$offline/migration.json"
  chmod 0755 "$offline/glivela-legacy-export"
  chmod 0644 "$offline/LICENSE.glivela" "$offline/THIRD-PARTY-LICENSES" "$offline/migration.json"
  tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    --format=gnu -C "$offline" -cf "$stage/offline-$arch.tar" LICENSE.glivela THIRD-PARTY-LICENSES glivela-legacy-export migration.json
  gzip -n -c "$stage/offline-$arch.tar" > "$output/glivela-legacy-export-$version-linux-$arch.tar.gz"
}

for arch in amd64 arm64; do
  (build_arch "$arch") > "$stage/build-$arch.log" 2>&1 &
  printf '%s\n' "$!" > "$stage/worker-$arch.pid"
done

failed=0
for arch in amd64 arm64; do
  pid=$(cat "$stage/worker-$arch.pid")
  worker_status=0
  wait "$pid" || worker_status=$?
  rm -f "$stage/worker-$arch.pid"
  if [ -s "$stage/build-$arch.log" ]; then
    echo "=== build-native-release ($arch) ==="
    cat "$stage/build-$arch.log"
  fi
  if [ "$worker_status" -ne 0 ]; then
    echo "Native release build failed for $arch with exit status $worker_status" >&2
    failed=1
  fi
done
test "$failed" -eq 0

cd "$output"
LC_ALL=C sha256sum ./*.tar.gz > SHA256SUMS
