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
trap 'test -n "$stage" && rm -rf -- "$stage"' EXIT HUP INT TERM

for arch in amd64 arm64; do
  case "$arch" in
    amd64)
      asset=Xray-linux-64.zip
      digest=8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40 ;;
    arm64)
      asset=Xray-linux-arm64-v8a.zip
      digest=f5698bb218ada3b4022db26fafc39601c5f53b46b19eb76c9616325985807501 ;;
  esac
  bundle="$stage/$arch"
  mkdir "$bundle"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 180 --retry 3 \
    "https://github.com/XTLS/Xray-core/releases/download/v26.7.28/$asset" -o "$stage/$asset"
  printf '%s  %s\n' "$digest" "$stage/$asset" | sha256sum --check --status
  unzip -p "$stage/$asset" xray > "$bundle/xray"
  unzip -p "$stage/$asset" LICENSE > "$bundle/LICENSE.xray"
  test -s "$bundle/xray"
  test -s "$bundle/LICENSE.xray"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false \
    -ldflags='-s -w -buildid=' -o "$bundle/glivela" ./cmd/glivela
  cp LICENSE "$bundle/LICENSE.glivela"
  chmod 0755 "$bundle/glivela" "$bundle/xray"
  xray_digest=$(sha256sum "$bundle/xray" | cut -d ' ' -f 1)
  jq -n --arg version "$version" --arg commit "$commit" --arg arch "$arch" \
    --arg xray "$xray_digest" --arg archive "$digest" \
    '{version:$version,commit:$commit,os:"linux",architecture:$arch,xray:{version:"26.7.28",sha256:$xray,sourceArchiveSHA256:$archive}}' > "$bundle/runtime.json"
  chmod 0644 "$bundle/LICENSE.glivela" "$bundle/LICENSE.xray" "$bundle/runtime.json"
  archive="glivela-$version-linux-$arch.tar.gz"
  tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    --format=gnu -C "$bundle" -cf "$stage/$arch.tar" LICENSE.glivela LICENSE.xray glivela runtime.json xray
  gzip -n -c "$stage/$arch.tar" > "$output/$archive"
done
cd "$output"
sha256sum ./*.tar.gz > SHA256SUMS
