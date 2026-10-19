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

# Reuse the reviewed UI toolchain/lockfile. Its bundle is served by Glivela's
# own management listener; no platform business API or remote UI fetch.
test "$(jq -er .version ui/package.json)" = "$version"
npm run build --prefix ui
test -s "ui/dist/ui-glivela-$version.js"
test -s "ui/dist/ui-glivela-$version.css"

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
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -mod=readonly -trimpath -buildvcs=false \
    -ldflags='-s -w -buildid=' -o "$bundle/glivela" ./cmd/glivela
  cp LICENSE "$bundle/LICENSE.glivela"
  cp "ui/dist/ui-glivela-$version.js" "$bundle/glivela-ui.js"
  cp "ui/dist/ui-glivela-$version.css" "$bundle/glivela-ui.css"
  chmod 0755 "$bundle/glivela" "$bundle/xray"
  xray_digest=$(sha256sum "$bundle/xray" | cut -d ' ' -f 1)
  ui_js_digest=$(sha256sum "$bundle/glivela-ui.js" | cut -d ' ' -f 1)
  ui_css_digest=$(sha256sum "$bundle/glivela-ui.css" | cut -d ' ' -f 1)
  jq -n --arg version "$version" --arg commit "$commit" --arg arch "$arch" \
    --arg xray "$xray_digest" --arg archive "$digest" --arg uiJS "$ui_js_digest" --arg uiCSS "$ui_css_digest" \
    '{version:$version,commit:$commit,os:"linux",architecture:$arch,xray:{version:"26.7.28",sha256:$xray,sourceArchiveSHA256:$archive},ui:{"glivela-ui.js":$uiJS,"glivela-ui.css":$uiCSS}}' > "$bundle/runtime.json"
  chmod 0644 "$bundle/LICENSE.glivela" "$bundle/LICENSE.xray" "$bundle/runtime.json"
  archive="glivela-$version-linux-$arch.tar.gz"
  tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    --format=gnu -C "$bundle" -cf "$stage/$arch.tar" LICENSE.glivela LICENSE.xray glivela glivela-ui.js glivela-ui.css runtime.json xray
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
  ) > "$stage/offline-modules"
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
  done < "$stage/offline-modules" > "$offline/THIRD-PARTY-LICENSES"
  go_root=$(go env GOROOT)
  printf '\nGo standard library / LICENSE\n\n' >> "$offline/THIRD-PARTY-LICENSES"
  cat "$go_root/LICENSE" >> "$offline/THIRD-PARTY-LICENSES"
  test -s "$offline/THIRD-PARTY-LICENSES"
  jq -n --arg version "$version" --arg commit "$commit" --arg arch "$arch" \
    '{version:$version,commit:$commit,os:"linux",architecture:$arch,sourceSchemas:[113,114],mode:"offline-read-only"}' > "$offline/migration.json"
  chmod 0755 "$offline/glivela-legacy-export"
  chmod 0644 "$offline/LICENSE.glivela" "$offline/THIRD-PARTY-LICENSES" "$offline/migration.json"
  tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    --format=gnu -C "$offline" -cf "$stage/offline-$arch.tar" LICENSE.glivela THIRD-PARTY-LICENSES glivela-legacy-export migration.json
  gzip -n -c "$stage/offline-$arch.tar" > "$output/glivela-legacy-export-$version-linux-$arch.tar.gz"
done
cd "$output"
sha256sum ./*.tar.gz > SHA256SUMS
