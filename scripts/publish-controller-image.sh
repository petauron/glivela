#!/bin/sh
set -eu

# Invoked only by the existing checked-Release-Please publication job. Reuse
# its verified cross-compiled bundles; do not rebuild source in a mutable image.
test "$#" = 1
output=$(CDPATH='' cd -- "$1" && pwd)
version=$(jq -er '.["."]' .release-please-manifest.json)
test "${RELEASE_SHA:?}" = "$(git rev-parse HEAD)"
test "${RELEASE_TAG:?}" = "v$version"
test "${DOCKER_BUILD_RECORD_UPLOAD:?}" = false
image=ghcr.io/petauron/glivela
reference="$image:$RELEASE_TAG"

# Never overwrite an already published image tag. Partial-image publication
# requires the explicit recovery procedure documented in RELEASING.md.
if docker buildx imagetools inspect "$reference" >/dev/null 2>&1; then
  echo 'Controller version image already exists; verify retained draft evidence before recovery.' >&2
  exit 1
fi
stage=$(mktemp -d)
trap 'test -n "$stage" && rm -rf -- "$stage"' EXIT HUP INT TERM
mkdir "$stage/state"
cp deploy/controller/state/.keep "$stage/state/.keep"
for arch in amd64 arm64; do
  mkdir "$stage/$arch"
  archive="glivela-$version-linux-$arch.tar.gz"
  (cd "$output" && sha256sum --check SHA256SUMS)
  tar -xzf "$output/$archive" -C "$stage/$arch"
  jq -e --arg version "$version" --arg commit "$RELEASE_SHA" --arg arch "$arch" \
    '.version == $version and .commit == $commit and .os == "linux" and .architecture == $arch' \
    "$stage/$arch/runtime.json" >/dev/null
done

# Docker/buildx are provided by the existing release runner. Scratch COPY has
# no RUN instructions, so cross-platform packaging needs no QEMU installation.
docker buildx create --name glivela-controller-release --driver docker-container --use
docker buildx build --platform linux/amd64,linux/arm64 \
  --file deploy/controller/Dockerfile \
  --build-arg "GLIVELA_VERSION=$version" --build-arg "GLIVELA_COMMIT=$RELEASE_SHA" \
  --build-arg "SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)" \
  --provenance=mode=max --metadata-file "$stage/image.json" \
  --tag "$reference" --push "$stage"
digest=$(jq -er '.["containerimage.digest"] | select(test("^sha256:[0-9a-f]{64}$"))' "$stage/image.json")
docker buildx imagetools inspect "$image@$digest" --raw > "$stage/manifest.json"
jq -e '[.manifests[] | select(.platform.os == "linux") | .platform.architecture] | sort == ["amd64","arm64"]' \
  "$stage/manifest.json" >/dev/null
jq -n --arg version "$version" --arg commit "$RELEASE_SHA" --arg reference "$image@$digest" \
  '{version:$version,commit:$commit,reference:$reference,platforms:["linux/amd64","linux/arm64"]}' \
  > "$output/glivela-controller-image.json"
(cd "$output" && sha256sum glivela-controller-image.json >> SHA256SUMS)

