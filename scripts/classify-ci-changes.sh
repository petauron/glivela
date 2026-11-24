#!/bin/sh
set -eu

usage() {
  echo 'usage: classify-ci-changes.sh --git <base-sha> <head-sha>' >&2
  echo '       classify-ci-changes.sh --files' >&2
  exit 2
}

compare_semver() {
  awk -v left="$1" -v right="$2" '
    function compare_number(a, b) {
      a += 0; b += 0
      return a < b ? -1 : a > b ? 1 : 0
    }
    function is_numeric(v) {
      return v ~ /^(0|[1-9][0-9]*)$/
    }
    function compare_ident(a, b, an, bn) {
      an = is_numeric(a); bn = is_numeric(b)
      if (an && bn) return compare_number(a, b)
      if (an != bn) return an ? -1 : 1
      return ("x" a) < ("x" b) ? -1 : ("x" a) > ("x" b) ? 1 : 0
    }
    BEGIN {
      sub(/\+.*/, "", left); sub(/\+.*/, "", right)
      d = index(left, "-"); lc = d ? substr(left, 1, d - 1) : left; lp = d ? substr(left, d + 1) : ""
      d = index(right, "-"); rc = d ? substr(right, 1, d - 1) : right; rp = d ? substr(right, d + 1) : ""
      split(lc, lparts, "."); split(rc, rparts, ".")
      for (i = 1; i <= 3; i++) {
        r = compare_number(lparts[i], rparts[i])
        if (r) { print r; exit }
      }
      if (lp == rp) { print 0; exit }
      if (lp == "") { print 1; exit }
      if (rp == "") { print -1; exit }
      ln = split(lp, lpre, "."); rn = split(rp, rpre, ".")
      n = ln > rn ? ln : rn
      for (i = 1; i <= n; i++) {
        if (i > ln) { print -1; exit }
        if (i > rn) { print 1; exit }
        r = compare_ident(lpre[i], rpre[i])
        if (r) { print r; exit }
      }
      print 0
    }
  '
}

snapshot_dir=''
cleanup_snapshot() {
  trap - EXIT HUP INT TERM
  if [ -n "$snapshot_dir" ]; then
    rm -rf -- "$snapshot_dir"
  fi
}
trap cleanup_snapshot EXIT
trap 'cleanup_snapshot; exit 129' HUP
trap 'cleanup_snapshot; exit 130' INT
trap 'cleanup_snapshot; exit 143' TERM

is_verified_version_only_release() {
  _repo_dir="$1"
  _base_ref="$2"
  _merge_base="$3"
  _head_ref="$4"

  _expected='.release-please-manifest.json
CHANGELOG.md
ui/package-lock.json
ui/package.json'
  _actual="$(git -C "$_repo_dir" diff --no-renames --name-only "$_merge_base" "$_head_ref" | LC_ALL=C sort)"
  if [ "$_actual" != "$_expected" ]; then
    return 1
  fi

  snapshot_dir="$(mktemp -d "${TMPDIR:-/tmp}/glivela-release-check.XXXXXX")"
  mkdir -p "$snapshot_dir/base/ui" "$snapshot_dir/head/ui" "$snapshot_dir/target"

  for _file in .release-please-manifest.json CHANGELOG.md ui/package.json ui/package-lock.json; do
    _mode="$(git -C "$_repo_dir" ls-tree "$_head_ref" -- "$_file" | awk 'NR == 1 { print $1 }')"
    if [ "$_mode" != '100644' ]; then
      return 1
    fi
    if ! git -C "$_repo_dir" show "$_head_ref:$_file" > "$snapshot_dir/head/$_file" 2>/dev/null; then
      return 1
    fi
    if ! git -C "$_repo_dir" show "$_merge_base:$_file" > "$snapshot_dir/base/$_file" 2>/dev/null; then
      return 1
    fi
  done
  if ! git -C "$_repo_dir" show "$_base_ref:.release-please-manifest.json" > "$snapshot_dir/target/.release-please-manifest.json" 2>/dev/null; then
    return 1
  fi

  _semver_pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
  _manifest_jq='if length == 1 and (.[0] | type == "object" and length == 1 and (.["."] | type == "string")) then .[0]["."] else error end'
  if ! _head_version="$(jq -ser "$_manifest_jq" "$snapshot_dir/head/.release-please-manifest.json" 2>/dev/null)"; then
    return 1
  fi
  if ! _merge_version="$(jq -ser "$_manifest_jq" "$snapshot_dir/base/.release-please-manifest.json" 2>/dev/null)"; then
    return 1
  fi
  if ! _base_version="$(jq -ser "$_manifest_jq" "$snapshot_dir/target/.release-please-manifest.json" 2>/dev/null)"; then
    return 1
  fi

  for _ver in "$_head_version" "$_merge_version" "$_base_version"; do
    if [ -z "$_ver" ] || [ "$(printf '%s\n' "$_ver" | awk 'END { print NR }')" -ne 1 ] || ! printf '%s\n' "$_ver" | grep -Eq "$_semver_pattern"; then
      return 1
    fi
  done

  if [ "$(compare_semver "$_merge_version" "$_head_version")" != '-1' ]; then
    return 1
  fi
  if [ "$(compare_semver "$_base_version" "$_head_version")" != '-1' ]; then
    return 1
  fi

  if ! grep -Fq "## [$_head_version](" "$snapshot_dir/head/CHANGELOG.md"; then
    return 1
  fi

  # Verify ui/package.json changed ONLY .version to the exact manifest version.
  if ! jq -en --arg v "$_head_version" \
    --slurpfile base "$snapshot_dir/base/ui/package.json" \
    --slurpfile head "$snapshot_dir/head/ui/package.json" \
    '($base | length == 1) and ($head | length == 1) and ($base[0] | type == "object") and ($head[0] | type == "object") and ($head[0].version == $v) and (($base[0] | del(.version)) == ($head[0] | del(.version)))' >/dev/null 2>&1; then
    return 1
  fi

  # Verify ui/package-lock.json changed ONLY .version and .packages[""].version.
  if ! jq -en --arg v "$_head_version" \
    --slurpfile base "$snapshot_dir/base/ui/package-lock.json" \
    --slurpfile head "$snapshot_dir/head/ui/package-lock.json" \
    '($base | length == 1) and ($head | length == 1) and ($base[0] | type == "object") and ($head[0] | type == "object") and ($head[0].packages | type == "object") and ($head[0].packages[""] | type == "object") and ($head[0].version == $v) and ($head[0].packages[""].version == $v) and (($base[0] | del(.version, .packages[""].version)) == ($head[0] | del(.version, .packages[""].version)))' >/dev/null 2>&1; then
    return 1
  fi

  return 0
}

classify_files() {
  _files="$1"
  if [ -z "$_files" ]; then
    go=true; ui=true; native=true; selection=true
    return
  fi
  go=false
  ui=false
  native=false
  selection=false
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    case "$path" in
      LICENSE*|NOTICE*|*THIRD_PARTY*|*LICENSES*|.github/workflows/*|scripts/build-native-release.sh|scripts/classify-ci-changes.sh|scripts/install-ci-runtime-tools.sh|scripts/publish-controller-image.sh|scripts/test-ci-workflows.sh|release-please-config.json|.release-please-manifest.json)
        go=true; ui=true; native=true; selection=true ;;
      subscription_profiles/*)
        go=true; native=true; selection=true ;;
      *.md|docs/*|.github/ISSUE_TEMPLATE/*|.github/PULL_REQUEST_TEMPLATE.md)
        ;;
      ui/*)
        ui=true; native=true ;;
      tools/legacy-export/*)
        go=true; native=true ;;
      *.go|go.mod|go.sum|cmd/*|control/*|landing/*|deploy/*|scripts/*|licenses/*)
        go=true; native=true; selection=true ;;
      *)
        go=true; ui=true; native=true; selection=true ;;
    esac
  done <<EOF
$_files
EOF
}

mode="${1:-}"
go=true
ui=true
native=true
selection=true
release_only=false

case "$mode" in
  --git)
    [ "$#" -eq 3 ] || usage
    repo_dir="$(git rev-parse --show-toplevel)"
    merge_base="$(git merge-base "$2" "$3")"
    if is_verified_version_only_release "$repo_dir" "$2" "$merge_base" "$3"; then
      go=false
      ui=true
      native=false
      selection=false
      release_only=true
    else
      changed="$(git diff --no-renames --name-only "$merge_base" "$3")"
      classify_files "$changed"
    fi
    ;;
  --files)
    [ "$#" -eq 1 ] || usage
    changed="$(cat)"
    classify_files "$changed"
    ;;
  *) usage ;;
esac

printf 'go=%s\nui=%s\nnative=%s\nselection=%s\nrelease_only=%s\n' \
  "$go" "$ui" "$native" "$selection" "$release_only"
