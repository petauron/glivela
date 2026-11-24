#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
project_dir="$(CDPATH='' cd -- "$script_dir/.." && pwd)"
ci_workflow="$project_dir/.github/workflows/ci.yml"
release_workflow="$project_dir/.github/workflows/release-please.yml"
classifier="$project_dir/scripts/classify-ci-changes.sh"

require_line() {
  file="$1"
  expected="$2"
  if ! grep -Fq -- "$expected" "$file"; then
    echo "$file is missing: $expected" >&2
    exit 1
  fi
}

# Verify POSIX sh syntax for all CI and release scripts.
for sh_script in \
  scripts/install-ci-runtime-tools.sh \
  scripts/build-native-release.sh \
  scripts/publish-controller-image.sh \
  scripts/classify-ci-changes.sh \
  scripts/test-ci-workflows.sh; do
  sh -n "$project_dir/$sh_script"
done

# Workflow policy invariants: zero downloadable artifacts, disabled Docker build
# records, strict fail-closed CI gate, cached upstream assets & legacy-export modules.
for workflow in "$ci_workflow" "$release_workflow"; do
  if grep -Eq 'actions/(upload|download)-artifact' "$workflow"; then
    echo "$workflow must not upload or download Actions artifacts." >&2
    exit 1
  fi
  require_line "$workflow" "DOCKER_BUILD_RECORD_UPLOAD: 'false'"
  require_line "$workflow" 'GLIVELA_UPSTREAM_CACHE_DIR: ${{ runner.temp }}/glivela-upstream-cache'
  require_line "$workflow" 'tools/legacy-export/go.sum'
done

require_line "$ci_workflow" '    name: CI / gate'
require_line "$ci_workflow" '    if: always() && !cancelled()'
require_line "$ci_workflow" 'sh scripts/classify-ci-changes.sh --git'
require_line "$ci_workflow" 'sh scripts/test-ci-workflows.sh'
require_line "$release_workflow" '          skip-github-pull-request: true'
require_line "$release_workflow" '          skip-github-release: true'
require_line "$release_workflow" '          permission-contents: write'
require_line "$release_workflow" '          permission-pull-requests: write'

# --files mode classification tests (no Git content -> release metadata fails closed).
assert_flags() {
  output="$1"
  shift
  for expected in "$@"; do
    if ! printf '%s\n' "$output" | grep -Fxq "$expected"; then
      echo "Expected $expected in classifier output:" >&2
      printf '%s\n' "$output" >&2
      exit 1
    fi
  done
}

out="$(printf '%s\n' 'README.md' 'docs/startup-readiness.md' | sh "$classifier" --files)"
assert_flags "$out" go=false ui=false native=false selection=false release_only=false

out="$(printf '%s\n' 'ui/src/App.tsx' | sh "$classifier" --files)"
assert_flags "$out" go=false ui=true native=true selection=false release_only=false

out="$(printf '%s\n' 'control/runtime.go' | sh "$classifier" --files)"
assert_flags "$out" go=true ui=false native=true selection=true release_only=false

out="$(printf '%s\n' 'tools/legacy-export/main.go' | sh "$classifier" --files)"
assert_flags "$out" go=true ui=false native=true selection=false release_only=false

out="$(printf '%s\n' 'subscription_profiles/README.md' | sh "$classifier" --files)"
assert_flags "$out" go=true ui=false native=true selection=true release_only=false

out="$(printf '' | sh "$classifier" --files)"
assert_flags "$out" go=true ui=true native=true selection=true release_only=false

out="$(printf '%s\n' 'unknown.dat' | sh "$classifier" --files)"
assert_flags "$out" go=true ui=true native=true selection=true release_only=false

out="$(printf '%s\n' '.release-please-manifest.json' 'CHANGELOG.md' 'ui/package.json' 'ui/package-lock.json' | sh "$classifier" --files)"
assert_flags "$out" go=true ui=true native=true selection=true release_only=false

# --git mode tests with a temporary Git repository.
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/glivela-ci-policy-test.XXXXXX")"
cleanup_tmp() {
  trap - EXIT HUP INT TERM
  rm -rf -- "$tmp_dir"
}
trap cleanup_tmp EXIT
trap 'cleanup_tmp; exit 129' HUP
trap 'cleanup_tmp; exit 130' INT
trap 'cleanup_tmp; exit 143' TERM

git_repo="$tmp_dir/repo"
mkdir -p "$git_repo/ui" "$git_repo/control" "$git_repo/docs"
git -C "$git_repo" init -q
git -C "$git_repo" config user.name test
git -C "$git_repo" config user.email test@example.invalid

write_release_files() {
  ver="$1"
  pkg_extra="${2:-}"
  lock_extra="${3:-}"
  printf '{"." : "%s"}\n' "$ver" > "$git_repo/.release-please-manifest.json"
  printf '# Changelog\n\n## [%s](https://example.invalid) (2026-11-24)\n' "$ver" > "$git_repo/CHANGELOG.md"
  printf '{"name":"@petauron/glivela-ui","version":"%s"%s}\n' "$ver" "$pkg_extra" > "$git_repo/ui/package.json"
  printf '{"name":"@petauron/glivela-ui","version":"%s","packages":{"":{"name":"@petauron/glivela-ui","version":"%s"}%s}}\n' "$ver" "$ver" "$lock_extra" > "$git_repo/ui/package-lock.json"
}

write_release_files 0.1.1
printf 'package control\n' > "$git_repo/control/sample.go"
printf '# Guide\n' > "$git_repo/docs/guide.md"
git -C "$git_repo" add -- .
git -C "$git_repo" commit -qm base-0-1-1
m0="$(git -C "$git_repo" rev-parse HEAD)"

# 1. Valid version-only Release Please PR -> UI build/test only, skip Go/native/selection.
git -C "$git_repo" checkout -qb pr-release "$m0"
write_release_files 0.2.0
git -C "$git_repo" add -- .release-please-manifest.json CHANGELOG.md ui/package.json ui/package-lock.json
git -C "$git_repo" commit -qm release-0-2-0
r1="$(git -C "$git_repo" rev-parse HEAD)"

out="$(cd "$git_repo" && sh "$classifier" --git "$m0" "$r1")"
assert_flags "$out" go=false ui=true native=false selection=false release_only=true

# 2. Extra file alongside release metadata -> fail closed to full CI.
git -C "$git_repo" checkout -qb pr-release-extra "$r1"
printf 'extra\n' > "$git_repo/README.md"
git -C "$git_repo" add -- README.md
git -C "$git_repo" commit -qm release-extra
r_extra="$(git -C "$git_repo" rev-parse HEAD)"

out="$(cd "$git_repo" && sh "$classifier" --git "$m0" "$r_extra")"
assert_flags "$out" go=true ui=true native=true selection=true release_only=false

# 3. Non-version change smuggled into ui/package.json -> fail closed.
git -C "$git_repo" checkout -qb pr-pkg-tamper "$m0"
write_release_files 0.2.0 ',"scripts":{"build":"echo tampered"}'
git -C "$git_repo" add -- .release-please-manifest.json CHANGELOG.md ui/package.json ui/package-lock.json
git -C "$git_repo" commit -qm pkg-tamper
r_pkg="$(git -C "$git_repo" rev-parse HEAD)"

out="$(cd "$git_repo" && sh "$classifier" --git "$m0" "$r_pkg")"
assert_flags "$out" go=true ui=true native=true selection=true release_only=false

# 4. Non-version change smuggled into ui/package-lock.json -> fail closed.
git -C "$git_repo" checkout -qb pr-lock-tamper "$m0"
write_release_files 0.2.0 '' ',"node_modules/evil":{"version":"1.0.0"}'
git -C "$git_repo" add -- .release-please-manifest.json CHANGELOG.md ui/package.json ui/package-lock.json
git -C "$git_repo" commit -qm lock-tamper
r_lock="$(git -C "$git_repo" rev-parse HEAD)"

out="$(cd "$git_repo" && sh "$classifier" --git "$m0" "$r_lock")"
assert_flags "$out" go=true ui=true native=true selection=true release_only=false

# 5. Mismatched .packages[""].version -> fail closed.
git -C "$git_repo" checkout -qb pr-lock-mismatch "$m0"
write_release_files 0.2.0
printf '{"name":"@petauron/glivela-ui","version":"0.2.0","packages":{"":{"name":"@petauron/glivela-ui","version":"0.1.1"}}}\n' > "$git_repo/ui/package-lock.json"
git -C "$git_repo" add -- .release-please-manifest.json CHANGELOG.md ui/package.json ui/package-lock.json
git -C "$git_repo" commit -qm lock-mismatch
r_mismatch="$(git -C "$git_repo" rev-parse HEAD)"

out="$(cd "$git_repo" && sh "$classifier" --git "$m0" "$r_mismatch")"
assert_flags "$out" go=true ui=true native=true selection=true release_only=false

# 6. Version downgrade -> fail closed.
git -C "$git_repo" checkout -qb pr-downgrade "$m0"
write_release_files 0.1.0
git -C "$git_repo" add -- .release-please-manifest.json CHANGELOG.md ui/package.json ui/package-lock.json
git -C "$git_repo" commit -qm downgrade
r_down="$(git -C "$git_repo" rev-parse HEAD)"

out="$(cd "$git_repo" && sh "$classifier" --git "$m0" "$r_down")"
assert_flags "$out" go=true ui=true native=true selection=true release_only=false

# 7. Executable 100755 manifest -> fail closed.
git -C "$git_repo" checkout -qb pr-exec-mode "$r1"
chmod +x "$git_repo/.release-please-manifest.json"
git -C "$git_repo" add -- .release-please-manifest.json
git -C "$git_repo" commit -qm exec-mode
r_exec="$(git -C "$git_repo" rev-parse HEAD)"

out="$(cd "$git_repo" && sh "$classifier" --git "$m0" "$r_exec")"
assert_flags "$out" go=true ui=true native=true selection=true release_only=false

# 8. Behind-main docs PR and behind-main release PR use git merge-base cleanly.
git -C "$git_repo" checkout -qb main-ahead "$m0"
printf 'package control // main update\n' > "$git_repo/control/sample.go"
git -C "$git_repo" add -- control/sample.go
git -C "$git_repo" commit -qm main-go
m1="$(git -C "$git_repo" rev-parse HEAD)"

git -C "$git_repo" checkout -qb pr-docs "$m0"
printf '# Updated guide\n' > "$git_repo/docs/guide.md"
git -C "$git_repo" add -- docs/guide.md
git -C "$git_repo" commit -qm pr-docs
d1="$(git -C "$git_repo" rev-parse HEAD)"

out="$(cd "$git_repo" && sh "$classifier" --git "$m1" "$d1")"
assert_flags "$out" go=false ui=false native=false selection=false release_only=false

out="$(cd "$git_repo" && sh "$classifier" --git "$m1" "$r1")"
assert_flags "$out" go=false ui=true native=false selection=false release_only=true

# 9. Main already released 0.2.0 -> stale release PR fails closed.
git -C "$git_repo" checkout -qb main-released "$m0"
write_release_files 0.2.0
git -C "$git_repo" add -- .release-please-manifest.json CHANGELOG.md ui/package.json ui/package-lock.json
git -C "$git_repo" commit -qm main-0-2-0
m2="$(git -C "$git_repo" rev-parse HEAD)"

out="$(cd "$git_repo" && sh "$classifier" --git "$m2" "$r1")"
assert_flags "$out" go=true ui=true native=true selection=true release_only=false

# 10. Multi-document / trailing-garbage manifest -> fail closed.
git -C "$git_repo" checkout -qb pr-multi-json "$m0"
write_release_files 0.2.0
printf '{"." : "0.2.0"}\n{"extra": 1}\n' > "$git_repo/.release-please-manifest.json"
git -C "$git_repo" add -- .release-please-manifest.json CHANGELOG.md ui/package.json ui/package-lock.json
git -C "$git_repo" commit -qm multi-json
r_multi="$(git -C "$git_repo" rev-parse HEAD)"

out="$(cd "$git_repo" && sh "$classifier" --git "$m0" "$r_multi")"
assert_flags "$out" go=true ui=true native=true selection=true release_only=false

# 11. Symlinked release metadata file (mode 120000) -> fail closed.
git -C "$git_repo" checkout -qb pr-symlink "$r1"
rm "$git_repo/CHANGELOG.md"
ln -s .release-please-manifest.json "$git_repo/CHANGELOG.md"
git -C "$git_repo" add -- CHANGELOG.md
git -C "$git_repo" commit -qm symlink-changelog
r_sym="$(git -C "$git_repo" rev-parse HEAD)"

out="$(cd "$git_repo" && sh "$classifier" --git "$m0" "$r_sym")"
assert_flags "$out" go=true ui=true native=true selection=true release_only=false

# 12. Moving a required file into docs/ must not hide the deleted source path (--no-renames).
git -C "$git_repo" checkout -qb pr-rename-to-docs "$m0"
git -C "$git_repo" mv control/sample.go docs/sample.md
git -C "$git_repo" commit -qm rename-source-to-docs
r_rename="$(git -C "$git_repo" rev-parse HEAD)"

out="$(cd "$git_repo" && sh "$classifier" --git "$m0" "$r_rename")"
assert_flags "$out" go=true ui=false native=true selection=true release_only=false

# 13. Empty diff in --git mode fails closed.
out="$(cd "$git_repo" && sh "$classifier" --git "$m0" "$m0")"
assert_flags "$out" go=true ui=true native=true selection=true release_only=false

echo "Glivela CI workflow policy test passed"
