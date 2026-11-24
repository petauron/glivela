#!/bin/sh
# Ubuntu tools for the existing isolated CI checks. Skip packages already
# present on the runner, scope APT to official Ubuntu sources over IPv4 with
# bounded timeouts, and fall back to an isolated 1.1.1.1 mount namespace only
# if the runner's default resolver fails.
set -eu
[ "${GITHUB_ACTIONS:-}" = true ]
[ "${RUNNER_OS:-}" = Linux ]
[ "$#" -gt 0 ]
for package in "$@"; do
  case "$package" in dnsmasq-base|iproute2|nftables) ;; *) exit 2 ;; esac
done

missing=''
for package in "$@"; do
  if [ "$(dpkg-query -W -f='${Status}\n' "$package" 2>/dev/null || true)" != 'install ok installed' ]; then
    missing="${missing:+$missing }$package"
  fi
done
if [ -z "$missing" ]; then
  exit 0
fi

ci_apt_dir=$(mktemp -d "${RUNNER_TEMP:?}/glivela-ci-apt.XXXXXX")
cleanup_apt() {
  trap - EXIT HUP INT TERM
  rm -rf -- "$ci_apt_dir"
}
trap cleanup_apt EXIT
trap 'cleanup_apt; exit 129' HUP
trap 'cleanup_apt; exit 130' INT
trap 'cleanup_apt; exit 143' TERM

mkdir -p "$ci_apt_dir/sources.list.d" "$ci_apt_dir/fallback-sources.d"
if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
  cp /etc/apt/sources.list.d/ubuntu.sources "$ci_apt_dir/sources.list.d/ubuntu.sources"
  sed -E 's|mirror\+file:/etc/apt/apt-mirrors\.txt|http://archive.ubuntu.com/ubuntu/|g; s|https?://[A-Za-z0-9.-]+\.archive\.ubuntu\.com/ubuntu/?|http://archive.ubuntu.com/ubuntu/|g' \
    /etc/apt/sources.list.d/ubuntu.sources > "$ci_apt_dir/fallback-sources.d/ubuntu.sources"
  apt_sourcelist=/dev/null
else
  apt_sourcelist=/etc/apt/sources.list
fi

apt_install_from() {
  _sourcelist="$1"
  _sourceparts="$2"
  shift 2
  sudo env DEBIAN_FRONTEND=noninteractive apt-get \
    -o Acquire::ForceIPv4=true \
    -o Acquire::Languages=none \
    -o Acquire::Retries=2 \
    -o Acquire::http::Timeout=10 \
    -o Acquire::https::Timeout=10 \
    -o "Dir::Etc::sourcelist=$_sourcelist" \
    -o "Dir::Etc::sourceparts=$_sourceparts" \
    update -qq --error-on=any && \
  sudo env DEBIAN_FRONTEND=noninteractive apt-get \
    -o Acquire::ForceIPv4=true \
    -o Acquire::Languages=none \
    -o Acquire::Retries=2 \
    -o Acquire::http::Timeout=10 \
    -o Acquire::https::Timeout=10 \
    -o "Dir::Etc::sourcelist=$_sourcelist" \
    -o "Dir::Etc::sourceparts=$_sourceparts" \
    install -y --no-install-recommends "$@"
}

# Word splitting on $missing is safe: every package name passed the allowlist above.
if apt_install_from "$apt_sourcelist" "$ci_apt_dir/sources.list.d" $missing; then
  exit 0
fi

# Fallback: isolate the resolver override inside APT's private mount namespace.
printf 'nameserver 1.1.1.1\nnameserver 1.0.0.1\noptions timeout:2 attempts:3\n' > "$ci_apt_dir/resolv.conf"
grep -q '^hosts:' /etc/nsswitch.conf
sed 's/^hosts:.*/hosts: files dns/' /etc/nsswitch.conf > "$ci_apt_dir/nsswitch.conf"
sha256sum /etc/resolv.conf /etc/nsswitch.conf > "$ci_apt_dir/host.sha256"
sudo unshare --mount --propagation private sh -s -- "$ci_apt_dir" "$apt_sourcelist" $missing <<'APT'
set -eu
ci_apt_dir=$1
apt_sourcelist=$2
shift 2
ci_resolver=$(readlink -f /etc/resolv.conf)
[ -f "$ci_resolver" ]
mount --bind "$ci_apt_dir/resolv.conf" "$ci_resolver"
mount --bind "$ci_apt_dir/nsswitch.conf" /etc/nsswitch.conf
cmp -s "$ci_apt_dir/resolv.conf" /etc/resolv.conf
getent ahostsv4 archive.ubuntu.com > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get \
  -o Acquire::ForceIPv4=true \
  -o Acquire::Languages=none \
  -o Acquire::Retries=2 \
  -o Acquire::http::Timeout=15 \
  -o Acquire::https::Timeout=15 \
  -o "Dir::Etc::sourcelist=$apt_sourcelist" \
  -o "Dir::Etc::sourceparts=$ci_apt_dir/fallback-sources.d" \
  update -qq --error-on=any
DEBIAN_FRONTEND=noninteractive apt-get \
  -o Acquire::ForceIPv4=true \
  -o Acquire::Languages=none \
  -o Acquire::Retries=2 \
  -o Acquire::http::Timeout=15 \
  -o Acquire::https::Timeout=15 \
  -o "Dir::Etc::sourcelist=$apt_sourcelist" \
  -o "Dir::Etc::sourceparts=$ci_apt_dir/fallback-sources.d" \
  install -y --no-install-recommends "$@"
APT
sha256sum --check --status "$ci_apt_dir/host.sha256"
