#!/bin/sh
# Ubuntu tools for the existing isolated CI checks. The hosted resolver can fail
# for Ubuntu archives while GitHub downloads remain available. Keep the resolver
# override inside APT's private mount namespace, never in the runner or tests.
set -eu
[ "${GITHUB_ACTIONS:-}" = true ]
[ "${RUNNER_OS:-}" = Linux ]
[ "$#" -gt 0 ]
for package in "$@"; do
  case "$package" in dnsmasq-base|iproute2|nftables) ;; *) exit 2 ;; esac
done
ci_apt_dir=$(mktemp -d "${RUNNER_TEMP:?}/glivela-ci-apt.XXXXXX")
trap 'rm -rf -- "$ci_apt_dir"' EXIT
printf 'nameserver 1.1.1.1\nnameserver 1.0.0.1\noptions timeout:2 attempts:3\n' > "$ci_apt_dir/resolv.conf"
grep -q '^hosts:' /etc/nsswitch.conf
sed 's/^hosts:.*/hosts: files dns/' /etc/nsswitch.conf > "$ci_apt_dir/nsswitch.conf"
sha256sum /etc/resolv.conf /etc/nsswitch.conf > "$ci_apt_dir/host.sha256"
sudo unshare --mount --propagation private sh -s -- "$ci_apt_dir" "$@" <<'APT'
set -eu
ci_apt_dir=$1
shift
ci_resolver=$(readlink -f /etc/resolv.conf)
[ -f "$ci_resolver" ]
mount --bind "$ci_apt_dir/resolv.conf" "$ci_resolver"
mount --bind "$ci_apt_dir/nsswitch.conf" /etc/nsswitch.conf
cmp -s "$ci_apt_dir/resolv.conf" /etc/resolv.conf
getent ahostsv4 azure.archive.ubuntu.com > /dev/null
apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update -qq --error-on=any
apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 install -y --no-install-recommends "$@"
APT
sha256sum --check --status "$ci_apt_dir/host.sha256"
