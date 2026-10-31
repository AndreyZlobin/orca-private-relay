#!/bin/sh
# Root-only preparation of an Ubuntu/Debian VPS. Existing engines are reused.
set -eu
MODE=${1:-apply}
NEED_BUILD=${RELAY_NEED_BUILD:-1}
case "$MODE" in apply|--plan|--dependencies-only) ;; *) echo 'Invalid bootstrap mode' >&2; exit 2;; esac
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;; *) echo 'Supported: Ubuntu 22.04/24.04/26.04 or Debian 12/13' >&2; exit 1;; esac
[ "$(dpkg --print-architecture)" = amd64 ] || { echo 'This installer currently supports Linux x86_64' >&2; exit 1; }
if [ "$MODE" = --plan ]; then
    for item in python3 curl tar iptables caddy docker; do
        if command -v "$item" >/dev/null 2>&1; then printf '%s: already installed\n' "$item";
        elif [ "$item" = docker ] && [ "$NEED_BUILD" = 0 ]; then printf 'docker: not needed (reuse installed binary)\n';
        else printf '%s: will install\n' "$item"; fi
    done
    printf 'Will configure: native Relay service, HTTPS, additive TCP 80/443 rules\n'
    exit 0
fi
[ "$(id -u)" = 0 ] || { echo 'Run bootstrap as root' >&2; exit 1; }
if [ "$MODE" = apply ]; then
    [ -d /run/systemd/system ] || { echo 'A booted systemd VPS is required' >&2; exit 1; }
fi
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
UPDATED=0
update_index() { if [ "$UPDATED" = 0 ]; then apt-get update -qq; UPDATED=1; fi; }
ensure_packages() {
    missing=''
    for package in "$@"; do
        if [ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)" != 'install ok installed' ]; then missing="$missing $package"; fi
    done
    [ -n "$missing" ] || return 0
    update_index
    # Never remove packages to fit a new engine or a reverse proxy onto a live host.
    plan=$(apt-get --simulate install --no-install-recommends $missing)
    if printf '%s\n' "$plan" | grep -Eq '^(Remv|Purg) '; then
        echo 'Package installation would remove existing software; refusing' >&2; exit 1
    fi
    for engine in docker.io docker-ce docker-ce-cli containerd containerd.io runc; do
        if [ "$(dpkg-query -W -f='${Status}' "$engine" 2>/dev/null || true)" = 'install ok installed' ] &&
            printf '%s\n' "$plan" | grep -Fq "Inst $engine "; then
            echo "Package installation would upgrade the running container runtime ($engine); refusing" >&2; exit 1
        fi
    done
    apt-get install -y --no-install-recommends --no-upgrade -o Dpkg::Options::=--force-confold $missing
}
ensure_packages ca-certificates curl python3 tar iproute2 iptables
if [ "$MODE" = apply ]; then
    listeners=$(ss -H -lntp '( sport = :80 or sport = :443 )')
    if [ -n "$listeners" ] && printf '%s\n' "$listeners" | grep -v '"caddy"' >/dev/null; then
        echo 'Ports 80/443 belong to another server; it will not be replaced' >&2; exit 1
    fi
fi
install -d -m 755 /etc/apt/keyrings
if ! command -v caddy >/dev/null 2>&1; then
    curl --fail --silent --show-error --location --retry 3 https://dl.cloudsmith.io/public/caddy/stable/gpg.key -o /etc/apt/keyrings/orca-caddy.asc
    chmod 644 /etc/apt/keyrings/orca-caddy.asc
    printf '%s\n' 'deb [signed-by=/etc/apt/keyrings/orca-caddy.asc] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main' > /etc/apt/sources.list.d/orca-caddy.list
    UPDATED=0
    ensure_packages caddy
fi
if [ "$NEED_BUILD" = 1 ] && ! command -v docker >/dev/null 2>&1; then
    for package in docker.io docker-ce containerd containerd.io runc podman-docker; do
        if [ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)" = 'install ok installed' ]; then
            echo "Existing container runtime ($package) requires explicit maintenance; refusing replacement" >&2; exit 1
        fi
    done
    curl --fail --silent --show-error --location --retry 3 "https://download.docker.com/linux/$ID/gpg" -o /etc/apt/keyrings/orca-docker.asc
    chmod 644 /etc/apt/keyrings/orca-docker.asc
    printf 'deb [arch=amd64 signed-by=/etc/apt/keyrings/orca-docker.asc] https://download.docker.com/linux/%s %s stable\n' "$ID" "$VERSION_CODENAME" > /etc/apt/sources.list.d/orca-docker.list
    UPDATED=0
    ensure_packages docker-ce docker-ce-cli containerd.io
    if [ "$MODE" = apply ]; then systemctl enable --now docker; fi
fi
if [ "$MODE" = --dependencies-only ]; then
    echo 'Dependencies prepared (service activation is performed during a normal VPS deployment)'
    exit 0
fi
if [ "$NEED_BUILD" = 1 ]; then
    docker info >/dev/null 2>&1 || { echo 'Existing Docker daemon is unavailable; refusing to restart it automatically' >&2; exit 1; }
fi
echo 'VPS dependencies ready; existing Docker and Caddy installations preserved'
