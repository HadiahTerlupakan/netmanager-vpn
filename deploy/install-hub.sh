#!/bin/sh
# Installs or upgrades a netmanager-vpn hub on a rented VPS. Run through the
# command the VPN tab in netmanager shows, which sets NMVPN_IMAGE and passes
# either the join bundle or "upgrade" as $1:
#   curl -fsSL <url> | $(command -v sudo) env NMVPN_IMAGE=<image> NMVPN_PORTS="<p>/udp 500/udp 4500/udp" sh -s -- <bundle>
#   curl -fsSL <url> | $(command -v sudo) env NMVPN_IMAGE=<image> NMVPN_PORTS="<p>/udp 500/udp 4500/udp" sh -s -- upgrade
# NMVPN_PORTS lists what the hub listens on; they must be free and are opened
# in the host firewall. NMVPN_ROOT only exists so the tests can run unrooted.
set -eu

ROOT=${NMVPN_ROOT:-}
STATE_DIR=$ROOT/var/lib/netmanager-vpn
STATE_DB=$STATE_DIR/state.db
ENV_DIR=$ROOT/etc/netmanager-vpn
ENV_FILE=$ENV_DIR/env
MODULES_CONF=$ROOT/etc/modules-load.d/netmanager-vpn.conf
CRON_FILE=$ROOT/etc/cron.d/netmanager-vpn-backup
PPP_DEVICE=$ROOT/dev/ppp
# L2TP/IPsec and the hub's nft rules need these on the host: a container
# cannot load kernel modules.
L2TP_MODULES="ppp_generic l2tp_ppp l2tp_netlink esp4 xfrm_user af_key nft_fib_inet nft_xfrm"
CONTAINER=netmanager-vpn-hub
MIN_KERNEL_MAJOR=5
MIN_KERNEL_MINOR=6
NOT_INSTALLED="Hub belum terpasang di VPS ini ($ENV_FILE dan $STATE_DB tidak ada); pakai perintah instal dengan bundle join, bukan upgrade."

die() {
  echo "$*" >&2
  exit 1
}

check_host() {
  # Checked before the root check so the refusal is testable without root.
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    virt=$(systemd-detect-virt 2>/dev/null || true)
    case $virt in
      openvz | lxc) die "VPS harus KVM (terdeteksi: $virt); WireGuard butuh modul kernel sendiri." ;;
    esac
  fi

  [ "$(id -u)" -eq 0 ] || die "Jalankan sebagai root (pakai sudo)."

  kernel=$(uname -r)
  major=${kernel%%.*}
  rest=${kernel#*.}
  minor=${rest%%[!0-9]*}
  if [ "$major" -lt "$MIN_KERNEL_MAJOR" ] ||
    { [ "$major" -eq "$MIN_KERNEL_MAJOR" ] && [ "$minor" -lt "$MIN_KERNEL_MINOR" ]; }; then
    die "Kernel $kernel terlalu lama; butuh >= $MIN_KERNEL_MAJOR.$MIN_KERNEL_MINOR."
  fi

  modprobe wireguard || die "Modul kernel wireguard tidak bisa dimuat."
  load_l2tp_modules
}

# Not fatal: without these the hub still serves WireGuard.
load_l2tp_modules() {
  loaded=""
  missing=""
  for m in $L2TP_MODULES; do
    if modprobe "$m" 2>/dev/null; then
      loaded="$loaded $m"
    else
      missing="$missing $m"
    fi
  done
  if [ -n "$missing" ]; then
    echo "L2TP tidak tersedia di VPS ini (modul gagal dimuat:$missing); hub berjalan dengan WireGuard saja." >&2
  fi
  [ -n "$loaded" ] || return 0
  mkdir -p "$(dirname "$MODULES_CONF")"
  for m in $loaded; do echo "$m"; done >"$MODULES_CONF"
}

# Names what holds a port, or prints nothing when it is free. Docker's
# published ports (Traefik on 443, say) are DNAT rules, not sockets, so the
# NAT table is read as well.
port_holder() {
  num=${1%/*}
  proto=${1#*/}
  case $proto in
    udp) flag=-Hlnu ;;
    *) flag=-Hlnt ;;
  esac
  ss "$flag" 2>/dev/null | awk -v p=":$num" 'substr($4, length($4) - length(p) + 1) == p' | head -n 1
  iptables-save -t nat 2>/dev/null | grep -E -- "-p $proto .*--dport $num( |\$)" | head -n 1 || true
}

check_ports() {
  for port in $NMVPN_PORTS; do
    holder=$(port_holder "$port")
    [ -z "$holder" ] || die "Port $port sudah dipakai: $holder"
  done
}

open_firewall() {
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    for port in $NMVPN_PORTS; do ufw allow "$port"; done
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && [ "$(firewall-cmd --state 2>/dev/null || true)" = running ]; then
    for port in $NMVPN_PORTS; do firewall-cmd --permanent --add-port="$port"; done
    firewall-cmd --reload
  fi
}

# Our own container holds the ports on a reinstall or upgrade, so it goes
# before they are checked.
release_ports() {
  docker rm -f "$CONTAINER" 2>/dev/null || true
  check_ports
}

install_docker() {
  command -v docker >/dev/null 2>&1 && return 0
  command -v apt-get >/dev/null 2>&1 ||
    die "Docker belum terpasang dan distro ini tidak dikenali; pasang Docker lewat paket distro lalu ulangi."
  # stdin is the script itself under curl | sh; apt must not read it.
  DEBIAN_FRONTEND=noninteractive apt-get update </dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io </dev/null
}

write_env() {
  mkdir -p "$STATE_DIR" "$ENV_DIR"
  chmod 700 "$STATE_DIR"
  # One key per host, kept across reinstalls: it encrypts the private keys
  # already stored in state.db, so a new one would lock the hub out of them.
  if [ ! -f "$ENV_FILE" ]; then
    key=$(head -c 32 /dev/urandom | base64)
    [ -n "$key" ] || die "Gagal membuat NMVPN_ENCRYPTION_KEY."
    (umask 077 && echo "NMVPN_ENCRYPTION_KEY=$key" >"$ENV_FILE")
  fi
  chmod 600 "$ENV_FILE"
}

pull_image() {
  docker pull "$NMVPN_IMAGE" || die "image tidak bisa di-pull; paket GHCR harus public atau login dulu"
}

join() {
  # Bundle goes over stdin: an argv element shows in ps and docker inspect.
  printf '%s' "$1" | docker run -i --rm --network host --cap-add NET_ADMIN \
    -v "$STATE_DIR:$STATE_DIR" --env-file "$ENV_FILE" \
    "$NMVPN_IMAGE" hub join -
}

start_hub() {
  open_firewall
  device=""
  [ ! -e "$PPP_DEVICE" ] || device="--device /dev/ppp"
  # shellcheck disable=SC2086 # $device is empty or two words
  docker run -d --name "$CONTAINER" --restart unless-stopped \
    --network host --cap-add NET_ADMIN $device \
    --env-file "$ENV_FILE" -v "$STATE_DIR:$STATE_DIR" \
    "$NMVPN_IMAGE" -mode hub
}

install_backup_cron() {
  # Backups stay under the mounted volume so they survive the container.
  if ! command -v crond >/dev/null 2>&1 && ! command -v cron >/dev/null 2>&1; then
    echo "Peringatan: cron tidak terpasang, cadangan harian tidak akan berjalan." >&2
  fi
  mkdir -p "$(dirname "$CRON_FILE")"
  cat >"$CRON_FILE" <<CRON
15 3 * * * root docker exec $CONTAINER netmanager-vpn backup $STATE_DIR/backups
CRON
}

# An upgrade keeps the hub's keys and peers: it needs the state an install
# left and never runs join, whose bundle would long have expired.
upgrade() {
  # The directory test runs before the root check so the refusal is testable
  # without root; the files inside are only readable once root.
  [ -d "$STATE_DIR" ] || die "$NOT_INSTALLED"
  check_host
  [ -f "$ENV_FILE" ] && [ -f "$STATE_DB" ] || die "$NOT_INSTALLED"
  command -v docker >/dev/null 2>&1 || die "Docker tidak ditemukan; hub ini tidak dipasang dengan skrip ini."
  pull_image
  release_ports
  start_hub
  install_backup_cron
  echo "Hub diperbarui ke $NMVPN_IMAGE."
}

# The whole body sits in main so a download cut short mid-function runs
# nothing: sh only executes the final `main "$@"` line if it arrived.
main() {
  # The bundle holds the hub's private key and API token, so it is never echoed.
  [ -n "${NMVPN_IMAGE:-}" ] || die "NMVPN_IMAGE belum diisi; pakai perintah instal dari tab VPN netmanager."
  [ -n "${NMVPN_PORTS:-}" ] || die "NMVPN_PORTS belum diisi; pakai perintah instal dari tab VPN netmanager."
  [ $# -ge 1 ] && [ -n "$1" ] || die "Bundle join (atau 'upgrade') wajib diberikan sebagai argumen pertama."
  if [ "$1" = upgrade ]; then
    upgrade
    return
  fi
  check_host
  install_docker
  write_env
  release_ports
  pull_image
  join "$1"
  start_hub
  install_backup_cron
  echo "Hub terpasang. Pantau statusnya di tab VPN netmanager sampai berubah menjadi online."
}

main "$@"
