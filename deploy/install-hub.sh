#!/bin/sh
# Installs a netmanager-vpn hub on a rented VPS. Run through the command the
# VPN tab in netmanager shows, which sets NMVPN_IMAGE and passes the join
# bundle as $1:
#   curl -fsSL <url> | sudo NMVPN_IMAGE=<image> sh -s -- <bundle>
set -eu

STATE_DIR=/var/lib/netmanager-vpn
ENV_DIR=/etc/netmanager-vpn
ENV_FILE=$ENV_DIR/env
CONTAINER=netmanager-vpn-hub
MIN_KERNEL_MAJOR=5
MIN_KERNEL_MINOR=6

die() {
  echo "$*" >&2
  exit 1
}

# The bundle holds the hub's private key and API token, so it is never echoed.
[ -n "${NMVPN_IMAGE:-}" ] || die "NMVPN_IMAGE belum diisi; pakai perintah instal dari tab VPN netmanager."
[ $# -ge 1 ] && [ -n "$1" ] || die "Bundle join wajib diberikan sebagai argumen pertama."
BUNDLE=$1

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

if ! command -v docker >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y docker.io
  else
    die "Docker belum terpasang dan distro ini tidak dikenali; pasang Docker lewat paket distro lalu ulangi."
  fi
fi

mkdir -p "$STATE_DIR" "$ENV_DIR"
# One key per host, kept across reinstalls: it encrypts the private keys
# already stored in state.db, so a new one would lock the hub out of them.
if [ ! -f "$ENV_FILE" ]; then
  (umask 077 && echo "NMVPN_ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)" >"$ENV_FILE")
fi
chmod 600 "$ENV_FILE"

docker pull "$NMVPN_IMAGE"
docker run --rm --network host --cap-add NET_ADMIN \
  -v "$STATE_DIR:$STATE_DIR" --env-file "$ENV_FILE" \
  "$NMVPN_IMAGE" hub join "$BUNDLE"

docker rm -f "$CONTAINER" 2>/dev/null || true
docker run -d --name "$CONTAINER" --restart unless-stopped \
  --network host --cap-add NET_ADMIN \
  --env-file "$ENV_FILE" -v "$STATE_DIR:$STATE_DIR" \
  "$NMVPN_IMAGE" -mode hub

# Backups stay under the mounted volume so they survive the container.
cat >/etc/cron.d/netmanager-vpn-backup <<CRON
15 3 * * * root docker exec $CONTAINER netmanager-vpn backup $STATE_DIR/backups
CRON

echo "Hub terpasang. Pantau statusnya di tab VPN netmanager sampai berubah menjadi online."
