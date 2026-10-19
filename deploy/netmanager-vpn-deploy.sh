#!/usr/bin/env bash
# Deploy netmanager-vpn ke k3s di radpro — dijalankan DI host itu.
#
# Pola yang sama dengan netmanager/scripts/deploy/netmanager-deploy.sh: dipanggil
# lewat SSH dengan kunci yang terkunci ke skrip ini
# (`command="/usr/local/bin/netmanager-vpn-deploy",restrict` di authorized_keys).
# Satu-satunya masukan adalah SHA commit; tag image dan manifes diturunkan dari
# commit itu, jadi kunci yang bocor paling jauh men-deploy ulang commit di `main`.
#
# REPO_GITHUB dan REGISTRY masih nilai rencana: repo GitHub dan visibilitas
# GHCR belum dibuat pemilik. Sesuaikan sebelum skrip ini dipasang di host.
#
# Pemakaian:
#   lewat SSH:  ssh radpro-vpn-deploy <sha-40>
#   manual di host:  netmanager-vpn-deploy <sha-40> --izinkan-tanpa-cadangan
#     (bendera itu hanya dihormati bila skrip TIDAK dipanggil lewat forced command)

set -euo pipefail

REPO_GITHUB="HadiahTerlupakan/netmanager-vpn"
CABANG_PRODUKSI="main"
NAMESPACE="netmanager-vpn"
REGISTRY="ghcr.io/hadiahterlupakan"
DIR_CADANGAN="/var/backups/netmanager-vpn"
# Direktori kunci milik root lalu diserahkan ke pengguna deploy dengan mode 700:
# /tmp bisa diisi symlink oleh pengguna lain.
DIR_KUNCI="/run/lock/netmanager-vpn"
BERKAS_KUNCI="${DIR_KUNCI}/deploy.lock"
CADANGAN_TERBARU_MENIT=1500
BATAS_ROLLOUT="180s"
K="sudo -n kubectl -n ${NAMESPACE}"

gagal() {
  echo "::error::$*" >&2
  exit 1
}

# Lewat forced command hanya token pertama SSH_ORIGINAL_COMMAND yang dipakai.
IZIN_TANPA_CADANGAN=false
if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
  read -r SHA _ <<< "${SSH_ORIGINAL_COMMAND}"
else
  SHA="${1:-}"
  [ "${2:-}" = "--izinkan-tanpa-cadangan" ] && IZIN_TANPA_CADANGAN=true
fi
[[ "${SHA}" =~ ^[0-9a-f]{40}$ ]] || gagal "Masukan harus SHA commit 40 karakter heksadesimal"

# Satu deploy dalam satu waktu; deploy kedua menunggu giliran.
sudo -n install -d -o "$(id -u)" -m 700 "${DIR_KUNCI}"
[ ! -L "${BERKAS_KUNCI}" ] || gagal "${BERKAS_KUNCI} adalah symlink; deploy ditolak"
exec 9>> "${BERKAS_KUNCI}"
echo "Menunggu giliran deploy..."
flock 9

api_github() {
  curl -fsS --retry 3 --retry-delay 5 \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO_GITHUB}/$1"
}

# Commit dari fork bisa dijangkau lewat URL repo induk; ia harus leluhur `main`.
echo "Verifikasi commit ${SHA} ada di ${CABANG_PRODUKSI}"
STATUS_BANDING="$(api_github "compare/${SHA}...${CABANG_PRODUKSI}" | jq -r '.status + " " + (.behind_by|tostring)')"
case "${STATUS_BANDING}" in
  "ahead 0"|"identical 0") ;;
  *) gagal "Commit ${SHA} bukan bagian dari ${CABANG_PRODUKSI} (${STATUS_BANDING}); deploy ditolak" ;;
esac

# Rumus tag harus sama dengan build-image.yml: 12 karakter commit + epoch committer.
TANGGAL_COMMIT="$(api_github "commits/${SHA}" | jq -r '.commit.committer.date')"
EPOCH_COMMIT="$(date -u -d "${TANGGAL_COMMIT}" +%s)"
TAG="${SHA:0:12}-${EPOCH_COMMIT}"
VPN_IMAGE="${REGISTRY}/netmanager-vpn:${TAG}"
echo "Image: ${VPN_IMAGE}"

KERJA="$(mktemp -d)"
trap 'rm -rf "${KERJA}"' EXIT
curl -fsSL --retry 3 "https://codeload.github.com/${REPO_GITHUB}/tar.gz/${SHA}" \
  | tar -xz -C "${KERJA}" --strip-components=1 --wildcards '*/deploy/k8s/core.yaml'
[ -f "${KERJA}/deploy/k8s/core.yaml" ] || gagal "Arsip commit tidak memuat deploy/k8s/core.yaml"
sed -e "s|{{VPN_IMAGE}}|${VPN_IMAGE}|g" "${KERJA}/deploy/k8s/core.yaml" > "${KERJA}/core.rendered.yaml"
if grep -qF '{{' "${KERJA}/core.rendered.yaml"; then
  gagal "Render manifes menyisakan placeholder"
fi

# Preflight sebelum apply: strategi Recreate mematikan core lama lebih dulu,
# jadi semua yang bisa diperiksa harus diperiksa di sini.
for rahasia in netmanager-vpn-secrets netmanager-vpn-registry; do
  ${K} get secret "${rahasia}" > /dev/null 2>&1 \
    || gagal "Secret ${rahasia} belum ada di namespace ${NAMESPACE}"
done

# Image dicek dengan kredensial pull cluster sendiri, sehingga yang lolos di
# sini pasti bisa ditarik kubelet.
KREDENSIAL_PULL="$(${K} get secret netmanager-vpn-registry -o jsonpath='{.data.\.dockerconfigjson}' \
  | base64 -d | jq -r '.auths | to_entries[0].value | .username + ":" + .password')"
REPO_IMAGE="${REGISTRY#ghcr.io/}/netmanager-vpn"
TOKEN_REGISTRY="$(curl -fsS -u "${KREDENSIAL_PULL}" "https://ghcr.io/token?scope=repository:${REPO_IMAGE}:pull" | jq -r .token)" \
  || gagal "Token registry tidak didapat; kredensial netmanager-vpn-registry salah?"
curl -fsS -o /dev/null \
  -H "Authorization: Bearer ${TOKEN_REGISTRY}" \
  -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
  "https://ghcr.io/v2/${REPO_IMAGE}/manifests/${TAG}" \
  || gagal "Image netmanager-vpn:${TAG} tidak ada di registry; build belum selesai?"
echo "Image tersedia."

# Cadangan lewat core yang sedang berjalan. Core yang crash-loop tidak bisa
# di-exec, padahal deploy perbaikannya justru yang dibutuhkan; maka salinan
# harian yang masih segar (CronJob) dianggap cukup.
if ${K} get deploy/netmanager-vpn > /dev/null 2>&1; then
  echo "Cadangan state sebelum rollout"
  if ! ${K} exec deploy/netmanager-vpn -- netmanager-vpn backup "${DIR_CADANGAN}"; then
    SEGAR="$(sudo -n find "${DIR_CADANGAN}" -maxdepth 1 -name 'state-*.db' -mmin "-${CADANGAN_TERBARU_MENIT}" 2> /dev/null || true)"
    if [ -n "${SEGAR}" ]; then
      echo "Exec gagal; memakai cadangan harian yang berumur < 25 jam"
    elif [ "${IZIN_TANPA_CADANGAN}" = "true" ]; then
      echo "PERINGATAN: lanjut tanpa cadangan (--izinkan-tanpa-cadangan)"
    else
      gagal "Cadangan gagal dan tidak ada salinan < 25 jam di ${DIR_CADANGAN}; deploy dibatalkan"
    fi
  fi
fi

${K} apply -f "${KERJA}/core.rendered.yaml"
${K} rollout status deploy/netmanager-vpn --timeout="${BATAS_ROLLOUT}" \
  || gagal "Rollout tidak selesai dalam ${BATAS_ROLLOUT}"

echo "Deploy ${TAG} selesai."
