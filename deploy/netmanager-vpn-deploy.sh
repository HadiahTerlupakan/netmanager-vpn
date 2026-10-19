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
# Pemakaian: ssh radpro-vpn-deploy <sha-40>

set -euo pipefail

REPO_GITHUB="HadiahTerlupakan/netmanager-vpn"
CABANG_PRODUKSI="main"
NAMESPACE="netmanager-vpn"
REGISTRY="ghcr.io/hadiahterlupakan"
DIR_CADANGAN="/var/backups/netmanager-vpn"
BERKAS_KUNCI="/tmp/netmanager-vpn-deploy.lock"
BATAS_ROLLOUT="180s"
K="sudo -n kubectl -n ${NAMESPACE}"

gagal() {
  echo "::error::$*" >&2
  exit 1
}

# Lewat forced command hanya token pertama SSH_ORIGINAL_COMMAND yang dipakai.
if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
  read -r SHA _ <<< "${SSH_ORIGINAL_COMMAND}"
else
  SHA="${1:-}"
fi
[[ "${SHA}" =~ ^[0-9a-f]{40}$ ]] || gagal "Masukan harus SHA commit 40 karakter heksadesimal"

# Satu deploy dalam satu waktu; deploy kedua menunggu giliran.
exec 9> "${BERKAS_KUNCI}"
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

# Cadangan sebelum rollout lewat image yang sedang berjalan, supaya skema lama
# yang masih dipakai core terbaca apa adanya. Image baru yang belum selesai
# dibangun baru ketahuan di rollout status. Deploy pertama belum punya
# Deployment dan dilewati.
if ${K} get deploy/netmanager-vpn > /dev/null 2>&1; then
  echo "Cadangan state sebelum rollout"
  ${K} exec deploy/netmanager-vpn -- netmanager-vpn backup "${DIR_CADANGAN}" \
    || gagal "Cadangan gagal; deploy dibatalkan"
fi

${K} apply -f "${KERJA}/core.rendered.yaml"
${K} rollout status deploy/netmanager-vpn --timeout="${BATAS_ROLLOUT}" \
  || gagal "Rollout tidak selesai dalam ${BATAS_ROLLOUT}"

echo "Deploy ${TAG} selesai."
