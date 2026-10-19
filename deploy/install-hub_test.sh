#!/bin/sh
# Refusal paths of install-hub.sh, run without root or Docker.
set -u

script=$(dirname "$0")/install-hub.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

# A fake systemd-detect-virt placed first in PATH decides the virt type.
printf '#!/bin/sh\necho openvz\n' >"$tmp/systemd-detect-virt"
chmod +x "$tmp/systemd-detect-virt"

out=$(PATH="$tmp:$PATH" NMVPN_IMAGE=example/img:tag-1 sh "$script" bundle 2>&1)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "VPS harus KVM"; then
  echo "FAIL: openvz not rejected (status $status): $out"
  fail=1
fi

out=$(env -u NMVPN_IMAGE sh "$script" bundle 2>&1)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "NMVPN_IMAGE"; then
  echo "FAIL: missing NMVPN_IMAGE not rejected (status $status): $out"
  fail=1
fi

out=$(NMVPN_IMAGE=example/img:tag-1 sh "$script" 2>&1)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "Bundle"; then
  echo "FAIL: missing bundle not rejected (status $status): $out"
  fail=1
fi

# No hub has been installed on the test machine, so upgrade must refuse.
out=$(NMVPN_IMAGE=example/img:tag-1 sh "$script" upgrade 2>&1)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "Hub belum terpasang"; then
  echo "FAIL: upgrade without an installed hub not rejected (status $status): $out"
  fail=1
fi

out=$(env -u NMVPN_IMAGE sh "$script" upgrade 2>&1)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "NMVPN_IMAGE"; then
  echo "FAIL: upgrade without NMVPN_IMAGE not rejected (status $status): $out"
  fail=1
fi

[ "$fail" -eq 0 ] && echo "install-hub tests passed"
exit "$fail"
