#!/bin/sh
# Refusal paths of install-hub.sh, run without root or Docker.
set -u

script=$(dirname "$0")/install-hub.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
ports="51821/udp 500/udp 4500/udp"

# A fake systemd-detect-virt placed first in PATH decides the virt type.
printf '#!/bin/sh\necho openvz\n' >"$tmp/systemd-detect-virt"
chmod +x "$tmp/systemd-detect-virt"

out=$(PATH="$tmp:$PATH" NMVPN_IMAGE=example/img:tag-1 NMVPN_PORTS="$ports" sh "$script" bundle 2>&1)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "VPS harus KVM"; then
  echo "FAIL: openvz not rejected (status $status): $out"
  fail=1
fi

out=$(env -u NMVPN_IMAGE NMVPN_PORTS="$ports" sh "$script" bundle 2>&1)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "NMVPN_IMAGE"; then
  echo "FAIL: missing NMVPN_IMAGE not rejected (status $status): $out"
  fail=1
fi

out=$(NMVPN_IMAGE=example/img:tag-1 NMVPN_PORTS="$ports" sh "$script" 2>&1)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "Bundle"; then
  echo "FAIL: missing bundle not rejected (status $status): $out"
  fail=1
fi

# No hub has been installed on the test machine, so upgrade must refuse.
out=$(NMVPN_IMAGE=example/img:tag-1 NMVPN_PORTS="$ports" sh "$script" upgrade 2>&1)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "Hub belum terpasang"; then
  echo "FAIL: upgrade without an installed hub not rejected (status $status): $out"
  fail=1
fi

out=$(env -u NMVPN_IMAGE NMVPN_PORTS="$ports" sh "$script" upgrade 2>&1)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "NMVPN_IMAGE"; then
  echo "FAIL: upgrade without NMVPN_IMAGE not rejected (status $status): $out"
  fail=1
fi

out=$(NMVPN_IMAGE=example/img:tag-1 NMVPN_PORTS="" sh "$script" bundle 2>&1)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "NMVPN_PORTS"; then
  echo "FAIL: empty NMVPN_PORTS not rejected (status $status): $out"
  fail=1
fi

# A rooted fake host: NMVPN_ROOT redirects every path the script writes, and
# the fakes below stand in for the tools that need root or a real kernel.
new_host() {
  host=$tmp/host
  rm -rf "$host" "$tmp/bin"
  mkdir -p "$host/dev" "$tmp/bin"
  : >"$tmp/calls"
  : >"$tmp/ss_udp"
  : >"$tmp/ss_tcp"
  : >"$tmp/nat"
  printf '#!/bin/sh\necho 0\n' >"$tmp/bin/id"
  printf '#!/bin/sh\necho 6.8.0\n' >"$tmp/bin/uname"
  printf '#!/bin/sh\necho "docker $*" >>"%s/calls"\n' "$tmp" >"$tmp/bin/docker"
  printf '#!/bin/sh\n[ "$1" = l2tp_ppp ] && [ -n "${FAIL_L2TP:-}" ] && exit 1\necho "$1" >>"%s/modprobed"\nexit 0\n' "$tmp" >"$tmp/bin/modprobe"
  printf '#!/bin/sh\ncase "$1" in -Hlnu) cat "%s/ss_udp";; -Hlnt) cat "%s/ss_tcp";; esac\n' "$tmp" "$tmp" >"$tmp/bin/ss"
  printf '#!/bin/sh\ncat "%s/nat"\n' "$tmp" >"$tmp/bin/iptables-save"
  printf '#!/bin/sh\n[ "$1" = link ] && [ -e "%s/wg-nm" ]\n' "$tmp" >"$tmp/bin/ip"
  printf '#!/bin/sh\n[ "$1" = status ] && echo "Status: inactive"\nexit 0\n' >"$tmp/bin/ufw"
  printf '#!/bin/sh\n[ "$1" = --state ] && echo "not running"\nexit 0\n' >"$tmp/bin/firewall-cmd"
  chmod +x "$tmp"/bin/*
  rm -f "$tmp/modprobed" "$tmp/wg-nm"
}

run_install() {
  PATH="$tmp/bin:$PATH" NMVPN_ROOT="$host" NMVPN_IMAGE=example/img:tag-1 NMVPN_PORTS="${PORTS:-$ports}" \
    sh "$script" "$@" 2>&1
}

new_host
echo "UNCONN 0 0 0.0.0.0:500 0.0.0.0:* users:((\"pluto\",pid=9,fd=5))" >"$tmp/ss_udp"
out=$(run_install secret-bundle)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "Port 500/udp sudah dipakai" ||
  ! printf '%s' "$out" | grep -q pluto || grep -q "docker run -d" "$tmp/calls"; then
  echo "FAIL: UDP port held by a socket not refused (status $status): $out"
  fail=1
fi
if printf '%s' "$out" | grep -q secret-bundle || grep -q secret-bundle "$tmp/calls"; then
  echo "FAIL: bundle echoed or passed on argv"
  fail=1
fi
if grep -q "docker run -i" "$tmp/calls"; then
  echo "FAIL: join ran although a port was taken"
  fail=1
fi

new_host
echo "LISTEN 0 4096 *:443 *:* users:((\"nginx\",pid=3,fd=6))" >"$tmp/ss_tcp"
out=$(PORTS="443/tcp 500/udp" run_install bundle)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "Port 443/tcp sudah dipakai"; then
  echo "FAIL: TCP port held by a socket not refused (status $status): $out"
  fail=1
fi

new_host
echo "-A DOCKER ! -i br-x -p tcp -m tcp --dport 443 -j DNAT --to-destination 172.18.0.2:443" >"$tmp/nat"
out=$(PORTS="443/tcp" run_install bundle)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "Port 443/tcp sudah dipakai" ||
  ! printf '%s' "$out" | grep -q DNAT; then
  echo "FAIL: DNAT port not refused (status $status): $out"
  fail=1
fi

new_host
echo "-A DOCKER -p tcp -m tcp --dport 4430 -j DNAT --to-destination 172.18.0.2:443" >"$tmp/nat"
out=$(PORTS="443/tcp" run_install bundle)
status=$?
if [ "$status" -ne 0 ]; then
  echo "FAIL: --dport 4430 mistaken for 443 (status $status): $out"
  fail=1
fi

new_host
touch "$host/dev/ppp"
out=$(FAIL_L2TP=1 run_install bundle)
status=$?
if [ "$status" -ne 0 ] || ! printf '%s' "$out" | grep -q "L2TP tidak tersedia di VPS ini" ||
  ! grep -q "docker run -d" "$tmp/calls"; then
  echo "FAIL: failed l2tp_ppp stopped the install or went unannounced (status $status): $out"
  fail=1
fi
conf=$host/etc/modules-load.d/netmanager-vpn.conf
if grep -q l2tp_ppp "$conf" || ! grep -q ppp_generic "$conf"; then
  echo "FAIL: modules-load.d must list only the modules that loaded: $(cat "$conf")"
  fail=1
fi

new_host
out=$(run_install bundle)
status=$?
if [ "$status" -ne 0 ] || printf '%s' "$out" | grep -q "L2TP tidak tersedia"; then
  echo "FAIL: clean install (status $status): $out"
  fail=1
fi
if grep "docker run -d" "$tmp/calls" | grep -q -- "--device /dev/ppp"; then
  echo "FAIL: --device /dev/ppp passed although the host has none"
  fail=1
fi

touch "$host/dev/ppp"
out=$(run_install bundle)
if ! grep "docker run -d" "$tmp/calls" | tail -1 | grep -q -- "--device /dev/ppp"; then
  echo "FAIL: --device /dev/ppp missing although the host has it: $out"
  fail=1
fi

# Upgrade starts the hub through the same path, so it gets the same checks.
mkdir -p "$host/var/lib/netmanager-vpn" "$host/etc/netmanager-vpn"
: >"$host/var/lib/netmanager-vpn/state.db"
: >"$host/etc/netmanager-vpn/env"
echo "UNCONN 0 0 0.0.0.0:4500 0.0.0.0:*" >"$tmp/ss_udp"
: >"$tmp/calls"
out=$(run_install upgrade)
status=$?
if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "Port 4500/udp sudah dipakai"; then
  echo "FAIL: upgrade did not refuse a taken port (status $status): $out"
  fail=1
fi
if ! grep -q "^docker start netmanager-vpn-hub" "$tmp/calls" || grep -q "^docker rm" "$tmp/calls" ||
  grep -q "docker run -d" "$tmp/calls"; then
  echo "FAIL: a refused upgrade must start the old container again and not remove it: $(cat "$tmp/calls")"
  fail=1
fi

# The hub's own wg-nm socket outlives the container; it must not block an upgrade.
echo "UNCONN 0 0 0.0.0.0:51821 0.0.0.0:*" >"$tmp/ss_udp"
out=$(run_install upgrade)
if ! printf '%s' "$out" | grep -q "Port 51821/udp sudah dipakai"; then
  echo "FAIL: port 51821 must be refused without wg-nm: $out"
  fail=1
fi
: >"$tmp/wg-nm"
out=$(run_install upgrade)
status=$?
if [ "$status" -ne 0 ]; then
  echo "FAIL: upgrade tripped on its own wg-nm port (status $status): $out"
  fail=1
fi
rm -f "$tmp/wg-nm"
: >"$tmp/ss_udp"

for rule in "-p udp -m multiport --dports 443,500 -j DNAT" "-p udp -m udp --dport 400:600 -j DNAT"; do
  new_host
  echo "-A DOCKER $rule --to-destination 172.18.0.2:1" >"$tmp/nat"
  out=$(PORTS="500/udp" run_install bundle)
  status=$?
  if [ "$status" -eq 0 ] || ! printf '%s' "$out" | grep -q "Port 500/udp sudah dipakai"; then
    echo "FAIL: NAT rule '$rule' not refused (status $status): $out"
    fail=1
  fi
done
new_host
echo "-A DOCKER -p udp -m udp --dport 5000 -j DNAT --to-destination 172.18.0.2:1" >"$tmp/nat"
out=$(PORTS="500/udp" run_install bundle)
status=$?
if [ "$status" -ne 0 ]; then
  echo "FAIL: --dport 5000 mistaken for 500 (status $status): $out"
  fail=1
fi

out=$(env -u NMVPN_PORTS NMVPN_IMAGE=example/img:tag-1 sh "$script" upgrade 2>&1)
if ! printf '%s' "$out" | grep -q "perintah upgrade terbaru"; then
  echo "FAIL: upgrade without NMVPN_PORTS gives the wrong advice: $out"
  fail=1
fi

new_host
printf '#!/bin/sh\n[ "$1" = status ] && echo "Status: active"\necho "ufw $*" >>"%s/calls"\n' "$tmp" >"$tmp/bin/ufw"
chmod +x "$tmp/bin/ufw"
out=$(run_install bundle)
status=$?
n=$(grep -c "^ufw allow " "$tmp/calls")
if [ "$status" -ne 0 ] || [ "$n" -ne 3 ] || ! grep -q "^ufw allow 4500/udp" "$tmp/calls"; then
  echo "FAIL: ufw allow must run once per port (status $status, $n calls): $out"
  fail=1
fi

new_host
printf '#!/bin/sh\ncase "$1" in --state) echo running;; *) echo "firewall-cmd $*" >>"%s/calls";; esac\n' "$tmp" >"$tmp/bin/firewall-cmd"
chmod +x "$tmp/bin/firewall-cmd"
out=$(run_install bundle)
if ! grep -q "^firewall-cmd --permanent --add-port=500/udp" "$tmp/calls" ||
  ! grep -q "^firewall-cmd --add-port=500/udp" "$tmp/calls" || grep -q '^firewall-cmd --reload' "$tmp/calls"; then
  echo "FAIL: firewalld ports not opened at runtime and permanently without a reload: $out"
  fail=1
fi

new_host
out=$(run_install bundle)
if grep -q "^ufw\|^firewall-cmd" "$tmp/calls"; then
  echo "FAIL: firewall touched although none is active"
  fail=1
fi

[ "$fail" -eq 0 ] && echo "install-hub tests passed"
exit "$fail"
