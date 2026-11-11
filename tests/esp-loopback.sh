#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# The KT golden scenario with real IPsec: imsroha installs its SAs and
# policies with ip xfrm in a private user and network namespace, the fake
# P-CSCF answers through them on loopback, and the output must match the
# golden file apart from the ip lines the fake ip(8) prints there.
set -eu
bin=$1 ref=$2 norm=$3
# Needs user and network namespaces and XFRM in the kernel; skip (77) without.
if ! unshare -rn sh -c 'ip link set lo up && ip -6 xfrm state list' >/dev/null 2>&1; then
	echo "esp-loopback: no user/network namespaces or XFRM here, skipped"
	exit 77
fi
out=$(mktemp) err=$(mktemp)
trap 'rm -f "$out" "$err"' EXIT
GOLDEN_CARRIER=KT GOLDEN_REAL_IP=1 unshare -rn sh -c 'ip link set lo up && exec "$0"' "$bin" 2>"$err" | "$norm" > "$out"
grep -v '^+ ip ' "$ref" | diff -u - "$out"
# Every one of the four SAs must have carried packets.
counters=$(grep -E '\(bytes\), [0-9]+\(packets\)' "$err" || true)
if [ "$(printf '%s\n' "$counters" | grep -c 'packets')" != 4 ] || printf '%s\n' "$counters" | grep -q ', 0(packets)'; then
	cat "$err" >&2
	echo "esp-loopback: not every SA carried ESP" >&2
	exit 1
fi
echo "esp-loopback: all four SAs carried ESP, output identical"
printf '%s\n' "$counters"
