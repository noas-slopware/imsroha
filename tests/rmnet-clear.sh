#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# A stale rmnet link on mux 3 (named like b2q-imsd's qmapmux0.3) and an
# unrelated one on mux 4: imsroha_rmnet_clear_mux(d0, 3) deletes the first
# only, and a new link on mux 3 can then be added. Skips (77) without user
# and network namespaces or the rmnet driver.
set -eu
bin=$1
if ! unshare -rn sh -c 'ip link add d0 type dummy && ip link add link d0 name t0 type rmnet mux_id 9' >/dev/null 2>&1; then
	echo "rmnet-clear: no namespaces or rmnet here, skipped"
	exit 77
fi
unshare -rn sh -c '
	set -e
	ip link add d0 type dummy
	ip link add link d0 name qmapmux0.3 type rmnet mux_id 3
	ip link add link d0 name other0 type rmnet mux_id 4
	"$0"
	ip link show qmapmux0.3 >/dev/null 2>&1 && { echo "stale link still there"; exit 1; }
	ip link show other0 >/dev/null
	ip link add link d0 name imsroha0 type rmnet mux_id 3
	echo "rmnet-clear: stale mux 3 link gone, mux 4 kept, imsroha0 added"
' "$bin"
