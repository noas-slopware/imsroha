#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# imsroha-rcs end to end, in a private network namespace with nothing but
# loopback (no packet can reach a carrier) and a private D-Bus:
#   - off: no [rcs], enable=false, and carriers.conf/[carrier] trying to turn
#     it on: no connection at all, no state written;
#   - off after on: exactly one rcs_state=-4 request, then nothing;
#   - on: autoconfig, REGISTER with Digest over TLS, a chat both ways over
#     MSRP/TLS with IMDNs and isComposing, OPTIONS.
# $1 imsroha-rcs, $2 rcs-client, $3 source dir.
set -eu
if ! unshare -rn true 2>/dev/null; then
	echo "rcs-daemon: no user/network namespaces here, skipped"
	exit 77
fi
command -v dbus-run-session >/dev/null || { echo "rcs-daemon: no dbus-run-session, skipped"; exit 77; }
exec unshare -rn sh "$3/tests/rcs/daemon-inner.sh" "$@"
