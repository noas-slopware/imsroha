#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Autoconfiguration against tests/rcs/fake-acs.py, in a private network
# namespace with nothing but loopback: no packet can reach a carrier.
# $1 acs-flow binary, $2 source dir.
set -eu
bin=$1 src=$2
if ! unshare -rn true 2>/dev/null; then
	echo "acs-flow: no user/network namespaces here, skipped"
	exit 77
fi
exec unshare -rn sh "$src/tests/rcs/acs-flow-inner.sh" "$bin" "$src"
