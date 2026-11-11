#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# imsroha-rcs with chatbots and RCS A2P (TTAK.KO-06.0410/R9 7.7), end to end
# in a private network namespace with nothing but loopback and a private
# D-Bus, against a fake chatbot platform (fake-pcscf.py --rbm) and a fake
# botinfo server; then the same configuration with [rcs] chatbot=false.
# $1 imsroha-rcs, $2 rbm-client, $3 source dir.
set -eu
if ! unshare -rn true 2>/dev/null; then
	echo "rcs-rbm: no user/network namespaces here, skipped"
	exit 77
fi
command -v dbus-run-session >/dev/null || { echo "rcs-rbm: no dbus-run-session, skipped"; exit 77; }
exec unshare -rn sh "$3/tests/rcs/rbm-inner.sh" "$@"
