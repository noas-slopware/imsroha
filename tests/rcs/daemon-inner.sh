#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
set -eu
rcs=$1 client=$2 src=$3
ip link set lo up
t=$(mktemp -d)
pids=""
trap 'for p in $pids; do kill $p 2>/dev/null || true; done; rm -rf "$t"' EXIT
. "$src/tests/rcs/certs.sh"
make_certs "$t"
sed 's/@SIP_PORT@/15061/' "$src/tests/rcs/acs.xml" > "$t/acs.xml"
fail=0
bad() { echo "FAIL: $*"; fail=1; }

# The fake ACS, for every case.
mkfifo "$t/acs.in" "$t/acs.ready"
exec 3<>"$t/acs.in"
python3 -I "$src/tests/rcs/fake-acs.py" --http-port 18080 --https-port 18443 --cert "$t/server.pem" \
	--key "$t/server.key" --xml "$t/acs.xml" --scenario netauth --log "$t/acs.log" <&3 > "$t/acs.ready" &
pids="$pids $!"
read -r _ < "$t/acs.ready"
conns() { grep -c '^connect' "$t/acs.log" || true; }

conf() { # rcs-section-lines...
	{
		printf '[device]\nmodel=SM-F711N\noperator=LGU\nbuild=b2q-imsd-0.1\nvendor=SEC\n'
		printf '[carrier]\nrcs-acs-url=http://localhost:18080\nrcs-acs-https-url=https://localhost:18443\n'
		printf 'enable=true\n'
		for l in "$@"; do printf '%s\n' "$l"; done
	} > "$t/imsroha.conf"
}
# carriers.conf with an LG U+ group that tries to turn RCS on.
sed 's/^\[LG U+\]$/[LG U+]\nenable=true\nrcs-enable=true/' "$src/data/carriers.conf" > "$t/carriers.conf"
export IMSROHA_CONF="$t/imsroha.conf" IMSROHA_CARRIERS="$t/carriers.conf" IMSROHA_RCS_STATE="$t/state"
export IMSROHA_RCS_IMSI=450069999999999 IMSROHA_RCS_IMEI=359999999999999 IMSROHA_RCS_BUS=session
unset DBUS_SESSION_BUS_ADDRESS || true

# --- off ---
for case in "none" "[rcs]|enable=false" "[rcs]|#enable=true"; do
	before=$(conns)
	# shellcheck disable=SC2046
	conf $(printf '%s' "$case" | tr '|' ' ' | sed 's/^none$//')
	"$rcs" 2> "$t/off.err" || bad "off ($case): exit status $?"
	[ "$(conns)" = "$before" ] || bad "off ($case): it connected to the ACS"
	[ ! -e "$t/state" ] || bad "off ($case): it wrote $t/state"
	grep -q "RCS is off" "$t/off.err" || bad "off ($case): $(cat "$t/off.err")"
	echo "off ($case): no connection, nothing written"
done

# --- on, under a private bus ---
conf '[rcs]' 'enable=true' "ca-file=$t/ca.pem" 'msisdn=+821099999999'
mkfifo "$t/net.in" "$t/net.out"
exec 4<>"$t/net.in"
python3 -I "$src/tests/rcs/fake-pcscf.py" --sip-port 15061 --msrp-port 12855 --cert "$t/server.pem" \
	--key "$t/server.key" --log "$t/net.log" <&4 > "$t/net.out" &
pids="$pids $!"
exec 5<"$t/net.out"
read -r _ <&5
dbus-run-session -- sh -c '
	"$1" 2> "$2/rcs.err" & d=$!
	"$3" > "$2/client.out" 2>&1; c=$?
	# The fake network reports when it has both IMDNs for the chat it opened.
	timeout 20 sh -c "read -r line <&5 && echo \"network: \$line\"" > "$2/net.result" || true
	kill -TERM $d; wait $d
	exit $c' sh "$rcs" "$t" "$client" || bad "client failed"
cat "$t/client.out"
cat "$t/net.result"
grep -q "network: done" "$t/net.result" || bad "the network did not get both IMDNs"
reg=$(grep -A14 '^sip-in REGISTER' "$t/net.log" | head -30)
for want in "Contact: <sip:+821099999999@127.0.0.1:" ';transport=tls>;+sip.instance="<urn:gsma:imei:35999999-999999-0>";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"' \
	"User-Agent: TTA-RCS/2.4 SM-F711N/b2q-imsd-0.1 Device_Type/RCS_Android_Phone LGU" \
	'Authorization: Digest username="+821099999999@rcs.test",realm="rcs.test",uri="sip:rcs.test",nonce="",response=""' \
	"Expires: 600000" "From: <sip:+821099999999@rcs.test>"; do
	printf '%s\n' "$reg" | grep -qF -- "$want" || bad "REGISTER lacks: $want"
done
grep -q 'nonce="b5ba9c08f1a8e1d1",response="' "$t/net.log" || bad "no Digest answer"
grep -q '^sip-in INVITE tel:+821000000001 SIP/2.0' "$t/net.log" || bad "no chat INVITE to tel:+821000000001"
grep -q '^   Route: <sip:orig@localhost:15061;transport=tls;lr>' "$t/net.log" || bad "INVITE without the Service-Route"
grep -q '^sip-in ACK sip:peer1@localhost:15061;transport=tls' "$t/net.log" || bad "no ACK to the Contact"
grep -q 'event composing active bare' "$t/net.log" || bad "no bare isComposing (R9 7.2.3)"
grep -q 'event imdn mt1 delivered' "$t/net.log" || bad "no delivered IMDN"
grep -q 'event imdn mt1 displayed' "$t/net.log" || bad "no displayed IMDN"
grep -q '^sip-in OPTIONS tel:+821000000001' "$t/net.log" || bad "no OPTIONS"
grep -q 'Expires: 0' "$t/net.log" || bad "no de-registration at SIGTERM"
grep -q '^state registered' "$t/client.out" || grep -q 'registered as' "$t/rcs.err" || bad "never registered"
[ -s "$t/state/450069999999999/config.xml" ] || bad "no stored configuration"

# --- off after on: one rcs_state=-4, then nothing ---
conf '[rcs]' 'enable=false' "ca-file=$t/ca.pem" 'msisdn=+821099999999'
before=$(conns)
"$rcs" 2> "$t/off2.err" || bad "disable: exit status"
grep -q 'rcs_state=-4' "$t/acs.log" || bad "disable: no rcs_state=-4"
n=$(conns)
[ "$n" -gt "$before" ] || bad "disable: no request"
"$rcs" 2> "$t/off3.err" || bad "second off: exit status"
[ "$(conns)" = "$n" ] || bad "second off: asked the ACS again"
echo "off after on: one rcs_state=-4, then nothing"

if [ $fail != 0 ]; then
	echo "--- imsroha-rcs"; cat "$t/rcs.err"
	echo "--- network"; cat "$t/net.log"
	echo "--- off2"; cat "$t/off2.err"
	exit 1
fi
echo "rcs-daemon: passed"
