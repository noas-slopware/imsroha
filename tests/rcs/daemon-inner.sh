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
sed 's/@SIP_PORT@/15061/; s/@CS_PORT@/18446/' "$src/tests/rcs/acs.xml" > "$t/acs.xml"
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
		printf '[device]\nmodel=SM-F711N\noperator=LGU\nvendor=SEC\n'
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

# --- file transfer: binary files (NULs, CRLFs, a boundary-like line, more
# than one read) and the fake content server ---
mkdir "$t/cs" "$t/ft" "$t/dl"
python3 -I - "$t/ft" <<'PY'
import sys
def blob(n, k):
    b = bytes((i * k + i // 253) % 256 for i in range(n))
    return (b'\r\n--imsroha\r\n\0\0\r\n\r\n' + b)[:n]
for name, n, k in (('rx1', 40000, 7), ('rx1t', 3000, 11), ('rx4', 100, 13), ('small.bin', 40000, 17),
                   ('large.bin', 100000, 19), ('huge.bin', 300000, 23)):
    open(f'{sys.argv[1]}/{name}', 'wb').write(blob(n, k))
PY
mkfifo "$t/cs.ready"
python3 -I "$src/tests/rcs/fake-cs.py" --port 18446 --cert "$t/server.pem" --key "$t/server.key" \
	--log "$t/cs.log" --store "$t/cs" --user ftuser@rcs.test --pwd ftSecretPw \
	--serve "rx1=$t/ft/rx1" --serve "rx1t=$t/ft/rx1t" --serve "rx4=$t/ft/rx4" --chunked rx1t \
	< /dev/null > "$t/cs.ready" &
pids="$pids $!"
read -r _ < "$t/cs.ready"
export RCS_FT_SMALL="$t/ft/small.bin" RCS_FT_LARGE="$t/ft/large.bin" RCS_FT_HUGE="$t/ft/huge.bin"

# --- on, under a private bus ---
conf '[rcs]' 'enable=true' "ca-file=$t/ca.pem" 'msisdn=+821099999999' "download-dir=$t/dl"
mkfifo "$t/net.in" "$t/net.out"
exec 4<>"$t/net.in"
python3 -I "$src/tests/rcs/fake-pcscf.py" --sip-port 15061 --msrp-port 12855 --cert "$t/server.pem" \
	--key "$t/server.key" --log "$t/net.log" --cs-port 18446 --ft-dir "$t/ft" <&4 > "$t/net.out" &
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
for want in "Contact: <sip:+821099999999@127.0.0.1:" ';transport=tls>;+sip.instance="<urn:gsma:imei:35999999-999999-0>";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session";+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.dp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp"' \
	"User-Agent: TTA-RCS/2.4 SM-F711N/IMSroha-0.2.0 Device_Type/RCS_Android_Phone LGU" \
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
grep -q '^sip-in SUBSCRIBE tel:+821000000001' "$t/net.log" || bad "no anonymous fetch SUBSCRIBE"
grep -q 'event anonymous-fetch' "$t/net.log" || bad "the SUBSCRIBE is not anonymous (R9 6.5.1)"
grep -q 'event publish 600 chat' "$t/net.log" || bad "no PUBLISH of the chat capability"
grep -q 'event publish 0' "$t/net.log" || bad "no PUBLISH Expires 0 at SIGTERM"
grep -q 'Expires: 0' "$t/net.log" || bad "no de-registration at SIGTERM"
grep -q '^state registered' "$t/client.out" || grep -q 'registered as' "$t/rcs.err" || bad "never registered"
[ -s "$t/state/450069999999999/config.xml" ] || bad "no stored configuration"

# File transfer: advertised in PUBLISH and in the chat's SDP.
grep -q 'org.openmobilealliance:File-Transfer-HTTP' "$t/net.log" || bad "PUBLISH without File-Transfer-HTTP"
grep -q 'a=accept-wrapped-types:text/plain message/imdn+xml application/im-iscomposing+xml application/vnd.gsma.rcs-ft-http+xml|' \
	"$t/net.log" || bad "SDP without the file-info type"
# Receive: the file and its thumbnail (chunked) byte for byte, under the
# name's last component, Digest to our server, delivered at once.
dl="$t/dl/450069999999999"
cmp "$t/ft/rx1" "$dl/evil name.bin" || bad "the received file is not what the server had"
cmp "$t/ft/rx1t" "$dl/thumb-mtft1.png" || bad "the thumbnail is not what the server had"
[ "$(ls -A "$dl" | wc -l)" = 2 ] || bad "the download directory holds more than the file and thumbnail: $(ls -A "$dl")"
[ "$(find "$t" -name 'evil*' | wc -l)" = 1 ] || bad "a file name left the download directory"
grep -q '^request GET /content/rx1?t=x&s=40000 len 0 noauth' "$t/cs.log" || bad "no first GET of the file"
grep -q '^request GET /content/rx1?t=x&s=40000 len 0 auth' "$t/cs.log" || bad "the file's 401 was not answered"
grep -q '^event get rx1t' "$t/cs.log" || bad "no thumbnail download"
grep -q 'event imdn mtft1 delivered' "$t/net.log" || bad "no delivered IMDN for the file-info"
# Expired and too large: no request at all. Another host: its 401 gets no credentials.
! grep -q 'GET /content/gone\|GET /content/big' "$t/cs.log" || bad "fetched an expired or oversize file"
grep -q '^request GET /content/rx4 len 0 noauth' "$t/cs.log" || bad "no GET of the other host's file"
! grep -q '^request GET /content/rx4 len 0 auth' "$t/cs.log" || bad "credentials went to a URL that is not our server"
# Send: an empty POST, its 401 answered, the file in multipart with a tid;
# above MaxSizeFileTr to ftHTTPExtraCSURI; the server's file-info is what
# goes out in MSRP, byte for byte; nothing over MaxSizeExtraFileTr goes up.
[ "$(grep -c '^event empty-post /content/' "$t/cs.log")" = 1 ] || bad "not one empty POST to ftHTTPCSURI"
[ "$(grep -c '^event empty-post /large/' "$t/cs.log")" = 1 ] || bad "not one empty POST to ftHTTPExtraCSURI"
grep -Eq '^event upload /content/ 1 tid [0-9a-f-]{36} parts tid,File name small.bin ctype \S+ size 40000$' "$t/cs.log" ||
	bad "the small file's upload is not tid,File"
grep -Eq '^event upload /large/ 2 tid [0-9a-f-]{36} parts tid,File name large.bin ctype \S+ size 100000$' "$t/cs.log" ||
	bad "the large file did not go to the large-file server"
[ "$(grep -c '^event upload' "$t/cs.log")" = 2 ] || bad "not exactly two uploads"
! grep -q 'bad-auth\|bad-upload' "$t/cs.log" || bad "the content server refused a request"
cmp "$t/ft/small.bin" "$t/cs/up-1.bin" || bad "the uploaded small file differs"
cmp "$t/ft/large.bin" "$t/cs/up-2.bin" || bad "the uploaded large file differs"
cmp "$t/cs/up-1.xml" "$t/ft/mo-1.xml" || bad "the MSRP file-info is not the server's answer"
cmp "$t/cs/up-2.xml" "$t/ft/mo-2.xml" || bad "the second MSRP file-info is not the server's answer"
! grep -q 'ftSecretPw\|ftuser' "$t/rcs.err" || bad "the content server credentials are in the log"

# --- first activation with the OTP SMS, then a P-CSCF that refuses connections:
# the ACS is asked once and not again within ACS_MIN_INTERVAL ---
sed 's/@SIP_PORT@/15062/; s/@CS_PORT@/18446/' "$src/tests/rcs/acs.xml" > "$t/acs2.xml"
mkfifo "$t/acs2.in" "$t/acs2.out" "$t/rcs2.pipe" "$t/acs2.ev"
exec 6<>"$t/acs2.in"
python3 -I "$src/tests/rcs/fake-acs.py" --http-port 18081 --https-port 18444 --cert "$t/server.pem" \
	--key "$t/server.key" --xml "$t/acs2.xml" --scenario otp --log "$t/acs2.log" --events "$t/acs2.ev" <&6 > "$t/acs2.out" &
pids="$pids $!"
exec 7<"$t/acs2.out"
read -r _ <&7
conf '[rcs]' 'enable=true' "ca-file=$t/ca.pem" 'msisdn=+821099999999'
sed -i 's|18080|18081|; s|18443|18444|' "$t/imsroha.conf"
# "654321", UCS-2, application port 37273 (R9 6.3.1.1.2), as imsroha's PortPduReceived carries it.
otp=0040048121430008521111310000001306050491990000003600350034003300320031
IMSROHA_RCS_STATE="$t/state2" dbus-run-session -- sh -c '
	# Held open read-write so the daemon can open its end at once.
	exec 8<>"$2/rcs2.pipe"
	"$1" 2> "$2/rcs2.pipe" & d=$!
	if timeout 20 sh -c "read -r l < \"\$0\" && [ \"\$l\" = otp-cookie ]" "$2/acs2.ev"; then
		gdbus emit --session --object-path /codes/noa/IMSroha --signal codes.noa.IMSroha.PortPduReceived \
			"uint16 37273" "\"$3\"" > /dev/null || echo "gdbus emit failed" >&2
	fi
	timeout 30 sh -c "while IFS= read -r l; do printf \"%s\n\" \"\$l\" >> \"\$0\"; case \$l in *\"not asking it again\"*) exit 0;; esac; done; exit 1" \
		"$2/rcs2.err" < "$2/rcs2.pipe"; rc=$?
	kill -TERM $d 2>/dev/null; wait $d 2>/dev/null
	exit $rc' sh "$rcs" "$t" "$otp" || bad "OTP/unreachable P-CSCF: no back-off in time"
grep -q '^https /?OTP=654321' "$t/acs2.log" || bad "the OTP from the SMS did not reach the ACS"
grep -q 'msisdn=%2B821099999999&SMS_port=37273&token=' "$t/acs2.log" || bad "no non-PS request after the 511"
grep -q 'waiting-otp' "$t/rcs2.err" || bad "the state never said waiting-otp"
n2=$(grep -c '^connect' "$t/acs2.log" || true)
[ "$n2" = 3 ] || bad "the ACS was contacted $n2 times, not 3 (HTTP, HTTPS, OTP)"
grep -q 'P-CSCF is unreachable; asking the ACS again' "$t/rcs2.err" || bad "no return to the ACS after the P-CSCF failed"
echo "OTP flow: SMS -> OTP -> configuration; unreachable P-CSCF: the ACS asked $n2 times in all"

# --- 403 to REGISTER: back to the ACS once (which the floor holds back), then
# the stored configuration, a second 403, and nothing more (R9 A.5 b) ---
sed 's/@SIP_PORT@/15063/; s/@CS_PORT@/18446/' "$src/tests/rcs/acs.xml" > "$t/acs3.xml"
mkfifo "$t/acs3.in" "$t/acs3.out" "$t/net3.in" "$t/net3.out" "$t/rcs3.pipe"
exec 8<>"$t/acs3.in"
python3 -I "$src/tests/rcs/fake-acs.py" --http-port 18082 --https-port 18445 --cert "$t/server.pem" \
	--key "$t/server.key" --xml "$t/acs3.xml" --scenario netauth --log "$t/acs3.log" <&8 > "$t/acs3.out" &
pids="$pids $!"
exec 9<"$t/acs3.out"
read -r _ <&9
exec 6<>"$t/net3.in"
python3 -I "$src/tests/rcs/fake-pcscf.py" --sip-port 15063 --msrp-port 12856 --cert "$t/server.pem" \
	--key "$t/server.key" --log "$t/net3.log" --reg403 <&6 > "$t/net3.out" &
pids="$pids $!"
exec 7<"$t/net3.out"
read -r _ <&7
sed -i 's|18081|18082|; s|18444|18445|' "$t/imsroha.conf"
IMSROHA_RCS_STATE="$t/state3" dbus-run-session -- sh -c '
	exec 8<>"$2/rcs3.pipe"
	"$1" 2> "$2/rcs3.pipe" & d=$!
	timeout 30 sh -c "while IFS= read -r l; do printf \"%s\n\" \"\$l\" >> \"\$0\"; case \$l in *\"second 403\"*) exit 0;; esac; done; exit 1" \
		"$2/rcs3.err" < "$2/rcs3.pipe"; rc=$?
	kill -TERM $d 2>/dev/null; wait $d 2>/dev/null
	exit $rc' sh "$rcs" "$t" || bad "403: never got to the second 403"
n3=$(grep -c '^connect' "$t/acs3.log" || true)
[ "$n3" = 2 ] || bad "403: the ACS was contacted $n3 times, not 2 (HTTP, HTTPS)"
[ "$(grep -c 'event register-403' "$t/net3.log")" = 2 ] || bad "403: not exactly two 403s"
grep -q 'not asking it again' "$t/rcs3.err" || bad "403: the first 403 did not meet the floor"
echo "403 to REGISTER: two 403s, the ACS asked $n3 times in all, then nothing"

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

# Under -Db_sanitize the daemon's own reports end up in its stderr, not in an exit status.
for f in "$t"/*.err; do
	! grep -q 'Sanitizer\|runtime error' "$f" || bad "sanitizer report in $(basename "$f"): $(grep -m1 'Sanitizer\|runtime error' "$f")"
done

if [ $fail != 0 ]; then
	echo "--- imsroha-rcs"; cat "$t/rcs.err"
	echo "--- network"; cat "$t/net.log"
	echo "--- content server"; cat "$t/cs.log"
	echo "--- off2"; cat "$t/off2.err"
	echo "--- otp run"; cat "$t/rcs2.err" 2>/dev/null; cat "$t/acs2.log" 2>/dev/null
	echo "--- 403 run"; cat "$t/rcs3.err" 2>/dev/null
	exit 1
fi
echo "rcs-daemon: passed"
