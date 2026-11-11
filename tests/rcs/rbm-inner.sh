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
fail=0
bad() { echo "FAIL: $*"; fail=1; }
rbm="$src/tests/rcs/rbm"

# A rich card of about 60 KB: pager mode over more than one SIP read.
python3 -I - "$t/big.json" <<'PY'
import json, sys
d = {"message": {"generalPurposeCard": {"content": {"title": "큰 카드", "description": "가나다라마바사" * 3000}}}}
open(sys.argv[1], 'w', encoding='utf-8').write(json.dumps(d, ensure_ascii=False))
PY
export RBM_BIG="$t/big.json"

# The configuration with R9 B.1.2's Chatbot characteristic (the botinfo root on loopback).
chatbot='<characteristic type="Chatbot"><parm name="ChatbotDirectory" value="botplatform.loopback.example"/><parm name="BotinfoFQDNRoot" value="localhost:18447"/><parm name="PrivacyDisable" value="1"/><parm name="ChatbotMsgTech" value="2"/></characteristic>'
sed "s/@SIP_PORT@/15071/; s/@CS_PORT@/18446/; s|<characteristic type=\"MESSAGING\">|&$chatbot|" \
	"$src/tests/rcs/acs.xml" > "$t/acs.xml"
grep -q 'BotinfoFQDNRoot' "$t/acs.xml" || { echo "FAIL: no Chatbot characteristic in the test configuration"; exit 1; }
sed "s/@SIP_PORT@/15072/; s/@CS_PORT@/18446/; s|<characteristic type=\"MESSAGING\">|&$chatbot|" \
	"$src/tests/rcs/acs.xml" > "$t/acs-off.xml"

conf() { # acs-http-port acs-https-port rcs-section-lines...
	{
		printf '[device]\nmodel=SM-F711N\noperator=LGU\nvendor=SEC\n'
		printf '[carrier]\nrcs-acs-url=http://localhost:%s\nrcs-acs-https-url=https://localhost:%s\n' "$1" "$2"
		shift 2
		printf '[rcs]\nenable=true\nca-file=%s\nmsisdn=+821099999999\n' "$t/ca.pem"
		for l in "$@"; do printf '%s\n' "$l"; done
	} > "$t/imsroha.conf"
}
export IMSROHA_CONF="$t/imsroha.conf" IMSROHA_CARRIERS="$src/data/carriers.conf"
export IMSROHA_RCS_IMSI=450069999999999 IMSROHA_RCS_IMEI=359999999999999 IMSROHA_RCS_BUS=session RBM_DIR="$rbm"
unset DBUS_SESSION_BUS_ADDRESS || true

# A SIP message block of the network's log: the one whose first line matches $2 and holds $3.
block() { # log first-line-pattern must-contain
	awk -v first="$2" -v want="$3" '
		/^sip-in / { if (b != "" && b ~ want) printf "%s", b; b = ""; keep = ($0 ~ first) }
		/^(sip-out|msrp-in|event|connect)/ { if (b != "" && b ~ want) printf "%s", b; b = ""; keep = 0 }
		keep { b = b $0 "\n" }
		END { if (b != "" && b ~ want) printf "%s", b }' "$1"
}

# ---- on ----
mkfifo "$t/acs.in" "$t/acs.out" "$t/net.in" "$t/net.out" "$t/bi.in" "$t/bi.out"
exec 3<>"$t/acs.in" 4<>"$t/net.in" 6<>"$t/bi.in"
python3 -I "$src/tests/rcs/fake-acs.py" --http-port 18090 --https-port 18453 --cert "$t/server.pem" \
	--key "$t/server.key" --xml "$t/acs.xml" --scenario netauth --log "$t/acs.log" <&3 > "$t/acs.out" &
pids="$pids $!"
python3 -I "$src/tests/rcs/fake-pcscf.py" --sip-port 15071 --msrp-port 12865 --cert "$t/server.pem" \
	--key "$t/server.key" --log "$t/net.log" --rbm on --rbm-dir "$rbm" --rbm-big "$t/big.json" <&4 > "$t/net.out" &
pids="$pids $!"
python3 -I "$src/tests/rcs/fake-botinfo.py" --port 18447 --cert "$t/server.pem" --key "$t/server.key" \
	--log "$t/bi.log" --dir "$rbm" <&6 > "$t/bi.out" &
pids="$pids $!"
exec 5<"$t/net.out" 7<"$t/acs.out" 8<"$t/bi.out"
read -r _ <&7
read -r _ <&5
read -r _ <&8
conf 18090 18453
IMSROHA_RCS_STATE="$t/state" dbus-run-session -- sh -c '
	"$1" 2> "$2/rcs.err" & d=$!
	"$3" > "$2/client.out" 2>&1; c=$?
	timeout 20 sh -c "read -r line <&5 && echo \"network: \$line\"" > "$2/net.result" || true
	kill -TERM $d; wait $d
	exit $c' sh "$rcs" "$t" "$client" || bad "client failed"
cat "$t/client.out"
cat "$t/net.result"
grep -q "network: done" "$t/net.result" || bad "the network did not see everything it waits for"

# Advertised: REGISTER (and so our OPTIONS answer), PUBLISH.
tags='+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session";+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.dp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot.sa,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.xbotmessage";+g.gsma.rcs.botversion="#=1"'
block "$t/net.log" '^sip-in REGISTER' 'Expires: 600000' | grep -qF -- "$tags" || bad "REGISTER Contact lacks the chatbot tags"
block "$t/net.log" '^sip-in SIP/2.0 200' 'Call-ID: opt-1' | grep -qF -- "$tags" || bad "the OPTIONS answer lacks the chatbot tags"
grep -q 'event publish 600 tuples rcs.chatbot< rcs.chatbot.sa< rcs.chatbot.xbotmessage<$' "$t/net.log" ||
	bad "PUBLISH without the three chatbot tuples"
# Our chat to the bot: the bot's URI, its IARI and botversion, what it may send us.
inv=$(block "$t/net.log" '^sip-in INVITE sip:bot@botplatform.loopback.example SIP/2.0' 'Content-Type')
printf '%s\n' "$inv" | grep -qF 'Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session";+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot";+g.gsma.rcs.botversion="#=1"' ||
	bad "the INVITE to the bot lacks its Accept-Contact"
printf '%s\n' "$inv" | grep -qF 'To: <sip:bot@botplatform.loopback.example>' || bad "the INVITE is not to the bot's URI"
printf '%s\n' "$inv" | grep -qF 'a=accept-wrapped-types:text/plain message/imdn+xml application/im-iscomposing+xml application/vnd.gsma.rcs-ft-http+xml multipart/mixed application/vnd.gsma.botmessage.v1.0+json application/vnd.gsma.botsuggestion.v1.0+json application/vnd.gsma.xbotmessage.v1.0+json application/vnd.gsma.openrichcard.v1.0+json|' ||
	bad "the bot session's SDP lacks the bot content types"
block "$t/net.log" '^sip-in SIP/2.0 200' 'Call-ID: bot2-1' | grep -qF 'multipart/mixed application/vnd.gsma.botmessage.v1.0+json' ||
	bad "the answer to the bot's INVITE lacks the bot content types"
# Large message mode: answered recvonly; the network's BYE taken.
large=$(block "$t/net.log" '^sip-in SIP/2.0 200' 'Call-ID: large-1')
printf '%s\n' "$large" | grep -q 'a=recvonly' || bad "the large message session is not recvonly"
printf '%s\n' "$large" | grep -qF 'multipart/mixed application/vnd.gsma.botmessage.v1.0+json application/vnd.gsma.botsuggestion.v1.0+json application/vnd.gsma.xbotmessage.v1.0+json' ||
	bad "the large message session's SDP lacks the bot content types"
grep -q 'event resp large-1 BYE 200' "$t/net.log" || bad "the large message session's BYE was not answered"
# The network check: 200 and nothing else; an xbotmessage v1.3: 606.
grep -q 'event resp netcheck-1 MESSAGE 200' "$t/net.log" || bad "the network check did not get its 200"
! grep -q 'event imdn 30ef1b07' "$t/net.log" || bad "an IMDN went back for the network check"
grep -q 'event resp a2p-1 MESSAGE 200' "$t/net.log" || bad "the pager-mode A2P message did not get its 200"
grep -q 'event resp a2p-big MESSAGE 200' "$t/net.log" || bad "the large pager-mode message did not get its 200"
grep -q 'event resp a2p-x13 MESSAGE 606' "$t/net.log" || bad "the xbotmessage v1.3 did not get 606"
# A2P IMDNs go to the tel URI (pager mode: SIP MESSAGE).
grep -q 'event imdn rbm6 delivered tel:+8215880000' "$t/net.log" || bad "no delivered IMDN to tel:+8215880000"
grep -q 'event imdn rbm6 displayed tel:+8215880000' "$t/net.log" || bad "no displayed IMDN to tel:+8215880000"
grep -q 'event imdn rbm7 delivered tel:+8215880000' "$t/net.log" || bad "no delivered IMDN for the large message"
# Bot messages in the sessions are delivered, in the session.
for id in rbm1 rbm2 rbm3 rbm4 rbm5; do
	grep -q "event imdn $id delivered msrp" "$t/net.log" || bad "no delivered IMDN for $id"
done
grep -q 'event suggestion-response application/vnd.gsma.botsuggestion.response.v1.0+json body ok' "$t/net.log" ||
	bad "the suggestion response is not the app's JSON as application/vnd.gsma.botsuggestion.response.v1.0+json"
# botinfo: stock's query; cached for max-age; revalidated with the ETag; unknown asked once; no tel: query.
grep -q '^request /bot?id=sip%3Abot%40botplatform.loopback.example&hl=ko&ho=450006&v=3 inm None ua TTA-RCS/2.4 SM-F711N/' "$t/bi.log" ||
	bad "the botinfo query is not stock's"
[ "$(grep -c 'id=sip%3Abot%40' "$t/bi.log")" = 1 ] || bad "a fresh botinfo was asked again"
[ "$(grep -c 'id=sip%3Abot2%40' "$t/bi.log")" = 2 ] || bad "botinfo with no-cache was not asked twice"
grep -q 'id=sip%3Abot2%40.* inm "b2"' "$t/bi.log" || bad "no If-None-Match for the second botinfo"
[ "$(grep -c 'id=sip%3Anobody%40' "$t/bi.log")" = 1 ] || bad "the unknown bot was not asked once"
! grep -q 'tel' "$t/bi.log" || bad "a botinfo query for a tel URI"
grep -q '^state\|registered' "$t/rcs.err" || bad "never registered"
grep -q 'chatbots: session, standalone, xbotmessage, botinfo at localhost:18447' "$t/rcs.err" || bad "the daemon did not log the chatbot configuration"

# ---- [rcs] chatbot=false: nothing advertised, nothing taken ----
mkfifo "$t/acs2.in" "$t/acs2.out" "$t/net2.in" "$t/net2.out"
exec 3<>"$t/acs2.in" 4<>"$t/net2.in"
python3 -I "$src/tests/rcs/fake-acs.py" --http-port 18091 --https-port 18454 --cert "$t/server.pem" \
	--key "$t/server.key" --xml "$t/acs-off.xml" --scenario netauth --log "$t/acs2.log" <&3 > "$t/acs2.out" &
pids="$pids $!"
python3 -I "$src/tests/rcs/fake-pcscf.py" --sip-port 15072 --msrp-port 12866 --cert "$t/server.pem" \
	--key "$t/server.key" --log "$t/net2.log" --rbm off --rbm-dir "$rbm" <&4 > "$t/net2.out" &
pids="$pids $!"
exec 5<"$t/net2.out" 7<"$t/acs2.out"
read -r _ <&7
read -r _ <&5
conf 18091 18454 'chatbot=false'
IMSROHA_RCS_STATE="$t/state2" dbus-run-session -- sh -c '
	"$1" 2> "$2/rcs2.err" & d=$!
	"$3" off > "$2/client2.out" 2>&1; c=$?
	timeout 20 sh -c "read -r line <&5 && echo \"network: \$line\"" > "$2/net2.result" || true
	kill -TERM $d; wait $d
	exit $c' sh "$rcs" "$t" "$client" || bad "off: client failed"
cat "$t/client2.out"
cat "$t/net2.result"
grep -q "network: done" "$t/net2.result" || bad "off: the network did not see everything it waits for"
reg=$(block "$t/net2.log" '^sip-in REGISTER' 'Expires: 600000')
printf '%s\n' "$reg" | grep -q 'Contact: ' || bad "off: no REGISTER"
! printf '%s\n' "$reg" | grep -q 'chatbot\|botversion\|xbotmessage' || bad "off: the REGISTER advertises chatbots"
grep -q 'event publish 600 tuples none' "$t/net2.log" || bad "off: PUBLISH with chatbot tuples"
grep -q 'event resp off-msg MESSAGE 606' "$t/net2.log" || bad "off: the chatbot's MESSAGE was not refused"
grep -q 'event resp off-inv INVITE 606' "$t/net2.log" || bad "off: the chatbot's INVITE was not refused"
grep -q 'event resp off-person MESSAGE 200' "$t/net2.log" || bad "off: a person's MESSAGE was refused"
grep -q 'chatbots: off (\[rcs\] chatbot=false)' "$t/rcs2.err" || bad "off: the daemon did not say chatbots are off"

for f in "$t"/*.err; do
	! grep -q 'Sanitizer\|runtime error' "$f" || bad "sanitizer report in $(basename "$f"): $(grep -m1 'Sanitizer\|runtime error' "$f")"
done
if [ $fail != 0 ]; then
	echo "--- imsroha-rcs"; cat "$t/rcs.err"
	echo "--- network"; cat "$t/net.log"
	echo "--- botinfo"; cat "$t/bi.log"
	echo "--- off: imsroha-rcs"; cat "$t/rcs2.err"
	echo "--- off: network"; cat "$t/net2.log"
	exit 1
fi
echo "rcs-rbm: passed"
