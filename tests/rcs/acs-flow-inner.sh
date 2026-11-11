#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Runs inside acs-flow.sh's namespace.
set -eu
bin=$1 src=$2
ip link set lo up
t=$(mktemp -d)
trap 'kill $srv 2>/dev/null || true; rm -rf "$t"' EXIT
. "$src/tests/rcs/certs.sh"
make_certs "$t"

conf() { # scenario
	cat > "$t/imsroha.conf" <<EOC
[device]
model=SM-F711N
operator=LGU
vendor=SEC
[rcs]
enable=true
ca-file=$t/ca.pem
msisdn=+821099999999
[carrier]
rcs-acs-url=http://localhost:18080
rcs-acs-https-url=https://localhost:18443
EOC
}

start() { # scenario
	rm -rf "$t/state"; : > "$t/log"
	mkfifo "$t/ready.$1"
	python3 -I "$src/tests/rcs/fake-acs.py" --http-port 18080 --https-port 18443 \
		--cert "$t/server.pem" --key "$t/server.key" --xml "$src/tests/rcs/acs.xml" \
		--scenario "$1" --log "$t/log" < "$t/fifo.in.$1" > "$t/ready.$1" &
	srv=$!
	read -r line < "$t/ready.$1"
}

stop() { kill $srv; wait $srv 2>/dev/null || true; }

export IMSROHA_CONF="$t/imsroha.conf" IMSROHA_CARRIERS="$src/data/carriers.conf" IMSROHA_RCS_STATE="$t/state"
conf
fail=0
check() { # what pattern file
	if ! grep -q -- "$2" "$3"; then echo "FAIL $1: no '$2' in $3:"; cat "$3"; fail=1; fi
}
count() { grep -c "^connect" "$t/log" || true; }

for s in netauth otp minus1 zero disable 403 503; do
	mkfifo "$t/fifo.in.$s"
	exec 3<>"$t/fifo.in.$s"
	start $s
	case $s in
	disable)
		"$bin" run > "$t/out.0"
		: > "$t/log"
		"$bin" disable > "$t/out" ;;
	*)	"$bin" run > "$t/out" ;;
	esac
	echo "--- $s"; cat "$t/out"
	case $s in
	netauth)
		check $s "outcome active version 12 validity 2592000 token testToken" "$t/out"
		check $s "pcscf localhost:@SIP_PORT@" "$t/out"
		check $s "Cookie: up10=netauth" "$t/log"
		check $s "^https /?vers=0&rcs_state=0&IMSI=450069999999999&IMEI=359999999999999&" "$t/log"
		# A refresh with the stored version: VERS only, configuration kept.
		"$bin" run > "$t/out2"; cat "$t/out2"
		check $s "outcome active version 12" "$t/out2"
		check $s "config.xml stored" "$t/out2"
		check $s "^https /?vers=12&rcs_state=12" "$t/log" ;;
	otp)
		check $s "otp asked" "$t/out"
		check $s "outcome active version 12" "$t/out"
		check $s "^https /?OTP=654321" "$t/log"
		check $s "Cookie: up10=otpcookie" "$t/log"
		check $s "msisdn=%2B821099999999&SMS_port=37273&token=" "$t/log" ;;
	minus1)
		check $s "outcome stopped version -1 validity -1 token - permanent 1" "$t/out"
		n=$(count)
		"$bin" run > "$t/out2"; cat "$t/out2"
		if [ "$(count)" != "$n" ]; then echo "FAIL minus1: asked the ACS again after -1"; fail=1; fi
		check $s "outcome stopped" "$t/out2" ;;
	zero)
		check $s "outcome none version 0 validity 0" "$t/out"
		check $s "config.xml absent" "$t/out" ;;
	disable)
		check $s "contacted 1" "$t/out.0"
		check $s "rcs_state=-4" "$t/log"
		check $s "disable-sent 1" "$t/out" ;;
	403)
		check $s "outcome none version 0" "$t/out"
		check $s "next-run next-start" "$t/out" ;;
	503)
		check $s "outcome none" "$t/out"
		check $s "next-run set" "$t/out" ;;
	esac
	exec 3>&-
	stop
done
[ $fail = 0 ] && echo "acs-flow: all scenarios passed"
exit $fail
