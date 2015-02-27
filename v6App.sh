#!/bin/sh
log() {
	MSG=$1
	logger -s "$MSG"
}
# DISCOVER_OUT=`cat /home/administrator/v6App/v6App.out`
log "Starting IPv6 Discovery"
OUT="/home/administrator/v6App/v6App.out"
RESULTS="/var/www/ipv6discovery/results.txt"
DISCOVER_OUT=`sh /home/administrator/v6App/run-ubuntu.sh > $OUT`
NOW=$(date +"%m-%d-%Y %T")

log "Processing discovered network data"
while read line
do
	# echo $line | awk -F"IP[" '{print $1}'
	FOUR=`cat $OUT | awk -FIP '{print $2}'|awk -F, '{print $1}'|grep -v ^$|grep -v ^v6|grep -c "\."`
	SIX=`cat $OUT | awk -FIP '{print $2}'|awk -F, '{print $1}'|grep -v ^$|grep -v ^v6|grep -c ":"`
	TOTAL=`cat $OUT | awk -FIP '{print $2}'|awk -F, '{print $1}'|grep -v ^$|grep -v ^v6|grep -c ^`
done < $OUT
log "Writing summary results of IPv6 Discovery"
echo "$NOW, TOTAL=$TOTAL, IPv6=$SIX, IPv4=$FOUR" >> $RESULTS
log "$NOW, TOTAL=$TOTAL, IPv6=$SIX, IPv4=$FOUR"
log "End IPv6 Discovery"
