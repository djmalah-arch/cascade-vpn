#!/bin/bash
# Queues the first packets of this server's own outgoing IPv4 TCP/443 connections to nfqws.
# nfqws only touches connections whose TLS SNI is in the hostlist (YouTube by default); everything else passes as is.
# Strategy / hostlist can be changed in ./data/zapret (strategy, hostlist.txt); find a working strategy with:
#   docker exec -it geovpn-zapret bash -c 'cd /opt/zapret && ./blockcheck.sh'
CFG=/opt/zapret/config.d
mkdir -p $CFG
[ -s $CFG/hostlist.txt ] || printf '%s\n' youtube.com googlevideo.com ytimg.com ggpht.com youtu.be \
  youtubei.googleapis.com youtube-nocookie.com yt3.googleusercontent.com > $CFG/hostlist.txt
[ -s $CFG/strategy ] || echo "--dpi-desync=fake --dpi-desync-fooling=badseq --dpi-desync-fake-tls=0x00000000" > $CFG/strategy
MARK=0x40000000
cleanup() { nft delete table inet geovpn_zapret 2>/dev/null; }
cleanup
nft -f - <<EOF
table inet geovpn_zapret {
  chain post {
    type filter hook postrouting priority 101; policy accept;
    meta nfproto ipv4 tcp dport 443 ct original packets 1-9 meta mark & $MARK == 0 queue num 200 bypass
  }
}
EOF
trap 'cleanup; kill $PID 2>/dev/null; exit 0' TERM INT
echo "zapret: strategy: $(cat $CFG/strategy)"
/opt/zapret/nfq/nfqws --qnum=200 --dpi-desync-fwmark=$MARK --filter-tcp=443 $(cat $CFG/strategy) --hostlist=$CFG/hostlist.txt &
PID=$!
wait $PID
cleanup
exit 1
