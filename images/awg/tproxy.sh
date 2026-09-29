#!/bin/bash
# Called by awg-quick (PostUp/PostDown).
#  1) everything clients send into awg0 (IPv4 and IPv6) -> TPROXY -> sing-box (127.0.0.1 / [::1]:12345)
#     -> xray (127.0.0.1:10808), so AmneziaWG users get the same routing as Hiddify/Happ (RU direct, YouTube via MSK,
#     rest via exits). IPv6 must be captured too: otherwise it bypasses the VPN on dual-stack (mobile) networks;
#  2) clients can't reach each other or services on the server's tunnel address;
#  3) the Remnawave node API port 2222 is reachable only locally / from docker networks.
ACT=${1:-up}
NET4=10.66.66.0/24
NET6=fd66:66:66::/64
if [ "$ACT" = up ]; then
  for V in 4 6; do
    if [ $V = 4 ]; then T=iptables; NET=$NET4; LO=127.0.0.1; ANY=0.0.0.0/0; LOC=127.0.0.0/8
    else T=ip6tables; NET=$NET6; LO=::1; ANY=::/0; LOC=::1/128; fi
    ip -$V rule show | grep -q "fwmark 0x1 lookup 100" || ip -$V rule add fwmark 0x1 lookup 100
    ip -$V route replace local $ANY dev lo table 100
    $T -t mangle -N AWG_TP 2>/dev/null || $T -t mangle -F AWG_TP
    $T -t mangle -A AWG_TP -d $NET -j RETURN
    $T -t mangle -A AWG_TP -d $LOC -j RETURN
    $T -t mangle -A AWG_TP -p tcp -j TPROXY --on-ip $LO --on-port 12345 --tproxy-mark 0x1
    $T -t mangle -A AWG_TP -p udp -j TPROXY --on-ip $LO --on-port 12345 --tproxy-mark 0x1
    $T -t mangle -C PREROUTING -i awg0 -j AWG_TP 2>/dev/null || $T -t mangle -A PREROUTING -i awg0 -j AWG_TP
    # TPROXY-delivered packets pass the filter INPUT chain: host firewalls with policy DROP (ufw) would eat them.
    # The tunnel address itself (and the other clients) is off limits: ping only.
    $T -N AWG_IN 2>/dev/null || $T -F AWG_IN
    $T -A AWG_IN -d $NET -p $([ $V = 4 ] && echo icmp || echo ipv6-icmp) -j ACCEPT
    $T -A AWG_IN -d $NET -j DROP
    $T -A AWG_IN -j ACCEPT
    $T -D INPUT -i awg0 -j ACCEPT 2>/dev/null   # older versions accepted everything from awg0
    $T -C INPUT -i awg0 -j AWG_IN 2>/dev/null || $T -I INPUT -i awg0 -j AWG_IN
    $T -C FORWARD -i awg0 -o awg0 -j DROP 2>/dev/null || $T -I FORWARD -i awg0 -o awg0 -j DROP
  done
  for T in iptables ip6tables; do
    $T -D INPUT -p tcp --dport 2222 -j GEOVPN_NODE 2>/dev/null
    $T -F GEOVPN_NODE 2>/dev/null || $T -N GEOVPN_NODE
    if [ $T = iptables ]; then L="127.0.0.0/8 172.16.0.0/12"; else L="::1 fd00::/8"; fi
    for s in $L; do $T -A GEOVPN_NODE -s "$s" -j ACCEPT; done   # ACCEPT, not RETURN: host firewalls (ufw) drop the rest
    $T -A GEOVPN_NODE -j DROP
    $T -I INPUT -p tcp --dport 2222 -j GEOVPN_NODE
  done
else
  for V in 4 6; do
    T=$([ $V = 4 ] && echo iptables || echo ip6tables)
    $T -t mangle -D PREROUTING -i awg0 -j AWG_TP 2>/dev/null || true
    $T -D INPUT -i awg0 -j AWG_IN 2>/dev/null || true
    $T -D INPUT -i awg0 -j ACCEPT 2>/dev/null || true
    $T -D FORWARD -i awg0 -o awg0 -j DROP 2>/dev/null || true
    $T -F AWG_IN 2>/dev/null; $T -X AWG_IN 2>/dev/null
    $T -t mangle -F AWG_TP 2>/dev/null || true
    $T -t mangle -X AWG_TP 2>/dev/null || true
    ip -$V rule del fwmark 0x1 lookup 100 2>/dev/null || true
    ip -$V route flush table 100 2>/dev/null || true
  done
fi
exit 0
