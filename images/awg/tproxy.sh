#!/bin/bash
# Called by awg-quick (PostUp/PostDown).
#  1) everything clients send into awg0 -> TPROXY -> sing-box (127.0.0.1:12345) -> xray (127.0.0.1:10808),
#     so AmneziaWG users get the same routing as Hiddify/Happ (RU direct, YouTube via MSK, rest via exits);
#  2) the Remnawave node API port 2222 is reachable only locally / from docker networks.
ACT=${1:-up}
if [ "$ACT" = up ]; then
  ip rule add fwmark 0x1 lookup 100 2>/dev/null || true
  ip route replace local 0.0.0.0/0 dev lo table 100
  iptables -t mangle -N AWG_TP 2>/dev/null || iptables -t mangle -F AWG_TP
  iptables -t mangle -A AWG_TP -d 10.66.66.0/24 -j RETURN
  iptables -t mangle -A AWG_TP -d 127.0.0.0/8 -j RETURN
  iptables -t mangle -A AWG_TP -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port 12345 --tproxy-mark 0x1
  iptables -t mangle -A AWG_TP -p udp -j TPROXY --on-ip 127.0.0.1 --on-port 12345 --tproxy-mark 0x1
  iptables -t mangle -C PREROUTING -i awg0 -j AWG_TP 2>/dev/null || iptables -t mangle -A PREROUTING -i awg0 -j AWG_TP
  # TPROXY-delivered packets pass the filter INPUT chain: host firewalls with policy DROP (ufw) would eat them
  iptables -C INPUT -i awg0 -j ACCEPT 2>/dev/null || iptables -I INPUT -i awg0 -j ACCEPT
  for T in iptables ip6tables; do
    $T -D INPUT -p tcp --dport 2222 -j GEOVPN_NODE 2>/dev/null
    $T -F GEOVPN_NODE 2>/dev/null || $T -N GEOVPN_NODE
    if [ $T = iptables ]; then L="127.0.0.0/8 172.16.0.0/12"; else L="::1 fd00::/8"; fi
    for s in $L; do $T -A GEOVPN_NODE -s "$s" -j ACCEPT; done   # ACCEPT, not RETURN: host firewalls (ufw) drop the rest
    $T -A GEOVPN_NODE -j DROP
    $T -I INPUT -p tcp --dport 2222 -j GEOVPN_NODE
  done
else
  iptables -t mangle -D PREROUTING -i awg0 -j AWG_TP 2>/dev/null || true
  iptables -D INPUT -i awg0 -j ACCEPT 2>/dev/null || true
  iptables -t mangle -F AWG_TP 2>/dev/null || true
  iptables -t mangle -X AWG_TP 2>/dev/null || true
  ip rule del fwmark 0x1 lookup 100 2>/dev/null || true
  ip route flush table 100 2>/dev/null || true
fi
exit 0
