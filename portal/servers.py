"""GeoVPN portal: exit servers management (/admin/servers).

The portal owns the MSK xray profile: it is generated from db["exits"] (priority, enabled, keys).
A watchdog probes every exit (via per-exit local inbounds on MSK) and rebuilds the chain
primary -> reserve 1 -> reserve 2 ... when availability changes.
"""
import datetime as dt, json, os, re, secrets, socket, threading, time, traceback
from concurrent.futures import ThreadPoolExecutor

import app as C

MSK_DOMAIN = C.HOST
CERT = f"/var/lib/remnawave/configs/xray/ssl/{MSK_DOMAIN}"   # Caddy's Let's Encrypt cert, mounted into the node
SNI_CHOICES = ["www.samsung.com", "www.asus.com", "dl.google.com", "www.microsoft.com", "www.apple.com", "www.booking.com"]
PROBE_EVERY = 30
FAILS_TO_DOWN, OKS_TO_UP = 2, 2

PORTAL_KEY = C.P("ssh/geovpn_portal", "/root/.ssh/geovpn_portal")  # restricted key: only updates MSK address in exits' firewall

# the portal key in exits' authorized_keys is forced to run this: it can only set MSK's address in the fw container
# Every fw container we install carries the label geovpn.msk=<this MSK's key id>: one exit can host nodes of several entry
# servers (or two of ours), each MSK's key updates exactly its own firewalls.
def msk_id():
    import hashlib
    return hashlib.sha256(portal_pubkey().split()[1].encode()).hexdigest()[:12]


def fw_cmd():
    return (f"for c in $(docker ps -q --filter label=geovpn.msk={msk_id()}); do "
            "docker exec -e SSH_ORIGINAL_COMMAND $c /conf/fw.sh set || exit 1; done")

STATUS = {}          # id -> {"ok","ms","ip","v4","v6","ts"}
COUNTERS = {}        # id -> {"fail": n, "ok": n, "up": bool}
JOBS = {}            # job id -> {"title","log":[],"done","ok","started"}
APPLY_LOCK = threading.Lock()


# ---------------------------------------------------------------- state / seed
def state():
    return json.load(open(C.STATE))


def seed(db):
    """First start: no exit servers yet (they are added on /admin/servers)."""
    if "exits" in db:
        return False
    db["exits"] = {}
    db["balancer"] = {"plan": None, "events": []}
    return True


def msk_addrs(db):
    m = db.get("msk") or {}
    if m.get("v4"):
        return m["v4"], m.get("v6", "")
    return detect_msk_addrs()


def detect_msk_addrs():
    """Public IPv4/IPv6 of MSK itself (portal runs on MSK); docker/private/ULA addresses are ignored."""
    import ipaddress
    found = {4: "", 6: ""}
    for fam in (4, 6):
        _, out = C.sh(f"ip -o -{fam} addr show scope global")
        for line in (out or "").splitlines():
            f = line.split()
            if len(f) < 4 or f[1].startswith(("docker", "br-", "veth", "awg", "amn", "lo")):
                continue
            ip = f[3].split("/")[0]
            try:
                if ipaddress.ip_address(ip).is_global:
                    found[fam] = ip
                    break
            except ValueError:
                pass
    return found[4], found[6]


def portal_pubkey():
    import os
    if not os.path.exists(PORTAL_KEY):
        os.makedirs(os.path.dirname(PORTAL_KEY), mode=0o700, exist_ok=True)
        C.sh(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "geovpn-portal-fw", "-f", PORTAL_KEY])
    return open(PORTAL_KEY + ".pub").read().strip()


def install_fw_key(c):
    """On an exit (open paramiko session as root): add the restricted portal key (runs fw_cmd only).
    Only this MSK's own key line is replaced: another entry server may have its own node on the same exit."""
    key = portal_pubkey()
    line = (f'command="{fw_cmd()}",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ' + key)
    _, o, _ = c.exec_command("mkdir -p /root/.ssh && touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"
                             f" && sed -i '\\#{key.split()[1]}#d' /root/.ssh/authorized_keys"
                             f" && echo '{line}' >> /root/.ssh/authorized_keys && echo ok", timeout=20)
    return o.read().decode().strip() == "ok"


BACKUP_KEY = C.P("ssh/geovpn_backup", "/root/.ssh/geovpn_backup")  # restricted key: can only store an MSK backup on an exit


def backup_pubkey():
    if not os.path.exists(BACKUP_KEY):
        os.makedirs(os.path.dirname(BACKUP_KEY), mode=0o700, exist_ok=True)
        C.sh(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "geovpn-portal-backup", "-f", BACKUP_KEY])
    return open(BACKUP_KEY + ".pub").read().strip()


# Host settings of an exit, outside the node's docker (safe to re-run, doesn't touch other VPNs on the server):
#  - fail2ban for SSH: every server gets thousands of password guesses a day;
#  - tcp_mtu_probing: path MTU MSK <-> exits is 1450, PMTU black holes must not stall connections;
#  - receiver of MSK backups (the portal copies its daily backup to the lowest-priority exit).
HOST_EXTRAS = r"""
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1
touch /etc/sysctl.d/99-geovpn.conf
grep -q tcp_mtu_probing /etc/sysctl.d/99-geovpn.conf || echo "net.ipv4.tcp_mtu_probing = 1" >> /etc/sysctl.d/99-geovpn.conf
sysctl -q -w net.ipv4.tcp_mtu_probing=1 && echo "mtu probing: on"
command -v fail2ban-client >/dev/null || { apt-get update -qq && apt-get install -y -qq fail2ban python3-systemd; } >/dev/null 2>&1
if command -v fail2ban-client >/dev/null; then
  mkdir -p /etc/fail2ban/jail.d
  cat > /etc/fail2ban/jail.d/geovpn.local <<'X'
# GeoVPN: SSH brute force. 5 wrong passwords in 10 min -> ban 1 h, repeat offenders up to a week. MSK is never banned.
[sshd]
enabled = true
backend = systemd
journalmatch = _COMM=sshd + _COMM=sshd-session
maxretry = 5
findtime = 10m
bantime = 1h
bantime.increment = true
bantime.maxtime = 1w
ignoreip = 127.0.0.1/8 ::1 __MSK4__ __MSK6__
X
  systemctl enable -q fail2ban 2>/dev/null; systemctl restart fail2ban && sleep 2 && fail2ban-client status sshd >/dev/null && echo "fail2ban: on"
else
  echo "fail2ban: не установлен (нет apt?)"
fi
cat > /usr/local/sbin/geovpn-backup-recv <<'X'
#!/bin/bash
# Forced command of the GeoVPN portal backup key (authorized_keys): only stores an MSK backup sent on stdin.
d=/root/geovpn-backups
n=${SSH_ORIGINAL_COMMAND#put }
[[ $SSH_ORIGINAL_COMMAND == "put "* && $n =~ ^msk-[0-9]{8}-[0-9]{4}\.tar\.gz$ ]] || { echo denied; exit 1; }
mkdir -p -m 700 $d
if head -c 512M > "$d/.$n.part" && [ -s "$d/.$n.part" ]; then mv "$d/.$n.part" "$d/$n"; chmod 600 "$d/$n"
else rm -f "$d/.$n.part"; echo failed; exit 1; fi
ls -1t $d/msk-*.tar.gz | tail -n +31 | xargs -r rm -f
echo "ok $(du -h "$d/$n" | cut -f1)"
X
chmod 755 /usr/local/sbin/geovpn-backup-recv
mkdir -p /root/.ssh && touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
sed -i '\#__BKEY__#d' /root/.ssh/authorized_keys
echo 'command="/usr/local/sbin/geovpn-backup-recv",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty __BKEYLINE__' >> /root/.ssh/authorized_keys
echo "backup receiver: on"
"""


def host_extras(c, db, log=print):
    """Run HOST_EXTRAS on an exit (open paramiko session as root). Failures here don't break the exit itself."""
    v4, v6 = msk_addrs(db)
    key = backup_pubkey()
    script = (HOST_EXTRAS.replace("__MSK4__", v4 or "").replace("__MSK6__", v6 or "")
              .replace("__BKEY__", key.split()[1]).replace("__BKEYLINE__", key))
    return ssh_run(c, script, log, timeout=600)


def push_msk_addrs(db, v4, v6, log=print):
    """Tell every exit's firewall the (new) MSK address, via the restricted key (IPv6 first: exits' IPv4 is often blocked)."""
    import paramiko
    res = {}
    for eid, e in exits_sorted(db):
        ok = False
        for host in [h for h in (e.get("ip6"), e.get("ip4")) if h]:
            try:
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect(host, username="root", key_filename=PORTAL_KEY, timeout=10, allow_agent=False, look_for_keys=False)
                _, o, _ = c.exec_command(f"set-msk {v4} {v6 or '-'}", timeout=30)
                out = o.read().decode().strip()
                c.close()
                if out.startswith("ok"):
                    ok = True
                    break
                log(f"  {e['name']} ({host}): {out}")
            except Exception as ex:
                log(f"  {e['name']} ({host}): {ex}")
        res[eid] = ok
        log(f"{e['name']}: {'адрес MSK обновлён' if ok else 'НЕ обновлён'}")
    return res


def check_msk_ip(db):
    """Watchdog: MSK's public IP changed -> push it to all exits' firewalls, remember, warn about DNS."""
    d4, d6 = detect_msk_addrs()
    s4, s6 = msk_addrs(db)
    if not d4 or (d4 == s4 and (d6 or s6) == s6):
        return False
    res = push_msk_addrs(db, d4, d6)
    db["msk"] = {"v4": d4, "v6": d6 or s6}
    bad = [db["exits"][i]["name"] for i, ok in res.items() if not ok]
    event(db, f"Сменился IP MSK: {s4} → {d4}. Файрволы выходов обновлены"
              + (f", кроме: {', '.join(bad)}" if bad else "") + ". Смените A-запись geo-msk в DNS!")
    return True


def dns_a(name):
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(name, 443, socket.AF_INET)})
    except OSError:
        return []


DNS_CACHE = {}
HOST_RX = re.compile(r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}")
COMMON_LABELS = ("exit", "vpn", "node", "srv", "server", "connect", "proxy", "de", "nl", "fi", "at", "us")


def norm_host(h):
    h = (h or "").strip().lower().rstrip(".")
    return h if HOST_RX.fullmatch(h) else ""


def resolve(name, ttl=300):
    """A and AAAA records of a hostname -> (v4 list, v6 list), cached for a few minutes."""
    hit = DNS_CACHE.get(name)
    if hit and hit[0] > time.time():
        return hit[1]
    res = []
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            res.append(sorted({a[4][0] for a in socket.getaddrinfo(name, None, fam, socket.SOCK_STREAM)}))
        except OSError:
            res.append([])
    DNS_CACHE[name] = (time.time() + ttl, tuple(res))
    return tuple(res)


def remember_host(db, host):
    """Hostnames ever used for exits: candidates for "which domain points here" after a server is deleted."""
    if host:
        kh = db.setdefault("known_hosts", [])
        if host not in kh:
            kh.append(host)
            del kh[:-50]


def host_candidates(db):
    """DNS has no "names pointing to this IP" lookup: guess within the zones we know (our own hostnames,
    their numbered siblings like geo-srv01 -> geo-srv02..20, and a few typical labels)."""
    known = {h for h in [norm_host(MSK_DOMAIN)] + [norm_host(e.get("host")) for e in db.get("exits", {}).values()]
             + [norm_host(h) for h in db.get("known_hosts", [])] if h}
    cands = set(known)
    for h in known:
        label, _, zone = h.partition(".")
        if "." not in zone:
            continue
        m = re.fullmatch(r"(.*?)(\d+)", label)
        if m:
            cands |= {f"{m.group(1)}{str(i).zfill(len(m.group(2)))}.{zone}" for i in range(1, 21)}
        cands |= {f"{x}.{zone}" for x in COMMON_LABELS}
    return sorted(cands)


def names_for(ip, db=None):
    """Domains (among the guessed candidates) whose A/AAAA point to ip, plus the PTR name if any."""
    import ipaddress
    want = ipaddress.ip_address(ip)
    cands = host_candidates(db or C.load_db())
    with ThreadPoolExecutor(max_workers=16) as ex:
        res = dict(zip(cands, ex.map(resolve, cands)))
    match = [h for h, (v4, v6) in res.items() if any(ipaddress.ip_address(a) == want for a in v4 + v6)]
    try:
        ptr = norm_host(socket.gethostbyaddr(ip)[0])
    except OSError:
        ptr = ""
    return {"match": match, "ptr": ptr if ptr and ptr not in match else ""}


def lookup(q):
    """/admin/servers/lookup: ?host= -> its addresses, ?ip= -> domains pointing to it."""
    if q.get("host"):
        h = norm_host(q["host"])
        if not h:
            return {"error": "некорректный домен"}
        v4, v6 = resolve(h, ttl=30)
        return {"host": h, "v4": v4, "v6": v6}
    ip = (q.get("ip") or "").strip()
    if valid_ip(ip, 4) or valid_ip(ip, 6):
        return {"ip": ip, **names_for(ip)}
    return {"error": "укажите домен или IP"}


def exits_sorted(db, only_enabled=False):
    items = [(i, e) for i, e in db.get("exits", {}).items() if e.get("enabled") or not only_enabled]
    return sorted(items, key=lambda kv: (kv[1]["priority"], kv[0]))


def fam_ports(db):
    """Per-family probe ports: 10900.. (2 per exit), stable by exit id order of creation."""
    ports, i = {}, 0
    for eid in sorted(db.get("exits", {}), key=lambda k: db["exits"][k].get("created", "")):
        ports[eid] = (10900 + 2 * i, 10901 + 2 * i)
        i += 1
    return ports


def event(db, text):
    db.setdefault("balancer", {"plan": None, "events": []})
    db["balancer"]["events"].insert(0, {"ts": C.now_utc().isoformat(), "text": text})
    del db["balancer"]["events"][50:]


# ---------------------------------------------------------------- xray config generation
def reality_in(tag, sni, priv, sid, port=443, listen="0.0.0.0", target=None, xver=0):
    return {"tag": tag, "listen": listen, "port": port, "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality",
                               "realitySettings": {"show": False, "target": target or sni + ":443", "xver": xver,
                                                   "serverNames": [sni],
                                                   "privateKey": priv, "shortIds": [sid],
                                                   # Xray >= 26.7.11 rejects sing-box clients without this
                                                   "minClientVer": "1.0.0"}},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}}


def exit_profile(eid, e):
    return {"log": {"loglevel": "warning"},
            "inbounds": [reality_in(f"EXIT_{eid.upper()}_REALITY", e["sni"], e["priv"], e["sid"], e.get("port", 443), "::")],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
            "routing": {"rules": [{"ip": ["geoip:private"], "outboundTag": "block"},
                                  {"protocol": ["bittorrent"], "outboundTag": "block"}]}}


def out_tags(eid, e):
    tags = []
    if e.get("host") or e.get("ip4"):
        tags.append(f"x-{eid}-4")
    if e.get("ip6"):
        tags.append(f"x-{eid}-6")
    return tags


def dns_mismatch(e, ttl=300):
    """Hostname set but its A records don't include the exit's IPv4 (stale DNS after an IP change) -> resolved list."""
    host, ip4 = e.get("host"), e.get("ip4")
    if not (host and ip4):
        return None
    addrs = resolve(host, ttl)[0]
    return None if ip4 in addrs else addrs


def bridge_addr(e):
    # The IP is authoritative (updated via the portal at once); DNS may lag up to a day after an IP change.
    return e.get("ip4") or e["host"]


def bridge_out(tag, addr, e, bridge_uuid):
    return {"tag": tag, "protocol": "vless",
            "settings": {"vnext": [{"address": addr, "port": e.get("port", 443),
                                    "users": [{"id": bridge_uuid, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
            "streamSettings": {"network": "tcp", "security": "reality",
                               "realitySettings": {"serverName": e["sni"], "fingerprint": "chrome",
                                                   "publicKey": e["pub"], "shortId": e["sid"]}}}


def best_tag(eid, e):
    s = STATUS.get(eid, {})
    tags = out_tags(eid, e)
    if s.get("v4") and f"x-{eid}-4" in tags:
        return f"x-{eid}-4"
    if s.get("v6") and f"x-{eid}-6" in tags:
        return f"x-{eid}-6"
    return tags[-1]  # IPv6 first when unknown: exits' IPv4 is the first thing RKN blocks


# Users' domains are resolved on MSK for routing (geoip:ru, IPIfNonMatch) and for direct/YouTube connections.
# DoH: queries are encrypted (the DPI of the Russian DC sees none of them) and cached by xray; plain system DNS
# (127.0.0.53 -> 1.1.1.1/8.8.8.8) only as the last resort.
MSK_DNS = {"servers": ["https+local://8.8.8.8/dns-query", "https+local://77.88.8.8/dns-query", "localhost"],
           "queryStrategy": "UseIP"}


def msk_profile(db, plan):
    st = state()
    K = st["keys"]["MSK"]
    ports = fam_ports(db)
    inb = [
        # self-steal: non-VPN visitors of :443 get our own site (Caddy on 127.0.0.1:8443, real cert for our domain);
        # xver 2 = PROXY protocol, so Caddy/portal see the real client IP
        reality_in("MSK_REALITY", MSK_DOMAIN, K["priv"], K["sid"], target="127.0.0.1:8443", xver=2),
        {"tag": "MSK_HY2", "listen": "0.0.0.0", "port": 443, "protocol": "hysteria",
         "settings": {"version": 2, "clients": []},
         "streamSettings": {"network": "hysteria", "security": "tls",
                            "tlsSettings": {"alpn": ["h3"], "certificates": [
                                {"certificateFile": f"{CERT}/{MSK_DOMAIN}.crt",
                                 "keyFile": f"{CERT}/{MSK_DOMAIN}.key"}]},
                            "hysteriaSettings": {"version": 2}},
         "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
        {"tag": "AWG_BRIDGE", "listen": "127.0.0.1", "port": 10808, "protocol": "mixed", "settings": {"udp": True},
         "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
        {"tag": "MON_YT", "listen": "127.0.0.1", "port": 10803, "protocol": "mixed", "settings": {"udp": False}},
        # MTProxy (Telegram) upstream: always abroad, Telegram is blocked in RU
        {"tag": "MTP_OUT", "listen": "127.0.0.1", "port": 10804, "protocol": "mixed", "settings": {"udp": False}},
    ]
    # direct: resolve through xray's DNS below (DoH, cached), not the host's plain-UDP resolver
    outs = [{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4v6"}},
            # YouTube: MSK DC blocks it over IPv4 -> IPv6 first, IPv4 through zapret
            {"tag": "yt-dpi", "protocol": "freedom", "settings": {"domainStrategy": "ForceIPv6v4"}}]
    # clients' plain DNS (Hiddify's remote DNS, AmneziaWG's 8.8.8.8...) is answered here by xray's DNS (DoH, cached):
    # one round trip to MSK instead of a detour via an exit
    outs.append({"tag": "dns-out", "protocol": "dns", "settings": {
        "rules": [{"action": "hijack", "qtype": "1,28"}, {"action": "direct"}]}})   # A/AAAA answered here, the rest passes
    bals, rules = [], [{"inboundTag": ["MON_YT"], "outboundTag": "yt-dpi"},
                       {"inboundTag": ["MSK_REALITY", "MSK_HY2", "AWG_BRIDGE"], "port": "53", "outboundTag": "dns-out"}]
    for eid, e in exits_sorted(db):
        tags = out_tags(eid, e)
        if not tags:
            continue
        if e.get("host") or e.get("ip4"):
            outs.append(bridge_out(f"x-{eid}-4", bridge_addr(e), e, st["bridge_uuid"]))
        if e.get("ip6"):
            outs.append(bridge_out(f"x-{eid}-6", e["ip6"], e, st["bridge_uuid"]))
        p4, p6 = ports[eid]
        inb.append({"tag": f"MON_{eid}", "listen": "127.0.0.1", "port": e["mon_port"], "protocol": "mixed", "settings": {"udp": False}})
        inb.append({"tag": f"MON_{eid}_4", "listen": "127.0.0.1", "port": p4, "protocol": "mixed", "settings": {"udp": False}})
        inb.append({"tag": f"MON_{eid}_6", "listen": "127.0.0.1", "port": p6, "protocol": "mixed", "settings": {"udp": False}})
        bals.append({"tag": f"bal-{eid}", "selector": [f"x-{eid}-"], "strategy": {"type": "leastPing"}, "fallbackTag": tags[-1]})
        rules.append({"inboundTag": [f"MON_{eid}"], "balancerTag": f"bal-{eid}"})
        rules.append({"inboundTag": [f"MON_{eid}_4"], "outboundTag": f"x-{eid}-4" if f"x-{eid}-4" in tags else "block"})
        rules.append({"inboundTag": [f"MON_{eid}_6"], "outboundTag": f"x-{eid}-6" if f"x-{eid}-6" in tags else "block"})
    outs.append({"tag": "block", "protocol": "blackhole"})
    primary = plan["primary"] or []
    have_exits = any(out_tags(i, e) for i, e in exits_sorted(db, True))
    if have_exits:
        main = {"tag": "exits", "selector": [f"x-{i}-" for i in primary] or ["x-"], "strategy": {"type": "leastPing"}}
        if plan.get("fallback"):
            main["fallbackTag"] = best_tag(plan["fallback"], db["exits"][plan["fallback"]])
        bals.insert(0, main)
    to_exits = {"balancerTag": "exits"} if have_exits else {"outboundTag": "direct"}   # fresh install: no exits yet
    rules += [dict({"inboundTag": ["MTP_OUT"]}, **to_exits),
              {"protocol": ["bittorrent"], "outboundTag": "block"},
              {"network": "udp", "port": "443", "domain": ["geosite:youtube"], "outboundTag": "block"},
              {"domain": ["geosite:youtube"], "outboundTag": "yt-dpi"}]
    # games/services from direct.json: straight from MSK, no detour via exits (Hiddify/Amnezia users)
    try:
        dj = json.load(open(C.DIRECT_JSON))
        rules += [{"domain": ["geosite:" + g for g in dj.get("geosite", [])] + ["domain:" + x for x in dj["domains"]],
                   "outboundTag": "direct"},
                  {"ip": dj["ips"], "outboundTag": "direct"}]
    except (OSError, ValueError, KeyError) as e:
        print("direct.json not applied:", e, flush=True)
    rules += [
              {"ip": ["geoip:private"], "outboundTag": "block"},
              {"domain": ["geosite:category-ru"], "outboundTag": "direct"},
              {"ip": ["geoip:ru"], "outboundTag": "direct"},
              dict({"network": "tcp,udp"}, **to_exits)]
    return {"log": {"loglevel": "warning"}, "inbounds": inb, "outbounds": outs, "dns": MSK_DNS,
            **({"burstObservatory": {"subjectSelector": ["x-"],
                                 "pingConfig": {"destination": "https://www.gstatic.com/generate_204",
                                                "interval": "15s", "timeout": "8s", "sampling": 2}}} if have_exits else {}),
            "routing": {"domainStrategy": "IPIfNonMatch", "balancers": bals, "rules": rules}}


def apply(db, plan=None):
    """Push MSK profile (+ node inbounds) and bridge squad to Remnawave."""
    with APPLY_LOCK:
        st = state()
        plan = plan or db["balancer"].get("plan") or compute_plan(db)
        prof = C.rw("PATCH", "/api/config-profiles", {"uuid": st["profiles"]["MSK"]["uuid"], "config": msk_profile(db, plan)})
        C.rw("PATCH", "/api/nodes", {"uuid": st["nodes"]["MSK"], "configProfile": {
            "activeConfigProfileUuid": st["profiles"]["MSK"]["uuid"], "activeInbounds": [i["uuid"] for i in prof["inbounds"]]}})
        inbounds = []
        for eid, e in exits_sorted(db):
            if e.get("profile_uuid"):
                p = C.rw("GET", f"/api/config-profiles/{e['profile_uuid']}")
                inbounds += [i["uuid"] for i in p.get("inbounds", [])]
        C.rw("PATCH", "/api/internal-squads", {"uuid": st["squads"]["bridge"], "inbounds": inbounds})
        db["balancer"]["plan"] = plan
        keep_enabled(st["nodes"]["MSK"])


def keep_enabled(node_uuid, wait=8):
    """A profile update gets new inbound ids; the panel restarts the node at once and, seeing the node's old ids,
    logs 'No active inbounds found ... disabling' - our PATCH with the new ids comes a moment later but the node
    stays disabled (prod, 2026-09-27). Watch it for a few seconds and switch it back on."""
    for _ in range(wait // 2):
        time.sleep(2)
        n = next((x for x in C.rw("GET", "/api/nodes") if x["uuid"] == node_uuid), None)
        if n and n.get("isDisabled"):
            C.rw("POST", f"/api/nodes/{node_uuid}/actions/enable", {})
            print(f"node {n['name']} was disabled by the panel after a profile update - enabled", flush=True)
            return True
    return False


# ---------------------------------------------------------------- probing / watchdog
def probe_port(port):
    t0 = time.time()
    rc, out = C.sh(["curl", "-s", "-m", "8", "--socks5-hostname", f"127.0.0.1:{port}", "https://api.ipify.org"])
    ok = rc == 0 and bool(re.fullmatch(r"[0-9a-fA-F.:]+", out or ""))
    return ok, int((time.time() - t0) * 1000), out if ok else None


def probe_all(db):
    ports = fam_ports(db)
    jobs = {}
    with ThreadPoolExecutor(max_workers=12) as ex:
        for eid, e in db.get("exits", {}).items():
            jobs[eid] = (ex.submit(probe_port, e["mon_port"]), ex.submit(probe_port, ports[eid][0]),
                         ex.submit(probe_port, ports[eid][1]))
        for eid, (b, p4, p6) in jobs.items():
            ok, ms, ip = b.result()
            e = db["exits"][eid]
            STATUS[eid] = {"ok": ok, "ms": ms, "ip": ip, "ts": C.now_utc(),
                           "v4": p4.result()[0] if (e.get("host") or e.get("ip4")) else None,
                           "v6": p6.result()[0] if e.get("ip6") else None}
            c = COUNTERS.setdefault(eid, {"fail": 0, "ok": 0, "up": ok})
            if ok:
                c["ok"], c["fail"] = c["ok"] + 1, 0
                if not c["up"] and c["ok"] >= OKS_TO_UP:
                    c["up"] = True
            else:
                c["fail"], c["ok"] = c["fail"] + 1, 0
                if c["up"] and c["fail"] >= FAILS_TO_DOWN:
                    c["up"] = False
                    if not starting_up():
                        C.log_error(f"Выход {e['name']} недоступен с MSK (IPv4: {STATUS[eid].get('v4')}, IPv6: {STATUS[eid].get('v6')})")


def starting_up():
    """Portal just started or a server is being added/removed: nodes may be down for a moment, don't raise alarms."""
    return time.time() - C.STARTED < C.STARTUP_GRACE or any(not j["done"] for j in JOBS.values())


def is_up(eid):
    return COUNTERS.get(eid, {}).get("up", True)


def compute_plan(db):
    en = exits_sorted(db, only_enabled=True)
    if not en:
        return {"primary": [], "fallback": None}
    alive = [(i, e) for i, e in en if is_up(i)]
    if alive:
        top = alive[0][1]["priority"]
        primary = [i for i, e in alive if e["priority"] == top]
    else:
        top = en[0][1]["priority"]
        primary = [i for i, e in en if e["priority"] == top]
    rest = [i for i, e in sorted(en, key=lambda kv: (not is_up(kv[0]), kv[1]["priority"])) if i not in primary]
    return {"primary": primary, "fallback": rest[0] if rest else None,
            "fb_tag": best_tag(rest[0], db["exits"][rest[0]]) if rest else None}


def names(db, ids):
    return ", ".join(db["exits"][i]["name"] for i in ids if i in db["exits"]) or "—"


def plan_works(plan):
    """Does xray still have a live route with this plan? Its main balancer skips dead primaries by itself and takes
    fallbackTag when all of them are down - no profile change needed (a change restarts xray: all users' connections drop)."""
    if not plan:
        return False
    if any(is_up(i) for i in plan.get("primary") or []):
        return True
    fb, tag = plan.get("fallback"), plan.get("fb_tag") or ""
    if not fb or not is_up(fb):
        return False
    return STATUS.get(fb, {}).get("v6" if tag.endswith("-6") else "v4") is not False


def best_prio(db, ids):
    return min((db["exits"][i]["priority"] for i in ids or [] if i in db["exits"]), default=10 ** 6)


def must_switch(db, old, new):
    """Rebuild the MSK profile only when the running one has no live route any more, or to return to
    higher-priority exits after an outage. A dead primary alone is handled inside xray (fallbackTag)."""
    if not old:
        return True
    if not plan_works(old):
        return True
    return best_prio(db, new["primary"]) < best_prio(db, old.get("primary"))


def heal_panel(nodes):
    """Self-repair of the panel state (both seen on prod 2026-09-27):
    - Remnawave disables a node after a few failed connects (e.g. while xray restarts) and never re-enables it.
      A disabled MSK node = empty subscriptions and no route to the exits. The portal itself never disables nodes.
    - an interrupted add may leave an EXIT-* node/profile the portal doesn't know; it blocks re-adding that server.
    Never runs while a server is being added/removed (its node/profile exist before the portal DB knows them)."""
    if starting_up():
        return
    db = C.load_db()
    known_n = {e.get("node_uuid") for e in db["exits"].values()}
    known_p = {e.get("profile_uuid") for e in db["exits"].values()}
    for n in nodes:
        if n.get("isDisabled") and (n["name"] == "MSK" or n["uuid"] in known_n):
            C.rw("POST", f"/api/nodes/{n['uuid']}/actions/enable", {})
            n["_healed"] = True     # skip the "not connected" alarm this tick: it is reconnecting
            C.log_error(f"Панель Remnawave отключила ноду {n['name']} — портал включил её обратно")
    for n in nodes:
        if n["name"].startswith("EXIT-") and n["uuid"] not in known_n:
            C.rw("DELETE", f"/api/nodes/{n['uuid']}")
            n["_gone"] = True
            C.log_error(f"Удалена лишняя нода {n['name']} ({n['address']}) — осталась от прерванного добавления сервера")
    profs = C.rw("GET", "/api/config-profiles")
    profs = profs.get("configProfiles", []) if isinstance(profs, dict) else profs
    for p in profs:
        if p["name"].startswith("EXIT-") and p["uuid"] not in known_p:
            C.rw("DELETE", f"/api/config-profiles/{p['uuid']}")
            C.log_error(f"Удалён лишний профиль {p['name']} — остался от прерванного добавления сервера")
    nodes[:] = [n for n in nodes if not n.get("_gone")]


def watchdog_tick():
    db = C.load_db()
    if seed(db):
        apply(db, compute_plan(db))
        event(db, "Портал взял управление балансировщиком")
        with C.LOCK:
            C.save_db(db)
    try:
        if check_msk_ip(db):
            with C.LOCK:
                fresh = C.load_db(); fresh["msk"] = db["msk"]; fresh["balancer"] = db["balancer"]; C.save_db(fresh)
    except Exception as ex:
        print("msk ip check:", repr(ex), flush=True)
    quiet = starting_up()
    try:
        # quiet while the portal is starting or a server is being added/removed (its node is not up yet)
        nodes = [] if quiet else C.rw("GET", "/api/nodes")
        if not quiet:
            heal_panel(nodes)
        for n in nodes:
            if not n.get("isConnected") and not n.get("isDisabled") and not n.get("_healed"):
                C.log_error(f"Нода {n['name']} ({n['address']}) не на связи с панелью: {(n.get('lastStatusMessage') or '')[:160]}")
    except Exception as ex:
        if not quiet:
            C.log_error(f"Панель Remnawave не отвечает: {ex}")
    probe_all(db)
    plan = compute_plan(db)
    old = db["balancer"].get("plan")
    degraded = bool(old) and plan != old and not any(is_up(i) for i in old.get("primary") or [])
    if degraded != db["balancer"].get("degraded", False):
        db["balancer"]["degraded"] = degraded
        event(db, f"{names(db, old['primary'])} недоступен — трафик сам ушёл на резерв {names(db, [old['fallback']])} "
                  "(без перезапуска)" if degraded else f"{names(db, (old or {}).get('primary') or [])} снова доступен")
        with C.LOCK:
            fresh = C.load_db(); fresh["balancer"] = db["balancer"]; C.save_db(fresh)
    if plan != old and must_switch(db, old, plan):
        db["balancer"]["degraded"] = False
        apply(db, plan)
        if not old or old.get("primary") != plan["primary"]:
            down = [i for i in (old or {}).get("primary", []) if not is_up(i)]
            why = f" ({names(db, down)} недоступен)" if down else ""
            event(db, f"Основной выход: {names(db, plan['primary'])}{why}; резерв: {names(db, [plan['fallback']] if plan['fallback'] else [])}")
        else:
            event(db, f"Резерв: {names(db, [plan['fallback']] if plan['fallback'] else [])}")
        with C.LOCK:
            fresh = C.load_db()
            fresh["balancer"] = db["balancer"]
            C.save_db(fresh)


def watchdog():
    time.sleep(5)
    while True:
        try:
            watchdog_tick()
        except Exception as e:
            if starting_up():
                print("watchdog (startup, not logged):", repr(e), flush=True)
            else:
                C.log_error(f"Сторож балансировщика: {e!r}")
        time.sleep(PROBE_EVERY)


# ---------------------------------------------------------------- jobs: add / delete server
def job(title, fn, *args):
    jid = secrets.token_hex(4)
    JOBS[jid] = {"title": title, "log": [], "done": False, "ok": False, "started": C.now_utc()}

    def log(msg):
        JOBS[jid]["log"].append(f"{C.now_utc().astimezone(dt.timezone(dt.timedelta(hours=3))).strftime('%H:%M:%S')}  {msg}")
    log.job = JOBS[jid]

    def run():
        try:
            fn(log, *args)
            JOBS[jid]["ok"] = True
            if not JOBS[jid].get("confirm"):
                log("Готово.")
        except Exception as e:
            log("ОШИБКА: " + str(e))
            if not isinstance(e, C.UserError):     # wrong input / refused action is not a system failure
                C.log_error(f"{title}: {e}")
            print(traceback.format_exc(), flush=True)
        JOBS[jid]["done"] = True

    threading.Thread(target=run, daemon=True).start()
    return jid


def ssh_connect(host, port, password):
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, port=port, username="root", password=password, timeout=15, allow_agent=False, look_for_keys=False)
    return c


def ssh_run(c, script, log=None, timeout=900):
    # The script runs from a file with its output redirected to a log: daemons it starts (dockerd, containerd...)
    # must not inherit the SSH channel, otherwise reading until EOF hangs until the timeout (seen 2026-09-27).
    sftp = c.open_sftp()
    with sftp.file("/tmp/geovpn-run.sh", "w") as fh:
        fh.write(script)
    sftp.close()
    _, o, e = c.exec_command("bash /tmp/geovpn-run.sh > /tmp/geovpn-run.log 2>&1 < /dev/null; rc=$?; "
                             "tail -n 20 /tmp/geovpn-run.log; exit $rc", timeout=timeout)
    out = o.read().decode(errors="replace")
    err = e.read().decode(errors="replace")
    rc = o.channel.recv_exit_status()
    if log:
        for line in out.strip().splitlines()[-6:]:
            log("  " + line)
    if rc != 0:
        raise RuntimeError(f"команда на сервере завершилась с кодом {rc}: {(err or out).strip()[-400:]}")
    return out


def valid_ip(s, version):
    import ipaddress
    try:
        return ipaddress.ip_address(s).version == version
    except ValueError:
        return False


def detect_addrs(c):
    """Global IPv4/IPv6 of the server itself (the form may contain a /48 prefix or nothing)."""
    _, o, _ = c.exec_command("ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1; echo ---; "
                             "ip -o -6 addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1", timeout=20)
    v4, _, v6 = o.read().decode(errors="replace").partition("---")
    return v4.strip(), v6.strip()


def tcp_ok(host, port, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


NODE_DEFAULTS = {"node_port": 2222, "node_dir": "/opt/remnanode", "node_name": "remnanode", "fw_name": "geovpn-fw"}
PENDING = {}         # confirm token -> {"f": add form (incl. password, memory only), "sug", "conflicts", "exp"}
NAME_RX = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,39}")
DIR_RX = re.compile(r"/opt/[A-Za-z0-9][A-Za-z0-9_.-]{0,39}")
REALITY_PORTS = [443, 8443, 2053, 2083, 2087, 2096, 4443, 10443]


def nd(e, k):
    """Per-exit install parameter (exits added before 2026-09-27 have none -> the old fixed values)."""
    return e.get(k) or NODE_DEFAULTS[k]


def fw_chain(fw_name):
    return "GEOVPN_NODE" if fw_name == "geovpn-fw" else ("GV_" + re.sub(r"[^A-Za-z0-9]", "_", fw_name).upper())[:28]


NODE_INSTALL = r"""
set -e
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1
for p in __PORT__ __NPORT__; do
  if ss -Htln | awk '{print $4}' | grep -qE "[:.]$p\$"; then echo "PORT_BUSY $p"; exit 17; fi
done
if [ -e __DIR__ ]; then echo "DIR_BUSY __DIR__"; exit 18; fi
if docker ps -a --format '{{.Names}}' | grep -qxE '__NODE__|__FW__'; then echo "NAME_BUSY"; exit 19; fi
cat >/etc/sysctl.d/99-geovpn.conf <<'X'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_mtu_probing = 1
X
sysctl --system >/dev/null 2>&1 || true
# everything else lives in __DIR__ and runs in docker: xray node + firewall of the node API port (only MSK may connect)
mkdir -p __DIR__/fw
cat >__DIR__/docker-compose.yml <<'X'
# geovpn-exit (managed by the GeoVPN portal; remove it from the portal, not by hand)
services:
  remnanode:
    container_name: __NODE__
    hostname: __NODE__
    image: __NTAG__
    pull_policy: never
    restart: always
    network_mode: host
    cap_add: [NET_ADMIN]
    ulimits:
      nofile: { soft: 1048576, hard: 1048576 }
    environment:
      - NODE_PORT=__NPORT__
      - SECRET_KEY=__SECRET__
    depends_on: [geovpn-fw]
  geovpn-fw:
    container_name: __FW__
    labels: ["geovpn.msk=__MSKID__"]
    image: __FTAG__
    pull_policy: never
    restart: always
    network_mode: host
    cap_add: [NET_ADMIN, NET_RAW]
    volumes: ["./fw:/conf"]
    entrypoint: ["/conf/fw.sh"]
    command: ["loop"]
X
printf 'ALLOW="%s"\nALLOW6="%s"\nNODE_PORT=%s\nCHAIN=%s\n' "__MSK4__" "__MSK6__" "__NPORT__" "__CHAIN__" >__DIR__/fw/fw.env
cat >__DIR__/fw/fw.sh <<'X'
#!/bin/bash
# geovpn-fw container: the node API port is reachable only from the MSK entry server.
#   fw.sh loop  - apply rules, re-apply if something (ufw reload, reboot) removed them
#   fw.sh set   - "set-msk <ipv4> <ipv6|->" from the restricted portal SSH key (SSH_ORIGINAL_COMMAND)
#   fw.sh clear - remove the rules (node removal)
. /conf/fw.env
apply() {
  . /conf/fw.env
  for T in iptables ip6tables; do
    $T -D INPUT -p tcp --dport "$NODE_PORT" -j "$CHAIN" 2>/dev/null
    $T -F "$CHAIN" 2>/dev/null || $T -N "$CHAIN"
    if [ $T = iptables ]; then L=$ALLOW; else L=$ALLOW6; fi
    for s in $L; do $T -A "$CHAIN" -s "$s" -j ACCEPT; done   # ACCEPT, not RETURN: host firewalls (ufw) drop the rest
    $T -A "$CHAIN" -j DROP
    $T -I INPUT -p tcp --dport "$NODE_PORT" -j "$CHAIN"
  done
}
in_place() {  # our jump exists in both families and comes before ufw's chains (ufw enable/reload puts them first)
  for T in iptables ip6tables; do
    r=$($T -S INPUT | grep -n -- "--dport $NODE_PORT -j $CHAIN" | head -1 | cut -d: -f1)
    u=$($T -S INPUT | grep -n -- "-j ufw" | head -1 | cut -d: -f1)
    [ -n "$r" ] && { [ -z "$u" ] || [ "$r" -lt "$u" ]; } || return 1
  done
}
case "$1" in
  set)
    read -r cmd v4 v6 extra <<< "$SSH_ORIGINAL_COMMAND"
    [ "$cmd" = set-msk ] && [ -z "$extra" ] || { echo "denied"; exit 1; }
    [ "$v6" = - ] && v6=""
    [[ $v4 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { [ -z "$v6" ] || [[ $v6 =~ ^[0-9a-fA-F:]{2,39}$ ]]; } || { echo "bad address"; exit 1; }
    printf 'ALLOW="%s"\nALLOW6="%s"\nNODE_PORT=%s\nCHAIN=%s\n' "$v4" "$v6" "$NODE_PORT" "$CHAIN" >/conf/fw.env
    apply && echo "ok $v4 ${v6:--}" ;;
  clear)
    touch /conf/.removing   # the loop below must not "restore" the rules in its last seconds
    for T in iptables ip6tables; do $T -D INPUT -p tcp --dport "$NODE_PORT" -j "$CHAIN" 2>/dev/null; $T -F "$CHAIN" 2>/dev/null; $T -X "$CHAIN" 2>/dev/null; done ;;
  loop)
    [ -f /conf/.removing ] && exec sleep infinity
    apply; echo "fw: port $NODE_PORT allowed only from MSK"
    while :; do
      sleep 30 & wait $!
      [ -f /conf/.removing ] && exec sleep infinity
      in_place || { apply; echo "fw: rules restored"; }
    done ;;
esac
X
chmod +x __DIR__/fw/fw.sh
# host firewall (ufw) would drop the Reality port: open it, and remember that we did (removal closes only what we opened)
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  if ! ufw status | grep -qE "^__PORT__(/tcp)? "; then ufw allow __PORT__/tcp >/dev/null && touch __DIR__/.ufw-opened && echo "ufw: opened __PORT__/tcp"; fi
fi
cd __DIR__ && docker compose up -d 2>&1 | tail -1
sleep 2; docker exec __FW__ iptables -C INPUT -p tcp --dport __NPORT__ -j __CHAIN__
echo "node installed on $(hostname) in __DIR__"
"""

NODE_REMOVE = r"""
D=__DIR__
if [ -f $D/docker-compose.yml ] && grep -qE '^# geovpn-exit|geovpn-fw|remnawave/node' $D/docker-compose.yml; then
  docker exec __FW__ /conf/fw.sh clear 2>/dev/null
  [ -f $D/.ufw-opened ] && ufw delete allow __PORT__/tcp >/dev/null 2>&1 && echo "ufw: closed __PORT__/tcp"
  cd $D && docker compose down --rmi local 2>&1 | tail -1
  cd / && rm -rf $D
else
  echo "в $D нет установки GeoVPN — ничего не удаляю"
fi
# the portal key stays while this MSK still has other nodes here
# ...and so do MSK's backups (they hold all secrets) with the key that writes them
if ! docker ps -aq --filter label=geovpn.msk=__MSKID__ 2>/dev/null | grep -q .; then
  sed -i -e '\#__KEY__#d' -e '\#__BKEY__#d' /root/.ssh/authorized_keys 2>/dev/null
  rm -rf /root/geovpn-backups && echo "бэкапы MSK с сервера удалены"
fi
# older installs (before 2026-09-27): host-level firewall unit
if [ -f /etc/systemd/system/geovpn-fw.service ]; then
  systemctl disable --now geovpn-fw >/dev/null 2>&1 || true
  for T in iptables ip6tables; do $T -D INPUT -p tcp --dport 2222 -j GEOVPN_NODE 2>/dev/null; $T -F GEOVPN_NODE 2>/dev/null; $T -X GEOVPN_NODE 2>/dev/null; done
  rm -f /usr/local/bin/geovpn-fw.sh /usr/local/bin/geovpn-fw-set /etc/systemd/system/geovpn-fw.service
  systemctl daemon-reload
fi
echo "node removed from $(hostname)"
"""

# Images for the exit: the node image (tagged locally) and the fw image built on top of it (+ iptables from Debian).
# Some hosting networks get 403 from Docker Hub (seen 2026-09-27, NetCrafters/Helsinki): then the portal ships both
# images from MSK over SSH (ship_images).
IMAGES = r"""
set -e
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1
command -v docker >/dev/null || curl -fsSL https://get.docker.com | sh >/var/log/geovpn-docker-install.log 2>&1
if ! docker image inspect __NTAG__ >/dev/null 2>&1; then
  if timeout 600 docker pull -q __IMAGE__ >/dev/null 2>&1; then docker tag __IMAGE__ __NTAG__; else echo "NEED_SHIP: Docker Hub недоступен с сервера"; exit 0; fi
fi
if ! docker image inspect __FTAG__ >/dev/null 2>&1; then
  printf '__FWDOCKERFILE__' | DOCKER_BUILDKIT=0 timeout 600 docker build -q -t __FTAG__ - >/dev/null 2>&1 \
    || { echo "NEED_SHIP: не удалось собрать образ файрвола на сервере"; exit 0; }
fi
echo "IMAGES_OK"
"""
FW_DOCKERFILE = "FROM {base}\\nRUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/*\\n"


def image_tags():
    """Local tags used on exits: geovpn/node:<digest12> and geovpn/fw:<digest12> (the fw image is FROM the node image)."""
    img = node_image()
    t = re.sub(r"[^a-f0-9]", "", img.split("@sha256:")[-1])[:12] if "@sha256:" in img else re.sub(r"[^A-Za-z0-9_.-]", "-", img)[-40:]
    return img, f"geovpn/node:{t}", f"geovpn/fw:{t}"


def images_script():
    img, ntag, ftag = image_tags()
    return (IMAGES.replace("__IMAGE__", img).replace("__NTAG__", ntag).replace("__FTAG__", ftag)
            .replace("__FWDOCKERFILE__", FW_DOCKERFILE.format(base=ntag)))


def ship_images(c, log):
    """Build the exit images on MSK (it has the node image) and copy them to the exit over SSH."""
    img, ntag, ftag = image_tags()
    tmp = "/tmp/geovpn-exit-images.tar.gz"
    rc, _ = C.sh(["docker", "image", "inspect", ntag])
    if rc != 0:
        rc, out = C.sh(["docker", "tag", img, ntag])
        if rc != 0:
            raise RuntimeError(f"на MSK нет образа ноды {img}: {out}")
    if C.sh(["docker", "image", "inspect", ftag])[0] != 0:
        log("  собираю образ файрвола на MSK…")
        rc, out = C.sh(f"printf '{FW_DOCKERFILE.format(base=ntag)}' | DOCKER_BUILDKIT=0 docker build -q -t {ftag} - 2>&1", timeout=900)
        if rc != 0:
            raise RuntimeError(f"не удалось собрать образ файрвола на MSK: {out[-300:]}")
    rc, out = C.sh(f"docker save {ntag} {ftag} | gzip -1 > {tmp}", timeout=900)
    if rc != 0:
        raise RuntimeError(f"docker save на MSK: {out[-300:]}")
    size = os.path.getsize(tmp) // (1 << 20)
    log(f"  передаю образы на сервер ({size} МБ)…")
    try:
        sftp = c.open_sftp()
        sftp.put(tmp, tmp)
        sftp.close()
    finally:
        os.remove(tmp)
    ssh_run(c, f"gunzip -c {tmp} | docker load >/dev/null && rm -f {tmp} && docker image inspect {ntag} {ftag} >/dev/null && echo loaded", log)


# read-only look at the server before installing: busy TCP ports (+ process), container names, /opt, our old installs
PREFLIGHT = r"""
echo "DOCKER=$(command -v docker >/dev/null 2>&1 && echo 1 || echo 0)"
echo "PORTS=$(ss -Htlnp 2>/dev/null | awk '{n=split($4,a,":"); m="?"; if (match($0,/\("[^"]+"/)) m=substr($0,RSTART+2,RLENGTH-3); print a[n]":"m}' | sort -u | tr '\n' ' ')"
echo "NAMES=$(command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Names}}' | tr '\n' ' ')"
echo "OPT=$(ls -1 /opt 2>/dev/null | tr '\n' ' ')"
echo "OURS=$(for d in /opt/*/; do grep -qsE '^# geovpn-exit|geovpn-fw|remnawave/node' ${d}docker-compose.yml && printf '%s ' ${d%/}; done)"
echo "UFW=$(command -v ufw >/dev/null && ufw status 2>/dev/null | head -1)"
"""


def preflight(c, want, sshport=22):
    """Check the wanted ports / container names / directory on the server. -> (conflicts, suggestions, info)"""
    import shlex
    _, o, _ = c.exec_command("bash -c " + shlex.quote(PREFLIGHT), timeout=60)
    info = {}
    for line in o.read().decode(errors="replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip()
    ports = {}
    for item in info.get("PORTS", "").split():
        p, _, proc = item.partition(":")
        if p.isdigit():
            ports.setdefault(int(p), proc)
    names = set(info.get("NAMES", "").split())
    used_dirs = {"/opt/" + x for x in info.get("OPT", "").split()}
    ours = set(info.get("OURS", "").split())
    reserved = {sshport, 22, 80}
    conflicts, sug = [], dict(want)

    def busy(p):
        return p in ports or p in reserved

    def who(p):
        return f"занят процессом «{ports[p]}»" if p in ports else "зарезервирован (SSH/HTTP)"

    if busy(want["port"]):
        conflicts.append(f"Порт Reality {want['port']}/tcp {who(want['port'])}")
    if busy(want["node_port"]):
        conflicts.append(f"Порт управления нодой {want['node_port']}/tcp {who(want['node_port'])}")
    if want["port"] == want["node_port"]:
        conflicts.append("Порт Reality и порт управления совпадают")
    free = lambda p: not busy(p)
    if busy(want["port"]) or want["port"] == want["node_port"]:
        sug["port"] = next(p for p in REALITY_PORTS + list(range(20443, 65000, 1000)) if free(p) and p != want["node_port"])
    if busy(want["node_port"]):
        sug["node_port"] = next(p for p in range(2222, 2300) if free(p) and p != sug["port"])
    for key, label in (("node_name", "Контейнер ноды"), ("fw_name", "Контейнер файрвола")):
        if want[key] in names:
            conflicts.append(f"{label} «{want[key]}» уже есть на сервере")
    if want["node_name"] == want["fw_name"]:
        conflicts.append("Имена контейнеров ноды и файрвола совпадают")
    if want["node_dir"] in used_dirs:
        conflicts.append(f"Папка {want['node_dir']} уже существует"
                         + (" — там прежняя установка GeoVPN (возможно, от другого входного сервера)" if want["node_dir"] in ours else ""))
    if want["node_name"] in names or want["fw_name"] in names or want["node_name"] == want["fw_name"] or want["node_dir"] in used_dirs:
        for k in range(1, 100):
            base = "geovpn-node" + ("" if k == 1 else f"-{k}")
            n_, f_, d_ = base, base + "-fw", "/opt/" + base
            if n_ not in names and f_ not in names and d_ not in used_dirs:
                sug.update(node_name=n_, fw_name=f_, node_dir=d_)
                break
    return conflicts, sug, {"docker": info.get("DOCKER") == "1", "ufw": info.get("UFW", "").strip() == "Status: active", "ours": sorted(ours)}


def node_image():
    import os
    if os.environ.get("NODE_IMAGE"):
        return os.environ["NODE_IMAGE"]
    t = open("/opt/remnanode/docker-compose.yml").read()
    return re.search(r"image:\s*(\S+)", t).group(1)


def install_params(f):
    """Validated port / container names / directory from the add (or confirm) form."""
    w = {}
    for k, default in (("port", 443), ("node_port", NODE_DEFAULTS["node_port"])):
        try:
            w[k] = int(f.get(k) or default)
        except ValueError:
            raise C.UserError(f"некорректный порт: {f.get(k)}")
        if not 1 <= w[k] <= 65535:
            raise C.UserError(f"некорректный порт: {w[k]}")
    for k in ("node_name", "fw_name"):
        w[k] = (f.get(k) or NODE_DEFAULTS[k]).strip()
        if not NAME_RX.fullmatch(w[k]):
            raise C.UserError(f"некорректное имя контейнера: {w[k]} (латиница, цифры, - _ .)")
    w["node_dir"] = (f.get("node_dir") or NODE_DEFAULTS["node_dir"]).strip().rstrip("/")
    if not DIR_RX.fullmatch(w["node_dir"]):
        raise C.UserError(f"папка установки должна быть вида /opt/имя, а не {w['node_dir']}")
    return w


def same_server(db, ip4, ip6):
    """Name of an exit already added with one of these addresses (a panel can't have two nodes on one address)."""
    for x in db.get("exits", {}).values():
        if (ip4 and ip4 == x.get("ip4")) or (ip6 and ip6 == x.get("ip6")):
            return x["name"]
    return None


def do_add(log, f):
    name = " ".join(f["name"].split())[:40]
    cc = (f.get("cc") or "").upper()[:2]
    ip4, ip6, host = f.get("ip4", "").strip(), f.get("ip6", "").strip(), f.get("host", "").strip()
    if host and not norm_host(host):
        raise C.UserError(f"некорректный домен: {host}")
    host = norm_host(host)
    from_dns = False
    if host and not (ip4 or ip6):                # only a domain given: take its A/AAAA records
        d4, d6 = resolve(host, ttl=0)
        if not (d4 or d6):
            raise C.UserError(f"домен {host} не резолвится — укажите IPv4 или IPv6 сервера")
        ip4, ip6, from_dns = (d4[0] if d4 else ""), (d6[0] if d6 else ""), True
        log(f"Адрес из DNS {host}: {ip4 or '—'} / {ip6 or '—'} (сверю с самим сервером после подключения)")
    ip4 = ip4 if valid_ip(ip4, 4) else ""
    ip6_try = [ip6] if valid_ip(ip6, 6) else []
    if not ip6_try and "/" in ip6:               # "2a12:…::/48" from the hoster panel: try typical host addresses
        import ipaddress
        try:
            net = ipaddress.ip_network(ip6, strict=False)
            ip6_try = [str(net.network_address + 2), str(net.network_address + 1)]
        except ValueError:
            pass
    ip6 = ip6_try[0] if ip6_try else ""
    prio, sni, pw = int(f.get("priority") or 10), f.get("sni") or SNI_CHOICES[0], f.get("password", "")
    sshport = int(f.get("sshport") or 22)
    w = install_params(f)
    port = w["port"]
    if not name or not (ip4 or ip6) or not pw:
        raise C.UserError("Нужны название, домен или корректный IPv4/IPv6-адрес сервера и root-пароль "
                           "(в поле IPv6 — адрес сервера, например 2a12:…::2, а не подсеть /48)")
    db = C.load_db()
    eid = re.sub(r"[^a-z0-9]", "", C.slugify(name))[:8] or "exit"
    base, n = eid, 2
    while eid in db.get("exits", {}):
        eid, n = f"{base}{n}", n + 1
    dup = same_server(db, ip4, ip6 if ip6_try and valid_ip(ip6, 6) else "")
    if dup:
        raise C.UserError(f"этот сервер уже добавлен как «{dup}». Для другого входного сервера (или чужого VPN) на нём "
                           "ограничений нет — но один вход может держать на сервере только одну свою ноду")
    created = {}
    c = None
    try:
        errs = []
        targets = ([ip4] if ip4 else []) + ip6_try
        if f.get("_ssh") in targets:             # confirm step: go straight to the address that answered last time
            targets.remove(f["_ssh"]); targets.insert(0, f["_ssh"])
        for target in targets:
            log(f"Подключаюсь по SSH к {target}…")
            try:
                c = ssh_connect(target, sshport, pw)
                if ":" in target:
                    ip6 = target
                ssh_target = target
                break
            except Exception as ex:
                errs.append(f"{target}: {ex}")
                log(f"  не отвечает ({ex})")
        if not c:
            raise RuntimeError("не удалось подключиться по SSH (" + "; ".join(errs) + "). " +
                               (f"Адрес взят из DNS {host} — если IP сервера недавно сменился, DNS может ещё указывать на "
                                "старый (обновление до суток): укажите IP вручную. " if from_dns else "") +
                               "Если IPv4 сервера заблокирован в РФ, укажите его IPv6-адрес (например 2a12:…::2) — портал подключится по нему")
        d4, d6 = detect_addrs(c)
        if d6 and valid_ip(d6, 6) and d6 != ip6:
            log(f"  IPv6 сервера: {d6}" + (f" (в форме было {f.get('ip6')})" if f.get("ip6") else ""))
            ip6 = d6
        d4_public = valid_ip(d4, 4) and not d4.startswith(("10.", "192.168.", "172."))
        if d4_public and d4 != ip4 and (not ip4 or from_dns):
            if ip4:
                log(f"  IPv4 сервера: {d4} (DNS {host} указывает на {ip4} — устарел, беру адрес с сервера)")
            ip4 = d4
        if not host and ip4:
            found = names_for(ip4)["match"]
            if len(found) == 1:
                host = found[0]
                log(f"  Домен сервера по DNS: {host}")
            elif found:
                log(f"  На этот IP указывают домены: {', '.join(found)} — домен не подставлен, укажите его в «Адрес…» при желании")
        dup = same_server(C.load_db(), ip4, ip6)
        if dup:
            raise C.UserError(f"этот сервер уже добавлен как «{dup}» (один вход может держать на сервере только одну свою ноду)")
        log("SSH: подключено. Проверяю, что порты, имена контейнеров и папка на сервере свободны…")
        conflicts, sug, pf = preflight(c, w, sshport)
        if pf["docker"]:
            log("  Docker на сервере уже есть — будет использован он, остальные контейнеры не затрагиваются.")
        if conflicts:
            for x in conflicts:
                log("  занято: " + x)
            token = secrets.token_urlsafe(16)
            PENDING[token] = {"f": {**f, "ip4": ip4, "ip6": ip6, "host": host, "_ssh": ssh_target}, "sug": sug, "conflicts": conflicts, "exp": time.time() + 900}
            log.job["confirm"] = token
            log("На сервере ничего не изменено. Проверьте предложенные значения ниже и подтвердите установку.")
            return
        log("  всё свободно." + (" На сервере включён ufw — порт Reality будет в нём открыт." if pf["ufw"] else ""))
        log("Генерирую ключи Reality…")
        kp = C.rw("GET", "/api/system/tools/x25519/generate")["keypairs"][0]
        e = {"name": name, "cc": cc, "host": host, "ip4": ip4, "ip6": ip6, "port": port, "sni": sni,
             "priv": kp["privateKey"], "pub": kp["publicKey"], "sid": secrets.token_hex(8), "priority": prio,
             "enabled": True, "mon_port": max([x["mon_port"] for x in db["exits"].values()] + [10809]) + 1,
             "node_port": w["node_port"], "node_dir": w["node_dir"], "node_name": w["node_name"], "fw_name": w["fw_name"],
             "created": C.now_utc().isoformat()}
        if e["mon_port"] in (10803, 10808):
            e["mon_port"] = 10820
        nport = w["node_port"]
        log("Создаю профиль и ноду в Remnawave…")
        prof = C.rw("POST", "/api/config-profiles", {"name": f"EXIT-{eid.upper()}", "config": exit_profile(eid, e)})
        created["profile"] = e["profile_uuid"] = prof["uuid"]
        node = C.rw("POST", "/api/nodes", {"name": f"EXIT-{eid.upper()}", "address": ip4 or f"[{ip6}]", "port": nport,
                                           "countryCode": cc or "XX",
                                           "configProfile": {"activeConfigProfileUuid": prof["uuid"],
                                                             "activeInbounds": [i["uuid"] for i in prof["inbounds"]]}})
        created["node"] = e["node_uuid"] = node["uuid"]
        secret = C.rw("GET", "/api/keygen")["secretKey"]
        log(f"Устанавливаю ноду в {w['node_dir']} (контейнеры {w['node_name']}, {w['fw_name']}; 1–3 минуты)…")
        log("Готовлю образы на сервере (Docker, нода, файрвол)…")
        created["remote"] = True
        out = ssh_run(c, images_script())
        if "NEED_SHIP" in out:
            log("  " + out.strip().splitlines()[-1].replace("NEED_SHIP: ", "") + " — передаю образы с MSK по SSH.")
            ship_images(c, log)
        _, ntag, ftag = image_tags()
        script = (NODE_INSTALL.replace("__NTAG__", ntag).replace("__FTAG__", ftag).replace("__SECRET__", secret)
                  .replace("__MSK4__", msk_addrs(db)[0]).replace("__MSK6__", msk_addrs(db)[1])
                  .replace("__PORT__", str(port)).replace("__NPORT__", str(nport)).replace("__DIR__", w["node_dir"])
                  .replace("__NODE__", w["node_name"]).replace("__FW__", w["fw_name"]).replace("__CHAIN__", fw_chain(w["fw_name"])).replace("__MSKID__", msk_id()))
        try:
            created["remote"] = True
            ssh_run(c, script, log)
        except RuntimeError as ex:
            rc = re.search(r"кодом? (\d+)", str(ex))
            if rc and rc.group(1) in ("17", "18", "19"):
                created.pop("remote")                # the script stopped before touching anything
                raise RuntimeError("пока шла установка, порт, имя контейнера или папка на сервере оказались заняты — "
                                   "добавьте сервер ещё раз, портал предложит свободные значения")
            raise
        if install_fw_key(c):
            log("Ключ для автообновления адреса MSK в файрволе установлен.")
        log("Защита SSH (fail2ban), настройки сети и приём бэкапов MSK…")
        try:
            host_extras(c, db, log)
        except Exception as ex:
            log(f"  не удалось: {ex} — на работу выхода это не влияет")
        time.sleep(5)
        if ip4 and tcp_ok(ip4, nport):
            log("Управление ноды: доступно по IPv4.")
        elif ip6 and tcp_ok(ip6, nport):
            log("IPv4 сервера недоступен из РФ — управление и мост пойдут по IPv6.")
            C.rw("PATCH", "/api/nodes", {"uuid": node["uuid"], "address": f"[{ip6}]"})
        else:
            log(f"ВНИМАНИЕ: порт управления {nport} недоступен ни по IPv4, ни по IPv6 — проверьте позже в панели Remnawave.")
        with C.LOCK:
            db = C.load_db()
            db["exits"][eid] = e
            remember_host(db, host)
            event(db, f"Добавлен сервер {name} (приоритет {prio})")
            C.save_db(db)
        created["db"] = True
        bad = dns_mismatch(e, 0)
        if bad is not None:
            log(f"ВНИМАНИЕ: {host} указывает на {', '.join(bad) or 'ничего'}, а не на {ip4} — обновите A-запись (мост MSK всё равно идёт по IP; DNS может обновляться до суток).")
        log("Обновляю маршрутизацию MSK…")
        apply(db, compute_plan(db))
        with C.LOCK:
            fresh = C.load_db(); fresh["balancer"] = db["balancer"]; C.save_db(fresh)
        log("Жду подключения ноды и проверяю канал (до 2 минут)…")
        for _ in range(24):
            time.sleep(5)
            ok, ms, ipx = probe_port(e["mon_port"])
            if ok:
                log(f"Канал MSK → {name} работает: выход в интернет с IP {ipx}, {ms} мс.")
                break
        else:
            log("ВНИМАНИЕ: канал пока не отвечает. Сервер добавлен; сторож продолжит проверки, статус видно в таблице.")
    except Exception:
        if "node" in created:
            try: C.rw("DELETE", f"/api/nodes/{created['node']}")
            except Exception: pass
        if "profile" in created:
            try: C.rw("DELETE", f"/api/config-profiles/{created['profile']}")
            except Exception: pass
        if "node" in created or "profile" in created:
            log("Изменения в Remnawave откатены.")
        if created.get("db"):
            with C.LOCK:
                db = C.load_db()
                db["exits"].pop(eid, None)
                event(db, f"Добавление сервера {name} отменено из-за ошибки")
                C.save_db(db)
            try:
                apply(db, compute_plan(db))
            except Exception as ex2:
                log(f"  маршрутизация MSK: {ex2}")
        if created.get("remote") and c:
            log("Убираю с сервера то, что успело поставиться…")
            try:
                ssh_run(c, remove_script(e), log)
            except Exception as ex2:
                log(f"  не удалось: {ex2}")
        raise
    finally:
        if c:
            c.close()


def remove_script(e):
    return (NODE_REMOVE.replace("__DIR__", nd(e, "node_dir")).replace("__FW__", nd(e, "fw_name"))
            .replace("__PORT__", str(e.get("port", 443))).replace("__KEY__", portal_pubkey().split()[1]).replace("__MSKID__", msk_id())
            .replace("__BKEY__", backup_pubkey().split()[1]))


def do_delete(log, eid, pw):
    db = C.load_db()
    e = db["exits"].get(eid)
    if not e:
        raise RuntimeError("сервер не найден")
    if len([1 for x in db["exits"].values() if x.get("enabled")]) <= 1 and e.get("enabled"):
        raise C.UserError("нельзя удалить последний включённый выходной сервер")
    with C.LOCK:
        db = C.load_db()
        db["exits"].pop(eid)
        event(db, f"Удалён сервер {e['name']}")
        C.save_db(db)
    log("Убираю сервер из маршрутизации MSK…")
    apply(db, compute_plan(db))
    with C.LOCK:
        fresh = C.load_db(); fresh["balancer"] = db["balancer"]; C.save_db(fresh)
    log("Удаляю ноду и профиль в Remnawave…")
    for path in (f"/api/nodes/{e.get('node_uuid')}", f"/api/config-profiles/{e.get('profile_uuid')}"):
        try:
            C.rw("DELETE", path)
        except Exception as ex:
            log(f"  {ex}")
    STATUS.pop(eid, None); COUNTERS.pop(eid, None)
    manual = f"cd {nd(e, 'node_dir')} && docker compose down && rm -rf {nd(e, 'node_dir')}"
    if pw:
        log(f"Удаляю ноду с самого сервера по SSH ({nd(e, 'node_dir')})…")
        c = None
        for h in (e.get("ip4"), e.get("ip6")):
            if not h:
                continue
            try:
                c = ssh_connect(h, 22, pw)
                break
            except Exception as ex:
                log(f"  {h}: {ex}")
        if c:
            ssh_run(c, remove_script(e), log)
            c.close()
        else:
            log(f"  не удалось подключиться — удалите на сервере вручную: {manual}")
    else:
        log(f"Пароль не указан: на самом сервере нода осталась. Удалите её вручную: {manual}")


def update_address(eid, form):
    """Exit server got a new IP: store it, point the Remnawave node and the MSK bridge to it. No reinstall."""
    import ipaddress
    ip4, ip6, host = form.get("ip4", "").strip(), form.get("ip6", "").strip(), form.get("host", "").strip()
    if host and not norm_host(host):
        raise RuntimeError(f"некорректный домен: {host}")
    host = norm_host(host)
    if host and not (ip4 or ip6):                # only a domain: take its current A/AAAA
        d4, d6 = resolve(host, ttl=0)
        if not (d4 or d6):
            raise RuntimeError(f"домен {host} не резолвится — укажите IP")
        ip4, ip6 = (d4[0] if d4 else ""), (d6[0] if d6 else "")
    if ip4 and not valid_ip(ip4, 4):
        raise RuntimeError(f"некорректный IPv4: {ip4}")
    cand6 = [ip6] if valid_ip(ip6, 6) else []
    if not cand6 and "/" in ip6:
        net = ipaddress.ip_network(ip6, strict=False)
        cand6 = [str(net.network_address + 2), str(net.network_address + 1)]
    elif ip6 and not cand6:
        raise RuntimeError(f"некорректный IPv6: {ip6}")
    if not (ip4 or cand6):
        raise RuntimeError("укажите новый IPv4 и/или IPv6")
    np_ = nd(C.load_db()["exits"].get(eid) or {}, "node_port")
    ip6 = next((a for a in cand6 if tcp_ok(a, np_)), cand6[0] if cand6 else "")
    with C.LOCK:
        db = C.load_db()
        e = db["exits"].get(eid)
        if not e:
            raise RuntimeError("сервер не найден")
        old = f"{e.get('ip4') or '—'} / {e.get('ip6') or '—'}"
        e["ip4"], e["ip6"], e["host"] = ip4, ip6, host
        remember_host(db, host)
        event(db, f"{e['name']}: новый адрес {ip4 or '—'} / {ip6 or '—'} (был {old})")
        C.save_db(db)
    if ip4 and tcp_ok(ip4, np_):
        addr, how = ip4, "по IPv4"
    elif ip6 and tcp_ok(ip6, np_):
        addr, how = f"[{ip6}]", "по IPv6"
    else:
        addr, how = (ip4 or f"[{ip6}]"), None
    if e.get("node_uuid"):
        C.rw("PATCH", "/api/nodes", {"uuid": e["node_uuid"], "address": addr})
    apply(db, compute_plan(db))
    with C.LOCK:
        fresh = C.load_db(); fresh["balancer"] = db["balancer"]; C.save_db(fresh)
    STATUS.pop(eid, None); COUNTERS.pop(eid, None)
    bad = dns_mismatch(e, 0)
    dns = (f" Внимание: {host} указывает на {', '.join(bad) or 'ничего'}, а не на {ip4} — обновите A-запись "
           "(мост MSK идёт по IP, DNS может обновляться до суток)." if bad is not None else "")
    if how:
        return f"Адрес обновлён, управление нодой доступно {how}. Канал проверится в течение минуты." + dns
    return (f"Адрес сохранён, но порт управления {np_} по новым адресам недоступен с MSK: проверьте адрес "
            "и что на сервере в файрволе разрешён текущий адрес MSK.")


def update_exit(eid, form):
    with C.LOCK:
        db = C.load_db()
        e = db["exits"].get(eid)
        if not e:
            raise RuntimeError("сервер не найден")
        changes = []
        if "priority" in form:
            p = int(form["priority"])
            if p != e["priority"]:
                changes.append(f"приоритет {e['priority']} → {p}")
                e["priority"] = p
        if "name" in form and form["name"].strip() and form["name"].strip() != e["name"]:
            e["name"] = form["name"].strip()[:40]
        if "toggle" in form:
            if e["enabled"] and len([1 for x in db["exits"].values() if x.get("enabled")]) <= 1:
                raise RuntimeError("нельзя отключить последний включённый выходной сервер")
            e["enabled"] = not e["enabled"]
            changes.append("включён" if e["enabled"] else "выведен из работы")
        if changes:
            event(db, f"{e['name']}: " + ", ".join(changes))
        C.save_db(db)
    plan = compute_plan(db)
    apply(db, plan)
    with C.LOCK:
        fresh = C.load_db(); fresh["balancer"] = db["balancer"]; C.save_db(fresh)


# ---------------------------------------------------------------- page
def role_of(db, eid):
    plan = db.get("balancer", {}).get("plan") or {}
    e = db["exits"][eid]
    if not e.get("enabled"):
        return "no", "выведен из работы"
    down = not any(is_up(i) for i in plan.get("primary") or [])
    if eid in (plan.get("primary") or []):
        return ("off", "основной — недоступен, трафик идёт через резерв") if down else ("on", "основной — трафик идёт сюда")
    if down and plan.get("fallback") == eid:
        return "on", "резерв — трафик идёт сюда"
    order = [i for i, x in exits_sorted(db, True) if i not in (plan.get("primary") or [])]
    n = order.index(eid) + 1 if eid in order else "?"
    return ("warnp" if not is_up(eid) else "no"), f"резерв {n}" + (" (следующий)" if plan.get("fallback") == eid else "")


def render(msg=None, err=None, jid=None, readonly=False):
    esc = C.esc
    db = C.load_db()
    nodes = {}
    try:
        nodes = {n["uuid"]: n for n in C.rw("GET", "/api/nodes")}
    except Exception:
        pass

    def pill(v, yes="да", no="нет", none="—"):
        if v is None:
            return f'<span class="pill no">{none}</span>'
        return f'<span class="pill {"on" if v else "off"}">{yes if v else no}</span>'

    rows = ""
    for eid, e in exits_sorted(db):
        s = STATUS.get(eid, {})
        n = nodes.get(e.get("node_uuid"), {})
        rc, rt = role_of(db, eid)
        addr = esc(e.get("host") or e.get("ip4") or "")
        if e.get("host") and e.get("ip4"):
            addr += f'<div class="mut">{esc(e["ip4"])}</div>'
            bad = dns_mismatch(e)
            if bad is not None:
                addr += (f'<div class="mut" style="color:#e0a040" title="мост MSK идёт по IP, на работу не влияет; '
                         f'DNS может обновляться до суток">DNS → {esc(", ".join(bad) or "не резолвится")}</div>')
        if e.get("ip6"):
            addr += f'<div class="mut">{esc(e["ip6"])}</div>'
        toggle = "Вывести из работы" if e.get("enabled") else "Вернуть в работу"
        rows += f"""<tr>
<td><form method="post" action="/admin/servers/{eid}/update" class="row" style="gap:6px;flex-wrap:nowrap">
<input type="text" name="priority" value="{e['priority']}" style="width:56px;text-align:center" inputmode="numeric">
<button class="btn sm alt" style="margin:0">ОК</button></form></td>
<td><div class="nm">{esc(e['name'])}</div><div class="mut">{esc(e.get('cc',''))} · id {esc(eid)} · SNI {esc(e['sni'])}</div></td>
<td>{addr}</td>
<td><span class="pill {rc}">{esc(rt)}</span></td>
<td>{pill(s.get('ok'), 'работает', 'недоступен', 'проверка…')}
<div class="mut">{(str(s.get('ms')) + ' мс') if s.get('ok') else ''} {esc(s.get('ip') or '')}</div></td>
<td class="hide-sm">IPv4 {pill(s.get('v4'), 'ок', 'нет')}<br>IPv6 {pill(s.get('v6'), 'ок', 'нет')}</td>
<td class="hide-sm">{pill(n.get('isConnected'), 'online', 'offline')}<div class="mut">{C.gb(n.get('trafficUsedBytes'))}</div></td>
<td><form method="post" action="/admin/servers/{eid}/update" style="display:inline"><input type="hidden" name="toggle" value="1">
<button class="btn sm alt">{toggle}</button></form>
<details style="display:inline-block"><summary class="btn sm alt" style="list-style:none">Адрес…</summary>
<form method="post" action="/admin/servers/{eid}/address" class="addr" style="margin-top:8px;min-width:220px">
<input type="text" name="ip4" value="{esc(e.get('ip4') or '')}" placeholder="IPv4" style="margin-bottom:6px">
<input type="text" name="ip6" value="{esc(e.get('ip6') or '')}" placeholder="IPv6 (можно подсеть /48)" style="margin-bottom:6px">
<input type="text" name="host" value="{esc(e.get('host') or '')}" placeholder="домен (необязательно)" list="dl-{eid}" style="margin-bottom:6px"><datalist id="dl-{eid}"></datalist>
<div class="mut lk" style="margin-bottom:6px"></div>
<button class="btn sm">Сохранить адрес</button>
<div class="mut">Если хостер сменил IP сервера. Переустановка не нужна.</div></form></details>
<details style="display:inline-block"><summary class="btn sm danger" style="list-style:none">Удалить…</summary>
<form method="post" action="/admin/servers/{eid}/delete" style="margin-top:8px" onsubmit="return confirm({esc(json.dumps('Удалить сервер ' + e['name'] + '?', ensure_ascii=False))})">
<input type="password" name="password" placeholder="root-пароль сервера (необязательно)" style="margin-bottom:6px">
<button class="btn sm danger">Удалить сервер</button>
<div class="mut">С паролем нода будет удалена и с самого сервера.</div></form></details></td></tr>"""

    if readonly:   # moderator: same table, no controls
        rows = re.sub(r'<form method="post" action="/admin/servers/[a-z0-9]+/update" class="row".*?value="(\d+)".*?</form>',
                      r'<b>\1</b>', rows, flags=re.S)
        rows = re.sub(r"<details.*?</details>", "", rows, flags=re.S)
        rows = re.sub(r'<form method="post".*?</form>', "", rows, flags=re.S)
    plan = db.get("balancer", {}).get("plan") or {}
    chain = ["Клиенты", "MSK (вход)"]
    en = exits_sorted(db, True)
    prim = plan.get("primary") or []
    chain.append("<b>" + esc(names(db, prim)) + "</b>")
    others = [i for i, _ in sorted(en, key=lambda kv: (not is_up(kv[0]), kv[1]["priority"])) if i not in prim]
    chain_html = " → ".join(chain) + (" ⇢ " + " ⇢ ".join(esc(db["exits"][i]["name"]) for i in others) if others else "")
    events = "".join(f'<div class="kv"><span>{C.fmt_date(C.parse_ts(ev["ts"]))} {C.parse_ts(ev["ts"]).astimezone(dt.timezone(dt.timedelta(hours=3))).strftime("%H:%M")}</span>'
                     f'<span style="text-align:right">{esc(ev["text"])}</span></div>'
                     for ev in db.get("balancer", {}).get("events", [])[:15]) or '<span class="mut">пока пусто</span>'

    n_ev = len(db.get("balancer", {}).get("events", []))
    errs = db.get("errors", [])
    msk_tz = dt.timezone(dt.timedelta(hours=3))
    recent_err = sum(1 for x in errs if (C.now_utc() - C.parse_ts(x["last"])).total_seconds() < 86400)
    last_err = (f'последняя: {C.ago(C.parse_ts(errs[0]["last"]))}' if errs else "")
    errors_html = "".join(
        f'<div class="kv"><span style="white-space:nowrap">{C.parse_ts(x["ts"]).astimezone(msk_tz).strftime("%d.%m %H:%M")}</span>'
        f'<span style="text-align:right">{esc(x["text"])}'
        + (f' <span class="pill warnp">×{x["count"]}, посл. {C.parse_ts(x["last"]).astimezone(msk_tz).strftime("%d.%m %H:%M")}</span>' if x.get("count", 1) > 1 else "")
        + '</span></div>' for x in errs[:30]) or '<span class="mut">ошибок нет</span>'
    jobhtml, refresh = "", ""
    if jid and jid in JOBS:
        j = JOBS[jid]
        pend = PENDING.get(j.get("confirm") or "")
        state_ = ("выполняется…" if not j["done"] else "нужно подтверждение" if pend
                  else "остановлено до подтверждения" if j.get("confirm") else "успешно" if j["ok"] else "с ошибкой")
        jobhtml = (f'<div class="card"><h2>{esc(j["title"])} — {state_}</h2>'
                   f'<code style="max-height:none;white-space:pre-wrap">{esc(chr(10).join(j["log"]) or "…")}</code>'
                   + (confirm_form(j["confirm"], pend) if pend and not readonly else "") + '</div>')
        if not j["done"]:
            refresh = '<meta http-equiv="refresh" content="3">'
    alert = f'<div class="card ok">{esc(msg)}</div>' if msg else ""
    alert += f'<div class="card err">{esc(err)}</div>' if err else ""
    sni_opts = "".join(f'<option value="{s}">{s}</option>' for s in SNI_CHOICES)
    s4, s6 = msk_addrs(db)
    d4, d6 = detect_msk_addrs()
    dns = dns_a(MSK_DOMAIN)
    dns_ok = s4 in dns
    add_card = f"""<div class="card"><h2>Добавить сервер</h2>
<form method="post" action="/admin/servers/add" class="addr">
<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr))">
<label>Название<input type="text" name="name" required maxlength="40" placeholder="Франкфурт"></label>
<label>Код страны<input type="text" name="cc" maxlength="2" placeholder="DE"></label>
<label>Домен<input type="text" name="host" placeholder="exit3.example.com" list="dl-add"><datalist id="dl-add"></datalist></label>
<label>IPv4<input type="text" name="ip4" placeholder="из DNS или 1.2.3.4"></label>
<label>IPv6 (желательно)<input type="text" name="ip6" placeholder="из DNS или 2a01:…::2"></label>
<div class="mut lk" style="grid-column:1/-1;min-height:1.2em"></div>
<label>Приоритет<input type="text" name="priority" value="{max([e['priority'] for e in db.get('exits', {}).values()] + [0]) + 1}"></label>
<label>Сайт-маскировка Reality<select name="sni" style="font:inherit;color:#e8e8e8;background:#0e1015;border:1px solid #343a48;border-radius:8px;padding:9px 12px;width:100%">{sni_opts}</select></label>
<label>Порт Reality<input type="text" name="port" value="443"></label>
<label>SSH-порт<input type="text" name="sshport" value="22"></label>
<label>root-пароль<input type="password" name="password" required></label>
</div>
<button class="btn" style="margin-top:14px">Добавить и установить</button>
<p class="note">Портал подключится к серверу по SSH, поставит Docker и ноду Remnawave, закроет порт управления для всех,
кроме MSK, создаст ключи и включит сервер в цепочку. Пароль используется один раз и нигде не сохраняется.
Достаточно указать домен — IPv4/IPv6 подтянутся из DNS (и сверятся с самим сервером),
или IP — портал подскажет домены, которые на него указывают. Требования: чистый Linux-сервер (Ubuntu/Debian) вне РФ, свободный порт Reality. Если IPv4 сервера окажется заблокирован
в РФ, мост автоматически пойдёт по IPv6.</p></form></div>
"""
    msk_card = (f'<div class="kv"><span>Адрес MSK (разрешён в файрволах выходов)</span><span>{esc(s4)} · {esc(s6 or "—")}</span></div>'
                f'<div class="kv"><span>Фактический адрес сервера</span><span>{esc(d4 or "?")} · {esc(d6 or "—")}</span></div>'
                f'<div class="kv"><span>DNS {MSK_DOMAIN}</span><span><span class="pill {"on" if dns_ok else "off"}">'
                f'{esc(", ".join(dns) or "не резолвится")}</span></span></div>'
                + ('' if dns_ok else f'<div class="card err" style="margin:10px 0 0">A-запись {MSK_DOMAIN} указывает не на текущий IP MSK '
                   f'({esc(s4)}). Клиенты не смогут подключиться, пока её не исправить в DNS (Timeweb).</div>')
                + ('' if readonly else '<form method="post" action="/admin/servers/msk-push" style="margin-top:10px">'
                  '<button class="btn sm alt">Разослать адрес MSK на выходы сейчас</button></form>')
                + '<p class="note">Если у MSK сменится IP, сторож сам заметит это в течение минуты и обновит адрес в файрволах '
                  'всех выходов (ограниченным ключом, который умеет только это), а здесь появится напоминание сменить A-запись в DNS. '
                  'Ссылки у пользователей не меняются — они указывают на домен.</p>')
    body = f"""{refresh}<div class="wrap">
<h1>{C.BRAND} — серверы</h1>
<div class="sub"><a class="inline" href="/admin">← пользователи и мониторинг</a> · <a class="inline" href="/admin/servers">обновить</a></div>
{alert}{jobhtml}
{'<div class="card"><span class="pill no">режим просмотра</span> <span class="mut">вход модератора: управление серверами доступно только администратору</span></div>' if readonly else ''}
<div class="card"><h2>Цепочка сейчас</h2><p class="hint" style="font-size:1rem">{chain_html}</p>
<p class="note">Сплошная стрелка — куда идёт трафик сейчас, пунктир — очередь резерва. Сторож проверяет каждый сервер
раз в {PROBE_EVERY} с; сервер считается упавшим после {FAILS_TO_DOWN} неудачных проверок подряд и возвращается после {OKS_TO_UP} удачных.
Мгновенно (за ~15–20 с) трафик уходит на следующий резерв средствами xray, затем сторож перестраивает очередь.
Каждое перестроение перезапускает xray на MSK — у клиентов возможен разрыв на 1–2 секунды.</p></div>
<div class="card"><h2>Выходные серверы</h2><div class="scroll"><table>
<tr><th>Приоритет</th><th>Сервер</th><th>Адреса</th><th>Роль</th><th>Канал с MSK</th><th class="hide-sm">Семейства</th><th class="hide-sm">Нода</th><th>Действия</th></tr>
{rows or '<tr><td colspan="8" class="mut">нет серверов</td></tr>'}</table></div>
<p class="note"><b>Приоритет:</b> 1 — основной, 2 — первый резерв и т. д. Серверы с одинаковым приоритетом работают вместе:
трафик идёт через тот, у которого меньше задержка. «Вывести из работы» — сервер остаётся настроенным, но трафик на него не идёт.</p></div>
{"" if readonly else add_card}<details class="card" style="padding:14px 18px"><summary style="cursor:pointer;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
<b>Журнал</b> <span class="mut">переключений: {n_ev}</span>
<span class="pill {"off" if recent_err else "no"}">ошибок за сутки: {recent_err}</span>
<span class="mut">{last_err}</span></summary>
<div class="grid" style="margin-top:14px;grid-template-columns:repeat(auto-fit,minmax(320px,1fr))">
<div class="card"><h2>Переключения</h2>{events}</div>
<div class="card"><h2>Критические ошибки</h2>{errors_html}</div></div></details>
<div class="card"><h2>Вход MSK</h2>{msk_card}</div>
</div>"""
    return C.page(f"{C.BRAND} — серверы", body, ADDR_JS)


# ---------------------------------------------------------------- HTTP handlers (called from app.H)
def confirm_form(token, pend):
    esc, sg = C.esc, pend["sug"]
    fld = lambda k, label, hint: (f'<label>{label}<input type="text" name="{k}" value="{esc(str(sg[k]))}" required>'
                                  f'<span class="mut" style="font-size:.8rem">{hint}</span></label>')
    return f"""<form method="post" action="/admin/servers/add-confirm" style="margin-top:14px">
<input type="hidden" name="token" value="{esc(token)}">
<p><b>На сервере занято:</b></p><ul>{"".join(f"<li>{esc(x)}</li>" for x in pend["conflicts"])}</ul>
<p>Портал подобрал свободные значения — можно оставить их или ввести свои:</p>
<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(210px,1fr))">
{fld("port", "Порт Reality (tcp)", "на него подключается MSK")}
{fld("node_port", "Порт управления нодой (tcp)", "открыт только для MSK")}
{fld("node_name", "Имя контейнера ноды", "латиница, цифры, - _ .")}
{fld("fw_name", "Имя контейнера файрвола", "латиница, цифры, - _ .")}
{fld("node_dir", "Папка установки", "только /opt/имя")}
</div>
<button class="btn" style="margin-top:14px">Установить с этими значениями</button>
<a class="inline" href="/admin/servers" style="margin-left:12px">отмена</a>
<p class="note">Существующие контейнеры и программы на сервере не затрагиваются. Значения проверятся ещё раз перед установкой;
если что-то снова окажется занято — портал предложит другое. Форма действует 15 минут, пароль хранится только в памяти до подтверждения.</p>
</form>"""


ADDR_JS = r"""
document.querySelectorAll('form.addr').forEach(function (f) {
  var h = f.elements.host, v4 = f.elements.ip4, v6 = f.elements.ip6, lk = f.querySelector('.lk'), dl = h.list;
  function get(q, cb) { fetch('/admin/servers/lookup?' + q, {credentials: 'same-origin'}).then(function (r) { return r.json(); }).then(cb, function () {}); }
  function note(t) { if (lk) lk.textContent = t; }
  h.addEventListener('change', function () {
    var d = h.value.trim(); if (!d) return;
    note('DNS: смотрю ' + d + '…');
    get('host=' + encodeURIComponent(d), function (r) {
      if (r.error) return note(r.error);
      if (!v4.value.trim() && r.v4.length) v4.value = r.v4[0];
      if (!v6.value.trim() && r.v6.length) v6.value = r.v6[0];
      var t = 'DNS ' + r.host + ': A ' + (r.v4.join(', ') || '—') + ', AAAA ' + (r.v6.join(', ') || '—');
      var ip = v4.value.trim();
      if (ip && r.v4.length && r.v4.indexOf(ip) < 0) t += ' — не совпадает с IPv4 ' + ip + ' (после смены IP DNS обновляется до суток; мост идёт по IP)';
      note(t);
    });
  });
  [v4, v6].forEach(function (inp) {
    inp.addEventListener('change', function () {
      var ip = inp.value.trim(); if (!ip || ip.indexOf('/') >= 0) return;
      note('Ищу домены для ' + ip + '…');
      get('ip=' + encodeURIComponent(ip), function (r) {
        if (r.error) return note(r.error);
        var all = r.match.concat(r.ptr ? [r.ptr] : []);
        dl.innerHTML = ''; all.forEach(function (n) { var o = document.createElement('option'); o.value = n; dl.appendChild(o); });
        if (!all.length) return note('Доменов на ' + ip + ' среди известных зон не найдено');
        if (!h.value.trim() && r.match.length === 1) h.value = r.match[0];
        note('На ' + ip + ' указывают: ' + (r.match.join(', ') || '—') + (r.ptr ? ' · PTR ' + r.ptr : '') + ' — выберите в поле «домен»');
      });
    });
  });
});
"""


def handle_get(h, path, q, readonly=False):
    if path in ("/admin/servers", "/admin/servers/"):
        return h.send(200, render(q.get("msg", [None])[0], q.get("err", [None])[0], q.get("job", [None])[0], readonly))
    if path == "/admin/servers/lookup":
        return h.send(200, json.dumps(lookup({k: v[0] for k, v in q.items()}), ensure_ascii=False), "application/json")
    return None


def handle_post(h, path, form):
    f = {k: v[0] for k, v in form.items()}
    if path == "/admin/servers/add":
        jid = job(f"Добавление сервера «{f.get('name', '')}»", do_add, f)
        return h.redirect(f"/admin/servers?job={jid}")
    if path == "/admin/servers/add-confirm":
        now = time.time()
        for k in [k for k, v in PENDING.items() if v["exp"] < now]:
            PENDING.pop(k, None)
        p = PENDING.pop(f.get("token", ""), None)
        if not p:
            return h.redirect("/admin/servers?err=" + C.quote("Подтверждение устарело — добавьте сервер заново"))
        ff = dict(p["f"])
        ff.update({k: f[k].strip() for k in ("port", "node_port", "node_name", "fw_name", "node_dir") if f.get(k, "").strip()})
        jid = job(f"Добавление сервера «{ff.get('name', '')}»", do_add, ff)
        return h.redirect(f"/admin/servers?job={jid}")
    if path == "/admin/servers/msk-push":
        def do_push(log):
            db = C.load_db()
            v4, v6 = detect_msk_addrs()
            v4, v6 = v4 or msk_addrs(db)[0], v6 or msk_addrs(db)[1]
            log(f"Адрес MSK: {v4} / {v6 or '—'}")
            res = push_msk_addrs(db, v4, v6, log)
            with C.LOCK:
                fresh = C.load_db(); fresh["msk"] = {"v4": v4, "v6": v6}; C.save_db(fresh)
            if not all(res.values()):
                raise RuntimeError("не на всех выходах удалось обновить адрес (см. выше)")
        jid = job("Рассылка адреса MSK на выходы", do_push)
        return h.redirect(f"/admin/servers?job={jid}")
    m = re.fullmatch(r"/admin/servers/([a-z0-9]+)/(update|delete|address)", path)
    if m:
        eid, act = m.groups()
        if act == "address":
            return h.redirect("/admin/servers?msg=" + C.quote(update_address(eid, f)))
        if act == "delete":
            jid = job(f"Удаление сервера {eid}", do_delete, eid, f.get("password", ""))
            return h.redirect(f"/admin/servers?job={jid}")
        update_exit(eid, f)
        return h.redirect("/admin/servers?msg=" + C.quote("Сохранено, маршрутизация обновлена"))
    return None
