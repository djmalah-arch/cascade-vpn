"""GeoVPN portal: exit servers management (/admin/servers).

The portal owns the MSK xray profile: it is generated from db["exits"] (priority, enabled, keys).
A watchdog probes every exit (via per-exit local inbounds on MSK) and rebuilds the chain
primary -> reserve 1 -> reserve 2 ... when availability changes.
"""
import datetime as dt, json, re, secrets, socket, threading, time, traceback
from concurrent.futures import ThreadPoolExecutor

import app as C

MSK_DOMAIN = C.HOST
CERT = f"/var/lib/remnawave/configs/xray/ssl/{MSK_DOMAIN}"   # Caddy's Let's Encrypt cert, mounted into the node
SNI_CHOICES = ["www.samsung.com", "www.asus.com", "dl.google.com", "www.microsoft.com", "www.apple.com", "www.booking.com"]
PROBE_EVERY = 30
FAILS_TO_DOWN, OKS_TO_UP = 2, 2

PORTAL_KEY = C.P("ssh/geovpn_portal", "/root/.ssh/geovpn_portal")  # restricted key: only updates MSK address in exits' firewall

# the portal key in exits' authorized_keys is forced to run this: it can only set MSK's address in the fw container
FW_CMD = "docker exec -e SSH_ORIGINAL_COMMAND geovpn-fw /conf/fw.sh set"

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
    """On an exit (open paramiko session as root): add the restricted portal key (runs FW_CMD only)."""
    line = (f'command="{FW_CMD}",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ' + portal_pubkey())
    _, o, _ = c.exec_command("mkdir -p /root/.ssh && touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"
                             " && sed -i '/geovpn-portal-fw/d' /root/.ssh/authorized_keys"
                             f" && echo '{line}' >> /root/.ssh/authorized_keys && echo ok", timeout=20)
    return o.read().decode().strip() == "ok"


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
    outs = [{"tag": "direct", "protocol": "freedom"},
            # YouTube: MSK DC blocks it over IPv4 -> IPv6 first, IPv4 through zapret
            {"tag": "yt-dpi", "protocol": "freedom", "settings": {"domainStrategy": "ForceIPv6v4"}}]
    bals, rules = [], [{"inboundTag": ["MON_YT"], "outboundTag": "yt-dpi"}]
    for eid, e in exits_sorted(db):
        tags = out_tags(eid, e)
        if not tags:
            continue
        if e.get("host") or e.get("ip4"):
            outs.append(bridge_out(f"x-{eid}-4", e.get("host") or e["ip4"], e, st["bridge_uuid"]))
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
    return {"log": {"loglevel": "warning"}, "inbounds": inb, "outbounds": outs,
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
        for n in ([] if quiet else C.rw("GET", "/api/nodes")):
            if not n.get("isConnected") and not n.get("isDisabled"):
                C.log_error(f"Нода {n['name']} ({n['address']}) не на связи с панелью: {(n.get('lastStatusMessage') or '')[:160]}")
    except Exception as ex:
        if not quiet:
            C.log_error(f"Панель Remnawave не отвечает: {ex}")
    probe_all(db)
    plan = compute_plan(db)
    old = db["balancer"].get("plan")
    if plan != old:
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

    def run():
        try:
            fn(log, *args)
            JOBS[jid]["ok"] = True
            log("Готово.")
        except Exception as e:
            log("ОШИБКА: " + str(e))
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


NODE_INSTALL = r"""
set -e
export DEBIAN_FRONTEND=noninteractive
if ss -ltn | grep -qE '[:.]__PORT__ '; then echo "PORT_BUSY"; exit 17; fi
command -v docker >/dev/null || (curl -fsSL https://get.docker.com | sh >/dev/null 2>&1)
cat >/etc/sysctl.d/99-geovpn.conf <<'X'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
X
sysctl --system >/dev/null 2>&1 || true
# everything else lives in /opt/remnanode and runs in docker: remnanode + geovpn-fw (node port 2222 only from MSK)
mkdir -p /opt/remnanode/fw
cat >/opt/remnanode/docker-compose.yml <<'X'
services:
  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: __IMAGE__
    restart: always
    network_mode: host
    cap_add: [NET_ADMIN]
    ulimits:
      nofile: { soft: 1048576, hard: 1048576 }
    environment:
      - NODE_PORT=2222
      - SECRET_KEY=__SECRET__
    depends_on: [geovpn-fw]
  geovpn-fw:
    container_name: geovpn-fw
    image: geovpn/fw
    build:
      dockerfile_inline: |
        FROM debian:trixie-slim
        RUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/*
    restart: always
    network_mode: host
    cap_add: [NET_ADMIN, NET_RAW]
    volumes: ["./fw:/conf"]
    command: ["/conf/fw.sh", "loop"]
X
[ -f /opt/remnanode/fw/fw.env ] || printf 'ALLOW="%s"\nALLOW6="%s"\n' "__MSK4__" "__MSK6__" >/opt/remnanode/fw/fw.env
cat >/opt/remnanode/fw/fw.sh <<'X'
#!/bin/bash
# geovpn-fw container: node API port 2222 is reachable only from the MSK entry server.
#   fw.sh loop  - apply rules, re-apply if something (ufw reload, reboot) removed them
#   fw.sh set   - "set-msk <ipv4> <ipv6|->" from the restricted portal SSH key (SSH_ORIGINAL_COMMAND)
#   fw.sh clear - remove the rules (node removal)
apply() {
  . /conf/fw.env
  for T in iptables ip6tables; do
    $T -D INPUT -p tcp --dport 2222 -j GEOVPN_NODE 2>/dev/null
    $T -F GEOVPN_NODE 2>/dev/null || $T -N GEOVPN_NODE
    if [ $T = iptables ]; then L=$ALLOW; else L=$ALLOW6; fi
    for s in $L; do $T -A GEOVPN_NODE -s "$s" -j ACCEPT; done   # ACCEPT, not RETURN: host firewalls (ufw) drop the rest
    $T -A GEOVPN_NODE -j DROP
    $T -I INPUT -p tcp --dport 2222 -j GEOVPN_NODE
  done
}
case "$1" in
  set)
    read -r cmd v4 v6 extra <<< "$SSH_ORIGINAL_COMMAND"
    [ "$cmd" = set-msk ] && [ -z "$extra" ] || { echo "denied"; exit 1; }
    [ "$v6" = - ] && v6=""
    [[ $v4 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { [ -z "$v6" ] || [[ $v6 =~ ^[0-9a-fA-F:]{2,39}$ ]]; } || { echo "bad address"; exit 1; }
    printf 'ALLOW="%s"\nALLOW6="%s"\n' "$v4" "$v6" >/conf/fw.env
    apply && echo "ok $v4 ${v6:--}" ;;
  clear)
    for T in iptables ip6tables; do $T -D INPUT -p tcp --dport 2222 -j GEOVPN_NODE 2>/dev/null; $T -F GEOVPN_NODE 2>/dev/null; $T -X GEOVPN_NODE 2>/dev/null; done ;;
  loop)
    apply; echo "fw: 2222 allowed only from MSK"
    while :; do
      sleep 30 & wait $!
      iptables -C INPUT -p tcp --dport 2222 -j GEOVPN_NODE 2>/dev/null && ip6tables -C INPUT -p tcp --dport 2222 -j GEOVPN_NODE 2>/dev/null || { apply; echo "fw: rules restored"; }
    done ;;
esac
X
chmod +x /opt/remnanode/fw/fw.sh
cd /opt/remnanode && docker compose build -q geovpn-fw && docker compose pull -q remnanode && docker compose up -d 2>&1 | tail -1
sleep 2; docker exec geovpn-fw iptables -C INPUT -p tcp --dport 2222 -j GEOVPN_NODE
echo "node installed on $(hostname)"
"""

NODE_REMOVE = r"""
cd /opt/remnanode 2>/dev/null && { docker exec geovpn-fw /conf/fw.sh clear 2>/dev/null; docker compose down --rmi local 2>&1 | tail -1; }
rm -rf /opt/remnanode
sed -i '/geovpn-portal-fw/d' /root/.ssh/authorized_keys 2>/dev/null
# older installs: host-level firewall unit
systemctl disable --now geovpn-fw >/dev/null 2>&1 || true
for T in iptables ip6tables; do $T -D INPUT -p tcp --dport 2222 -j GEOVPN_NODE 2>/dev/null; $T -F GEOVPN_NODE 2>/dev/null; $T -X GEOVPN_NODE 2>/dev/null; done
rm -f /usr/local/bin/geovpn-fw.sh /usr/local/bin/geovpn-fw-set /etc/systemd/system/geovpn-fw.service
systemctl daemon-reload
echo "node removed from $(hostname)"
"""


def node_image():
    import os
    if os.environ.get("NODE_IMAGE"):
        return os.environ["NODE_IMAGE"]
    t = open("/opt/remnanode/docker-compose.yml").read()
    return re.search(r"image:\s*(\S+)", t).group(1)


def do_add(log, f):
    name = " ".join(f["name"].split())[:40]
    cc = (f.get("cc") or "").upper()[:2]
    ip4, ip6, host = f.get("ip4", "").strip(), f.get("ip6", "").strip(), f.get("host", "").strip()
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
    sshport, port = int(f.get("sshport") or 22), int(f.get("port") or 443)
    if not name or not (ip4 or ip6) or not pw:
        raise RuntimeError("Нужны название, корректный IPv4 или IPv6-адрес сервера и root-пароль "
                           "(в поле IPv6 — адрес сервера, например 2a12:…::2, а не подсеть /48)")
    db = C.load_db()
    eid = re.sub(r"[^a-z0-9]", "", C.slugify(name))[:8] or "exit"
    base, n = eid, 2
    while eid in db.get("exits", {}):
        eid, n = f"{base}{n}", n + 1
    created = {}
    try:
        c, errs = None, []
        for target in ([ip4] if ip4 else []) + ip6_try:
            log(f"Подключаюсь по SSH к {target}…")
            try:
                c = ssh_connect(target, sshport, pw)
                if ":" in target:
                    ip6 = target
                break
            except Exception as ex:
                errs.append(f"{target}: {ex}")
                log(f"  не отвечает ({ex})")
        if not c:
            raise RuntimeError("не удалось подключиться по SSH (" + "; ".join(errs) + "). Если IPv4 сервера "
                               "заблокирован в РФ, укажите его IPv6-адрес (например 2a12:…::2) — портал подключится по нему")
        d4, d6 = detect_addrs(c)
        if d6 and valid_ip(d6, 6) and d6 != ip6:
            log(f"  IPv6 сервера: {d6}" + (f" (в форме было {f.get('ip6')})" if f.get("ip6") else ""))
            ip6 = d6
        if not ip4 and valid_ip(d4, 4) and not d4.startswith(("10.", "192.168.", "172.")):
            ip4 = d4
        log("SSH: подключено. Генерирую ключи Reality…")
        kp = C.rw("GET", "/api/system/tools/x25519/generate")["keypairs"][0]
        e = {"name": name, "cc": cc, "host": host, "ip4": ip4, "ip6": ip6, "port": port, "sni": sni,
             "priv": kp["privateKey"], "pub": kp["publicKey"], "sid": secrets.token_hex(8), "priority": prio,
             "enabled": True, "mon_port": max([x["mon_port"] for x in db["exits"].values()] + [10809]) + 1,
             "created": C.now_utc().isoformat()}
        if e["mon_port"] in (10803, 10808):
            e["mon_port"] = 10820
        log("Создаю профиль и ноду в Remnawave…")
        prof = C.rw("POST", "/api/config-profiles", {"name": f"EXIT-{eid.upper()}", "config": exit_profile(eid, e)})
        created["profile"] = e["profile_uuid"] = prof["uuid"]
        node = C.rw("POST", "/api/nodes", {"name": f"EXIT-{eid.upper()}", "address": ip4 or f"[{ip6}]", "port": 2222,
                                           "countryCode": cc or "XX",
                                           "configProfile": {"activeConfigProfileUuid": prof["uuid"],
                                                             "activeInbounds": [i["uuid"] for i in prof["inbounds"]]}})
        created["node"] = e["node_uuid"] = node["uuid"]
        secret = C.rw("GET", "/api/keygen")["secretKey"]
        log("Устанавливаю Docker и ноду на сервер (1–3 минуты)…")
        script = (NODE_INSTALL.replace("__IMAGE__", node_image()).replace("__SECRET__", secret)
                  .replace("__MSK4__", msk_addrs(db)[0]).replace("__MSK6__", msk_addrs(db)[1]).replace("__PORT__", str(port)))
        try:
            ssh_run(c, script, log)
            if install_fw_key(c):
                log("Ключ для автообновления адреса MSK в файрволе установлен.")
        except RuntimeError as ex:
            if "PORT_BUSY" in str(ex) or "код 17" in str(ex) or "кодом 17" in str(ex):
                raise RuntimeError(f"порт {port} на сервере уже занят — укажите другой порт Reality")
            raise
        finally:
            c.close()
        time.sleep(5)
        if ip4 and tcp_ok(ip4, 2222):
            log("Управление ноды: доступно по IPv4.")
        elif ip6 and tcp_ok(ip6, 2222):
            log("IPv4 сервера недоступен из РФ — управление и мост пойдут по IPv6.")
            C.rw("PATCH", "/api/nodes", {"uuid": node["uuid"], "address": f"[{ip6}]"})
        else:
            log("ВНИМАНИЕ: порт управления 2222 недоступен ни по IPv4, ни по IPv6 — проверьте позже в панели Remnawave.")
        with C.LOCK:
            db = C.load_db()
            db["exits"][eid] = e
            event(db, f"Добавлен сервер {name} (приоритет {prio})")
            C.save_db(db)
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
        log("Изменения в Remnawave откатены.")
        raise


def do_delete(log, eid, pw):
    db = C.load_db()
    e = db["exits"].get(eid)
    if not e:
        raise RuntimeError("сервер не найден")
    if len([1 for x in db["exits"].values() if x.get("enabled")]) <= 1 and e.get("enabled"):
        raise RuntimeError("нельзя удалить последний включённый выходной сервер")
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
    if pw:
        log("Удаляю ноду с самого сервера по SSH…")
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
            ssh_run(c, NODE_REMOVE, log)
            c.close()
        else:
            log("  не удалось подключиться — остановите контейнер remnanode на сервере вручную.")
    else:
        log("Пароль не указан: на самом сервере контейнер remnanode остался. Остановите его: cd /opt/remnanode && docker compose down")


def update_address(eid, form):
    """Exit server got a new IP: store it, point the Remnawave node and the MSK bridge to it. No reinstall."""
    import ipaddress
    ip4, ip6, host = form.get("ip4", "").strip(), form.get("ip6", "").strip(), form.get("host", "").strip()
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
    ip6 = next((a for a in cand6 if tcp_ok(a, 2222)), cand6[0] if cand6 else "")
    with C.LOCK:
        db = C.load_db()
        e = db["exits"].get(eid)
        if not e:
            raise RuntimeError("сервер не найден")
        old = f"{e.get('ip4') or '—'} / {e.get('ip6') or '—'}"
        e["ip4"], e["ip6"], e["host"] = ip4, ip6, host
        event(db, f"{e['name']}: новый адрес {ip4 or '—'} / {ip6 or '—'} (был {old})")
        C.save_db(db)
    if ip4 and tcp_ok(ip4, 2222):
        addr, how = ip4, "по IPv4"
    elif ip6 and tcp_ok(ip6, 2222):
        addr, how = f"[{ip6}]", "по IPv6"
    else:
        addr, how = (ip4 or f"[{ip6}]"), None
    if e.get("node_uuid"):
        C.rw("PATCH", "/api/nodes", {"uuid": e["node_uuid"], "address": addr})
    apply(db, compute_plan(db))
    with C.LOCK:
        fresh = C.load_db(); fresh["balancer"] = db["balancer"]; C.save_db(fresh)
    STATUS.pop(eid, None); COUNTERS.pop(eid, None)
    if how:
        return f"Адрес обновлён, управление нодой доступно {how}. Канал проверится в течение минуты."
    return ("Адрес сохранён, но порт управления 2222 по новым адресам недоступен с MSK: проверьте адрес "
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
    if eid in (plan.get("primary") or []):
        return "on", "основной — трафик идёт сюда"
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
<form method="post" action="/admin/servers/{eid}/address" style="margin-top:8px;min-width:220px">
<input type="text" name="ip4" value="{esc(e.get('ip4') or '')}" placeholder="IPv4" style="margin-bottom:6px">
<input type="text" name="ip6" value="{esc(e.get('ip6') or '')}" placeholder="IPv6 (можно подсеть /48)" style="margin-bottom:6px">
<input type="text" name="host" value="{esc(e.get('host') or '')}" placeholder="домен (необязательно)" style="margin-bottom:6px">
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
        state_ = "выполняется…" if not j["done"] else ("успешно" if j["ok"] else "с ошибкой")
        jobhtml = (f'<div class="card"><h2>{esc(j["title"])} — {state_}</h2>'
                   f'<code style="max-height:none;white-space:pre-wrap">{esc(chr(10).join(j["log"]) or "…")}</code></div>')
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
<form method="post" action="/admin/servers/add">
<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr))">
<label>Название<input type="text" name="name" required maxlength="40" placeholder="Франкфурт"></label>
<label>Код страны<input type="text" name="cc" maxlength="2" placeholder="DE"></label>
<label>IPv4<input type="text" name="ip4" placeholder="1.2.3.4"></label>
<label>IPv6 (желательно)<input type="text" name="ip6" placeholder="2a01:…::2"></label>
<label>Домен (необязательно)<input type="text" name="host" placeholder="exit3.example.com"></label>
<label>Приоритет<input type="text" name="priority" value="{max([e['priority'] for e in db.get('exits', {}).values()] + [0]) + 1}"></label>
<label>Сайт-маскировка Reality<select name="sni" style="font:inherit;color:#e8e8e8;background:#0e1015;border:1px solid #343a48;border-radius:8px;padding:9px 12px;width:100%">{sni_opts}</select></label>
<label>Порт Reality<input type="text" name="port" value="443"></label>
<label>SSH-порт<input type="text" name="sshport" value="22"></label>
<label>root-пароль<input type="password" name="password" required></label>
</div>
<button class="btn" style="margin-top:14px">Добавить и установить</button>
<p class="note">Портал подключится к серверу по SSH, поставит Docker и ноду Remnawave, закроет порт управления для всех,
кроме MSK, создаст ключи и включит сервер в цепочку. Пароль используется один раз и нигде не сохраняется.
Требования: чистый Linux-сервер (Ubuntu/Debian) вне РФ, свободный порт Reality. Если IPv4 сервера окажется заблокирован
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
    return C.page(f"{C.BRAND} — серверы", body)


# ---------------------------------------------------------------- HTTP handlers (called from app.H)
def handle_get(h, path, q, readonly=False):
    if path in ("/admin/servers", "/admin/servers/"):
        return h.send(200, render(q.get("msg", [None])[0], q.get("err", [None])[0], q.get("job", [None])[0], readonly))
    return None


def handle_post(h, path, form):
    f = {k: v[0] for k, v in form.items()}
    if path == "/admin/servers/add":
        jid = job(f"Добавление сервера «{f.get('name', '')}»", do_add, f)
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
