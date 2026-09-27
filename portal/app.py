#!/usr/bin/env python3
"""GeoVPN portal: admin page (/admin) + personal user pages (/c/<id>).

Remnawave is the source of truth for users (Happ/Hiddify). AmneziaWG peers are owned by this
portal: awg0.conf peers are regenerated from the portal DB for ACTIVE users only.
Listens on 127.0.0.1:8090 behind Caddy (/admin is protected by the Caddy cookie).
"""
import base64, datetime as dt, hashlib, hmac, html, io, json, os, re, secrets, subprocess, sys, threading, time, zlib
import urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

import segno

sys.modules.setdefault("app", sys.modules[__name__])

DATA = os.environ.get("GEOVPN_DATA")     # set in the docker image (/data); unset = legacy host install


def P(docker_rel, legacy):
    return os.path.join(DATA, docker_rel) if DATA else legacy


SITE_ENV = P("geovpn.env", "/etc/geovpn/geovpn.env")


def _site():
    """Per-installation settings (written by the installer): geovpn.env"""
    out = {}
    try:
        for line in open(SITE_ENV, encoding="utf-8"):
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.strip().split("=", 1)
                out[k.strip()] = v.strip().strip('"')
    except OSError:
        pass
    return out


SITE = _site()
HOST = SITE.get("DOMAIN", "vpn.example.com")     # entry server domain (A/AAAA -> MSK)
BASE_URL = f"https://{HOST}"
BRAND = SITE.get("BRAND", "GeoVPN")
import servers  # noqa: E402  (uses this module as `app`; needs HOST defined above)
LISTEN = ("127.0.0.1", 8090)
DB_PATH = P("db.json", "/var/lib/geovpn-portal/db.json")
AWG_DIR = os.environ.get("AWG_DIR", "/etc/amnezia/amneziawg")
AWG_NET = "10.66.66"
APP_DIR = os.environ.get("APP_DIR", "/opt/geovpn-portal/app")
SECRETS = P("secrets.env", "/root/geovpn-secrets.env")
PORTAL_ENV = P("portal.env", "/etc/geovpn/portal.env")   # SERVERS_PASS/USERS_PASS (pbkdf2 salt$hash), SESSION_SECRET
DIRECT_JSON = P("direct.json", "/etc/geovpn/direct.json")
HC_ENV = P("hc.env", "/etc/geovpn/hc.env")
BACKUP_DIR = P("backups", "/root/backups")
SESSION_TTL = 12 * 3600
STATE = P("state.json", "/root/geovpn-state.json")
SERVICE_USERS = {"bridge-msk"}
VALID_DAYS = 365
class UserError(RuntimeError):
    """Expected, user-facing error (bad input, no permission): shown, not written to the critical log."""


MOD_GROUP = "work"          # the only group a moderator sees and creates users in
DEFAULT_GROUP = "general"   # users created before groups existed


def valid_group(g):
    g = (g or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]{1,20}", g):
        raise UserError("название группы: латиница, цифры, - и _, до 20 символов")
    return g


def ugroup(u):
    return u.get("group") or DEFAULT_GROUP
MTP_PORT = int(SITE.get("MTP_PORT", "9443"))  # MTProxy (Telegram), Fake-TLS
MTP_DOMAIN = SITE.get("MTP_DOMAIN", "ya.ru")  # Fake-TLS / masking domain: RU site, clean TLS1.3 record order
MTP_CONF = os.environ.get("MTP_CONF", "/etc/geovpn/mtproxy/config.py")
MTP_METRICS = "http://127.0.0.1:9189/"

LOCK = threading.RLock()
STARTED = time.time()
STARTUP_GRACE = 180  # s after portal start: services are still coming up, don't log health alerts
CACHE = {"users": ([], 0.0), "mon": ({}, 0.0)}


# ---------------------------------------------------------------- helpers
def esc(s):
    return html.escape(str(s if s is not None else ""), quote=True)


def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def parse_ts(s):
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def fmt_date(s):
    t = parse_ts(s) if isinstance(s, str) else s
    return t.astimezone(dt.timezone(dt.timedelta(hours=3))).strftime("%d.%m.%Y") if t else "—"


def ago(t):
    if not t:
        return "никогда"
    sec = (now_utc() - t).total_seconds()
    if sec < 120:
        return "сейчас"
    if sec < 3600:
        return f"{int(sec // 60)} мин назад"
    if sec < 86400:
        return f"{int(sec // 3600)} ч назад"
    return f"{int(sec // 86400)} дн назад"


def gb(b):
    b = b or 0
    if b < 1024 ** 3:
        return f"{b / 1024 ** 2:.0f} МБ"
    return f"{b / 1024 ** 3:.2f} ГБ"


def sh(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=timeout,
                           executable="/bin/bash" if isinstance(cmd, str) else None)
        return r.returncode, r.stdout.strip()
    except subprocess.TimeoutExpired:
        return 124, ""


TR = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
              "a b v g d e e zh z i y k l m n o p r s t u f kh ts ch sh shch _ y _ e yu ya".split()))


def slugify(name):
    s = "".join(TR.get(c, c) for c in name.lower()).replace("_", "")
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return (s[:28].strip("-") or "user")


# ---------------------------------------------------------------- services (docker containers or systemd units)
SERVICES = ({"AmneziaWG": "geovpn-awg", "мост AWG→xray": "geovpn-singbox", "zapret": "geovpn-zapret",
             "MTProxy": "geovpn-mtproxy", "Caddy": "geovpn-caddy", "нода xray": "remnanode",
             "панель": "remnawave", "БД панели": "remnawave-db"} if DATA else
            {"awg-quick@awg0": "awg-quick@awg0", "sing-box": "sing-box", "zapret": "zapret",
             "geovpn-mtproxy": "geovpn-mtproxy", "geovpn-fw": "geovpn-fw", "docker": "docker"})


def svc_active(name):
    if DATA:
        return sh(["docker", "inspect", "-f", "{{.State.Running}}", name])[1] == "true"
    return sh(["systemctl", "is-active", name])[1] == "active"


def svc_signal(name, sig):
    if DATA:
        sh(["docker", "kill", "-s", sig, name])
    else:
        sh(["systemctl", "kill", "-s", "SIG" + sig, name])


# ---------------------------------------------------------------- storage
def load_db():
    if os.path.exists(DB_PATH):
        return json.load(open(DB_PATH, encoding="utf-8"))
    return {"users": {}}


def save_db(db):
    tmp = DB_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, DB_PATH)


def log_error(text):
    """Critical error log shown on /admin/servers. Same message within 30 min -> counter instead of a new line."""
    text = str(text)[:400]
    with LOCK:
        db = load_db()
        errs = db.setdefault("errors", [])
        now = now_utc()
        if errs and errs[0]["text"] == text and (now - parse_ts(errs[0]["last"])).total_seconds() < 1800:
            errs[0]["count"] = errs[0].get("count", 1) + 1
            errs[0]["last"] = now.isoformat()
        else:
            errs.insert(0, {"ts": now.isoformat(), "last": now.isoformat(), "text": text, "count": 1})
            del errs[100:]
        save_db(db)
    print("ERROR-LOG:", text, flush=True)


def env_file(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# ---------------------------------------------------------------- Remnawave API
def rw(method, path, body=None):
    token = env_file(SECRETS)["RW_TOKEN"]
    req = urllib.request.Request(
        "http://127.0.0.1:3000" + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token,
                 "X-Forwarded-For": "127.0.0.1", "X-Forwarded-Proto": "https"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            return json.loads(raw).get("response") if raw.strip() else None
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Remnawave {method} {path}: HTTP {e.code} {e.read().decode()[:300]}")


def rw_users(force=False):
    with LOCK:
        users, ts = CACHE["users"]
        if force or time.time() - ts > 20:
            users = [u for u in rw("GET", "/api/users?start=0&size=1000")["users"] if u["username"] not in SERVICE_USERS]
            CACHE["users"] = (users, time.time())
        return users


def rw_user_by_id(uid):
    return next((u for u in rw_users() if u["id"] == uid), None)


# ---------------------------------------------------------------- AmneziaWG
def awg_params():
    return env_file(f"{AWG_DIR}/params.env")


def awg_server():
    conf = open(f"{AWG_DIR}/awg0.conf", encoding="utf-8").read()
    port = re.search(r"ListenPort\s*=\s*(\d+)", conf).group(1)
    return open(f"{AWG_DIR}/server.pub").read().strip(), port


def awg_keys():
    _, priv = sh(["awg", "genkey"])
    pub = subprocess.run(["awg", "pubkey"], input=priv, capture_output=True, text=True).stdout.strip()
    _, psk = sh(["awg", "genpsk"])
    return priv, pub, psk


def awg_new_peer(db):
    used = {u["awg"]["ip"] for u in db["users"].values() if u.get("awg")}
    for i in range(2, 255):
        ip = f"{AWG_NET}.{i}"
        if ip not in used:
            priv, pub, psk = awg_keys()
            return {"ip": ip, "priv": priv, "pub": pub, "psk": psk}
    raise RuntimeError("Нет свободных адресов AmneziaWG")


def awg_client_conf(peer):
    p = awg_params()
    spub, port = awg_server()
    # MTU 1376 (as AmneziaVPN itself uses): default 1420 breaks big packets on mobile networks with smaller MTU
    lines = ["[Interface]", f"PrivateKey = {peer['priv']}", f"Address = {peer['ip']}/32", "DNS = 1.1.1.1, 1.0.0.1", "MTU = 1376"]
    lines += [f"{k} = {v}" for k, v in p.items()]
    lines += ["", "[Peer]", f"PublicKey = {spub}", f"PresharedKey = {peer['psk']}", f"Endpoint = {HOST}:{port}",
              "AllowedIPs = 0.0.0.0/0", "PersistentKeepalive = 25", ""]
    return "\n".join(lines)


def awg_vpn_key(peer, title):
    """AmneziaVPN import key: vpn:// + base64url(qCompress(json))."""
    p = awg_params()
    spub, port = awg_server()
    conf = awg_client_conf(peer)
    last = dict(p)
    last.update({"allowed_ips": ["0.0.0.0/0"], "clientId": "", "client_ip": peer["ip"], "client_priv_key": peer["priv"],
                 "client_pub_key": peer["pub"], "config": conf, "hostName": HOST, "mtu": "1376",
                 "persistent_keep_alive": "25", "port": int(port), "psk_key": peer["psk"], "server_pub_key": spub})
    awg = dict(p)
    awg.update({"last_config": json.dumps(last, ensure_ascii=False), "port": port, "protocol_version": "2",
                "subnet_address": f"{AWG_NET}.0", "transport_proto": "udp"})
    data = {"containers": [{"awg": awg, "container": "amnezia-awg2"}], "defaultContainer": "amnezia-awg2",
            "description": title, "dns1": "1.1.1.1", "dns2": "1.0.0.1", "hostName": HOST}
    raw = json.dumps(data, ensure_ascii=False).encode()
    blob = len(raw).to_bytes(4, "big") + zlib.compress(raw, 8)
    return "vpn://" + base64.urlsafe_b64encode(blob).decode().rstrip("=")


def awg_apply(db):
    """Rewrite awg0.conf peers = portal users that are ACTIVE in Remnawave, then hot-reload."""
    active = {u["id"] for u in rw_users() if u["status"] == "ACTIVE"}
    path = f"{AWG_DIR}/awg0.conf"
    conf = open(path, encoding="utf-8").read()
    head = conf.split("\n[Peer]")[0].rstrip() + "\n"
    peers = []
    for slug, u in sorted(db["users"].items()):
        if u.get("awg") and u["rw_id"] in active:
            a = u["awg"]
            peers.append(f"\n[Peer]\n# {slug}\nPublicKey = {a['pub']}\nPresharedKey = {a['psk']}\nAllowedIPs = {a['ip']}/32\n")
    new = head + "".join(peers)
    if new != conf:
        with open(path + ".tmp", "w", encoding="utf-8") as f:
            f.write(new)
        os.chmod(path + ".tmp", 0o600)
        os.replace(path + ".tmp", path)
        rc, out = sh("awg syncconf awg0 <(awg-quick strip awg0)")
        if rc != 0:
            raise RuntimeError("awg syncconf failed: " + out)
    mt_apply(db)


def awg_stats():
    rc, out = sh(["awg", "show", "awg0", "dump"])
    stats = {}
    for line in out.splitlines()[1:]:
        f = line.split("\t")
        if len(f) >= 7:
            hs = int(f[4]) if f[4].isdigit() else 0
            stats[f[0]] = {"hs": dt.datetime.fromtimestamp(hs, dt.timezone.utc) if hs else None,
                           "rx": int(f[5]), "tx": int(f[6])}
    return stats


# ---------------------------------------------------------------- MTProxy (Telegram)
def mt_apply(db):
    """Write mtprotoproxy config with secrets of ACTIVE users; hot-reload on change (SIGUSR2)."""
    active = {u["id"] for u in rw_users() if u["status"] == "ACTIVE"}
    users = {slug: u["mt"] for slug, u in sorted(db["users"].items()) if u.get("mt") and u["rw_id"] in active}
    if not users:                       # never let mtprotoproxy fall back to its default zero secret
        users = {"_disabled": secrets.token_hex(16)}
    conf = ("# generated by geovpn-portal, do not edit\n"
            f"PORT = {MTP_PORT}\n"
            f"USERS = {json.dumps(users, indent=1)}\n"
            'MODES = {"classic": False, "secure": False, "tls": True}\n'
            f'TLS_DOMAIN = "{MTP_DOMAIN}"\n'
            'SOCKS5_HOST = "127.0.0.1"\nSOCKS5_PORT = 10804\n'
            "USE_MIDDLE_PROXY = False\nPREFER_IPV6 = False\n"
            'METRICS_PORT = 9189\nMETRICS_LISTEN_ADDR_IPV4 = "127.0.0.1"\nMETRICS_WHITELIST = ["127.0.0.1"]\n'
            "STATS_PRINT_PERIOD = 3600\n")
    old = open(MTP_CONF).read() if os.path.exists(MTP_CONF) else ""
    if conf != old:
        with open(MTP_CONF + ".tmp", "w") as f:
            f.write(conf)
        os.chmod(MTP_CONF + ".tmp", 0o640)
        if not DATA:
            sh(["chgrp", "mtproxy", MTP_CONF + ".tmp"])
        os.replace(MTP_CONF + ".tmp", MTP_CONF)
        if svc_active("geovpn-mtproxy"):
            svc_signal("geovpn-mtproxy", "USR2")


def mt_secret_full(u):
    return "ee" + u["mt"] + MTP_DOMAIN.encode().hex()


def mt_links(u):
    q = f"server={HOST}&port={MTP_PORT}&secret={mt_secret_full(u)}"
    return f"tg://proxy?{q}", f"https://t.me/proxy?{q}"


def mt_stats():
    """{slug: {"octets": n, "curr": n}} from mtprotoproxy metrics (counters reset on proxy restart)."""
    rc, out = sh(["curl", "-s", "-m", "3", MTP_METRICS])
    st = {}
    for m in re.finditer(r'^mtprotoproxy_(user_octets|user_connects_curr)\{user="([^"]+)"\} (\d+)', out or "", re.M):
        st.setdefault(m.group(2), {})["octets" if m.group(1) == "user_octets" else "curr"] = int(m.group(3))
    return st


# ---------------------------------------------------------------- user operations
def create_user(name, group=MOD_GROUP):
    group = valid_group(group)
    name = " ".join(name.split())[:60]
    if len(name) < 2:
        raise UserError("Укажите имя пользователя")
    with LOCK:
        db = load_db()
        existing = {u["username"] for u in rw_users(force=True)} | set(db["users"]) | SERVICE_USERS
        base = slugify(name)
        base = base if len(base) >= 3 else base + "-vpn"
        slug, n = base, 2
        while slug in existing:
            slug, n = f"{base}-{n}", n + 1
        st = json.load(open(STATE))
        u = rw("POST", "/api/users", {
            "username": slug, "description": name, "trafficLimitBytes": 0, "trafficLimitStrategy": "NO_RESET",
            "expireAt": (now_utc() + dt.timedelta(days=VALID_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "activeInternalSquads": [st["squads"]["clients"]]})
        db["users"][slug] = {"name": name, "rw_id": u["id"], "page": f"{slug}-{secrets.token_hex(3)}",
                             "created": now_utc().isoformat(), "awg": awg_new_peer(db), "mt": secrets.token_hex(16),
                             "group": group}
        save_db(db)
        rw_users(force=True)
        awg_apply(db)
        return slug


def user_action(slug, action, role="a", group=None):
    with LOCK:
        db = load_db()
        u = db["users"].get(slug)
        if not u:
            raise UserError("Пользователь не найден")
        if role != "a" and ugroup(u) != MOD_GROUP:
            raise UserError("Нет доступа к этому пользователю")
        if action == "group":
            if role != "a":
                raise UserError("Переносить пользователей между группами может только администратор")
            u["group"] = valid_group(group)
            save_db(db)
            return
        uid = u["rw_id"]
        if action == "extend":
            cur = rw_user_by_id(uid) or {}
            start = max(now_utc(), parse_ts(cur.get("expireAt")) or now_utc())
            body = {"id": uid, "username": slug,
                    "expireAt": (start + dt.timedelta(days=VALID_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")}
            if cur.get("status") == "EXPIRED":
                body["status"] = "ACTIVE"
            rw("PATCH", "/api/users", body)
        elif action in ("disable", "enable"):
            rw("POST", f"/api/users/{uid}/actions/{action}", {})
        elif action == "reissue":
            rw("POST", f"/api/users/{uid}/actions/revoke", {})
            u["awg"] = None
            u["awg"] = awg_new_peer(db)
            u["mt"] = secrets.token_hex(16)
            u["page"] = f"{slug}-{secrets.token_hex(3)}"
        elif action == "delete":
            try:
                rw("DELETE", f"/api/users/{uid}")
            except RuntimeError as e:
                if "404" not in str(e):
                    raise
            del db["users"][slug]
        else:
            raise RuntimeError("Неизвестное действие")
        save_db(db)
        rw_users(force=True)
        awg_apply(db)


def import_existing():
    """Adopt Remnawave users created outside the portal (e.g. test-admin)."""
    with LOCK:
        db = load_db()
        known = {u["rw_id"] for u in db["users"].values()}
        changed = False
        for ru in rw_users(force=True):
            if ru["id"] in known or ru["username"] in db["users"]:
                continue
            slug = ru["username"]
            peer = None
            cf = f"{AWG_DIR}/clients/{slug}.conf"
            if os.path.exists(cf):
                t = open(cf).read()
                priv = re.search(r"PrivateKey\s*=\s*(\S+)", t).group(1)
                pub = subprocess.run(["awg", "pubkey"], input=priv, capture_output=True, text=True).stdout.strip()
                peer = {"ip": re.search(r"Address\s*=\s*([\d.]+)", t).group(1), "priv": priv, "pub": pub,
                        "psk": re.search(r"PresharedKey\s*=\s*(\S+)", t).group(1)}
            db["users"][slug] = {"name": ru.get("description") or slug, "rw_id": ru["id"],
                                 "page": f"{slug}-{secrets.token_hex(3)}", "created": ru.get("createdAt"),
                                 "awg": peer or awg_new_peer(db)}
            changed = True
        for u in db["users"].values():          # MTProxy secret for users created before it existed
            if not u.get("mt"):
                u["mt"] = secrets.token_hex(16)
                changed = True
        # drop portal records whose Remnawave user was deleted in the panel
        alive = {u["id"] for u in rw_users()}
        for slug in [s for s, u in db["users"].items() if u["rw_id"] not in alive]:
            del db["users"][slug]
            changed = True
        if changed:
            save_db(db)
        awg_apply(db)


# ---------------------------------------------------------------- monitoring
def probe(port, url="https://api.ipify.org"):
    t0 = time.time()
    rc, out = sh(["curl", "-s", "-m", "10", "--socks5-hostname", f"127.0.0.1:{port}", url])
    return (out if rc == 0 and out else None), int((time.time() - t0) * 1000)


def collect_monitoring():
    m = {"ts": now_utc()}
    try:
        m["nodes"] = rw("GET", "/api/nodes")
    except Exception as e:
        m["nodes_err"] = str(e)
        m["nodes"] = []
    rc, code = sh(["curl", "-s", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}", "--socks5-hostname",
                   "127.0.0.1:10803", "https://www.youtube.com/generate_204"])
    m["youtube"] = code == "204"
    m["services"] = {label: ("active" if svc_active(name) else "down") for label, name in SERVICES.items()}
    if DATA:
        m["containers"] = {}
    else:
        _, dps = sh(["docker", "ps", "--format", "{{.Names}}"])
        m["containers"] = {c: c in dps.split() for c in ["remnawave", "remnawave-db", "remnanode", "caddy"]}
    _, load = sh("cut -d' ' -f1-3 /proc/loadavg")
    _, mem = sh("free -m | awk 'NR==2{print $3\"/\"$2\" МБ\"}'")
    _, disk = sh(f"df -h {DATA or '/'} | awk 'NR==2{{print $3\"/\"$2}}'")
    _, up = sh("uptime -p")
    m["host"] = {"load": load, "mem": mem, "disk": disk, "uptime": up.replace("up ", "")}
    try:
        b = sorted(f for f in os.listdir(BACKUP_DIR) if f.startswith("msk-"))
        m["backup"] = dt.datetime.fromtimestamp(os.path.getmtime(os.path.join(BACKUP_DIR, b[-1])), dt.timezone.utc) if b else None
    except OSError:
        m["backup"] = None
    return m


def monitoring():
    with LOCK:
        m, ts = CACHE["mon"]
    if time.time() - ts > 60 or not m:
        m = collect_monitoring()
        with LOCK:
            CACHE["mon"] = (m, time.time())
    return m


# ---------------------------------------------------------------- scheduled jobs (docker mode; host install uses cron)
def heartbeat():
    """healthchecks.io pings THROUGH each channel; missing ping -> healthchecks.io alerts (Telegram/email) from abroad."""
    try:
        hc = env_file(HC_ENV)
    except OSError:
        return
    ping = lambda port, uid: uid and sh(["curl", "-fsS", "-m", "15", "--retry", "2", "--socks5-hostname",
                                         f"127.0.0.1:{port}", f"https://hc-ping.com/{uid}"])
    for eid, e in servers.exits_sorted(load_db()):
        ping(e["mon_port"], hc.get(f"HC_EXIT_{eid.upper()}") or {"nl": hc.get("HC_EXIT_NL"), "at": hc.get("HC_EXIT_AT")}.get(eid))
    if hc.get("HC_YOUTUBE") and sh(["curl", "-fsS", "-m", "15", "-o", "/dev/null", "--socks5-hostname", "127.0.0.1:10803",
                                   "https://www.youtube.com/generate_204"])[0] == 0:
        sh(["curl", "-fsS", "-m", "15", f"https://hc-ping.com/{hc['HC_YOUTUBE']}"])
    if hc.get("HC_ALIVE"):
        bad = [k for k, v in SERVICES.items() if not svc_active(v)]
        url = f"https://hc-ping.com/{hc['HC_ALIVE']}" + ("/fail" if bad else "")
        if sh(["curl", "-fsS", "-m", "15", "--data-raw", ", ".join(bad) or "ok", url])[0] != 0:
            sh(["curl", "-fsS", "-m", "15", "--socks5-hostname", "127.0.0.1:10808", "--data-raw", ", ".join(bad) or "ok", url])


def backup():
    """Daily: panel DB dump + all state (portal data, AWG keys/params, MTProxy, Caddy certs) -> BACKUP_DIR, 14 days."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M")
    dump = os.path.join(DATA, "remnawave-db.sql")
    rc, _ = sh(f"docker exec remnawave-db pg_dumpall -U postgres > {dump}", timeout=600)
    if rc != 0:
        raise RuntimeError("pg_dumpall failed")
    out = os.path.join(BACKUP_DIR, f"msk-{ts}.tar.gz")
    extra = " ".join(x for x in (AWG_DIR, os.path.dirname(MTP_CONF), os.environ.get("CADDY_DATA", "")) if x and os.path.isdir(x))
    rc, o = sh(f"tar czf {out} --exclude=./backups --exclude=./apps -C {DATA} . {extra} 2>&1", timeout=600)
    os.remove(dump)
    if rc != 0:
        raise RuntimeError("tar failed: " + o[-200:])
    os.chmod(out, 0o600)
    for f in sorted(x for x in os.listdir(BACKUP_DIR) if x.startswith("msk-"))[:-14]:
        os.remove(os.path.join(BACKUP_DIR, f))
    target = SITE.get("BACKUP_SSH")            # optional offsite copy: user@host (key: <data>/ssh/backup_key)
    key = os.path.join(DATA, "ssh", "backup_key")
    if target and os.path.exists(key):
        import paramiko
        user, host = target.split("@", 1)
        c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(host, username=user, key_filename=key, timeout=20, allow_agent=False, look_for_keys=False)
        sftp = c.open_sftp()
        try:
            sftp.mkdir("geovpn-backups")
        except OSError:
            pass
        sftp.put(out, f"geovpn-backups/{os.path.basename(out)}")
        sftp.close(); c.close()


def scheduler():
    """Docker mode only: heartbeat every minute, backup daily ~03:30 MSK, installers weekly."""
    last = {"backup": None, "apps": 0}
    while True:
        try:
            heartbeat()
        except Exception as e:
            log_error(f"Пульс мониторинга: {e!r}")
        msk = dt.datetime.now(dt.timezone(dt.timedelta(hours=3)))
        if msk.hour == 3 and msk.minute >= 30 and last["backup"] != msk.date():
            last["backup"] = msk.date()
            try:
                backup()
            except Exception as e:
                log_error(f"Бэкап не сделан: {e}")
        if time.time() - last["apps"] > 7 * 86400:
            last["apps"] = time.time()
            rc, out = sh(["bash", "/app/scripts/apps-update.sh"], timeout=3600)
            if rc != 0:
                log_error("Обновление установщиков приложений: " + out[-300:])
        time.sleep(60)


def ensure_awg_routing():
    """AmneziaWG -> TPROXY needs 'ip rule fwmark 0x1 lookup 100' + a local route in table 100.
    systemd-networkd (restarted by package upgrades) flushes such "foreign" rules -> clients connect, no traffic.
    Seen in production 2026-09-27; the installer also sets ManageForeignRoutingPolicyRules=no."""
    if not os.path.exists("/sys/class/net/awg0"):
        return
    if "lookup 100" not in sh(["ip", "rule"])[1]:
        sh(["ip", "rule", "add", "fwmark", "0x1", "lookup", "100"])
        log_error("Правило маршрутизации AmneziaWG (fwmark 0x1 → table 100) пропало — восстановлено автоматически")
    if "local default" not in sh(["ip", "route", "show", "table", "100"])[1]:
        sh(["ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100"])
        log_error("Маршрут AmneziaWG в table 100 пропал — восстановлен автоматически")


def background():
    while True:
        try:
            ensure_awg_routing()
        except Exception as e:
            log_error(f"Проверка маршрутизации AmneziaWG: {e!r}")
        try:
            import_existing()
            mon = collect_monitoring()
            with LOCK:
                CACHE["mon"] = (mon, time.time())
            bad = [k for k, v in mon["services"].items() if v != "active"] + \
                  [f"docker:{k}" for k, v in mon["containers"].items() if not v]
            warm = time.time() - STARTED > STARTUP_GRACE
            if bad and warm:
                log_error("Службы MSK не работают: " + ", ".join(bad))
            if not mon.get("youtube") and warm:
                log_error("YouTube с MSK недоступен (проверь IPv6 и zapret, ADMIN.md 6.4)")
        except Exception as e:
            log_error(f"Фоновая задача портала: {e!r}")
        time.sleep(60)


# ---------------------------------------------------------------- HTML
CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; background:#0f1115; color:#e8e8e8;
  margin:0; padding:24px 16px; line-height:1.5; }
.wrap { max-width:1100px; margin-inline:auto; } .narrow { max-width:680px; }
h1 { font-size:1.4rem; margin:0 0 4px 0; } h2 { font-size:1.05rem; margin:0 0 12px 0; }
.sub { color:#9099a8; font-size:0.9rem; margin-bottom:24px; }
.card { background:#1a1d24; border:1px solid #2a2e38; border-radius:12px; padding:18px; margin-bottom:16px; }
.hint { margin:0 0 12px 0; color:#b9c0cc; font-size:0.9rem; }
.note { margin:12px 0 0 0; color:#8f97a5; font-size:0.85rem; }
a.inline { color:#7aa2ff; }
input[type=text], input[type=password] { font:inherit; color:#e8e8e8; background:#0e1015; border:1px solid #343a48; border-radius:8px;
  padding:9px 12px; width:100%; }
.btn { display:inline-block; background:#3866ff; color:#fff; text-decoration:none; padding:9px 16px; border-radius:8px;
  font-size:0.88rem; font-weight:500; border:none; cursor:pointer; font-family:inherit; margin:0 8px 8px 0; }
.btn.alt { background:#232733; border:1px solid #343a48; color:#e8e8e8; }
.btn.danger { background:#7a2626; } .btn.sm { padding:5px 10px; font-size:0.8rem; margin:0 4px 4px 0; }
.sz { opacity:.7; font-size:.8em; margin-left:4px; }
table { width:100%; border-collapse:collapse; font-size:0.86rem; }
th { text-align:left; color:#8f97a5; font-weight:500; padding:8px 10px; border-bottom:1px solid #2a2e38; }
td { padding:10px; border-bottom:1px solid #21252e; vertical-align:top; }
tr:last-child td { border-bottom:none; } tr.hl td { background:#1d2433; }
.nm { font-weight:600; } .mut { color:#6c7383; font-size:0.8rem; }
.pill { display:inline-block; font-size:0.74rem; padding:2px 8px; border-radius:999px; white-space:nowrap; }
.on { background:#173a26; color:#5fd88a; } .off { background:#3d1f1f; color:#e07a7a; } .no { background:#26292f; color:#7d8492; }
.warnp { background:#3d311f; color:#e0b36a; }
.row { display:flex; gap:12px; flex-wrap:wrap; align-items:center; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:12px; }
.kv { display:flex; justify-content:space-between; gap:8px; font-size:0.86rem; padding:3px 0; }
.kv span:first-child { color:#8f97a5; }
.tabs { display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap; }
.tab { padding:9px 18px; border-radius:8px; cursor:pointer; background:#1a1d24; border:1px solid #2a2e38; font-size:0.9rem; }
.tab.act { background:#3866ff; border-color:#3866ff; color:#fff; }
.qr { width:min(300px,100%); aspect-ratio:1; border-radius:8px; background:#fff; padding:10px; flex:none; }
.qr svg { width:100%; height:100%; display:block; }
code { display:block; word-break:break-all; background:#0a0b0e; padding:10px; border-radius:6px; font-size:0.72rem;
  color:#9fd3ff; margin-bottom:10px; max-height:88px; overflow:auto; }
ol { padding-left:20px; margin:0; } li { margin-bottom:10px; } li:last-child { margin-bottom:0; }
.warn { font-size:0.84rem; color:#e0a86a; } .err { background:#3d1f1f; color:#ffb4b4; }
.ok { background:#173a26; color:#9ff0bd; } .foot { color:#6c7383; font-size:0.8rem; text-align:center; margin-top:8px; }
.scroll { overflow-x:auto; }
@media (max-width:640px) { .hide-sm { display:none; } }
"""

JS_COMMON = """
function copyText(t, btn, okMsg) {
  var old = btn.textContent;
  function done() { btn.textContent = okMsg || 'Скопировано'; setTimeout(function () { btn.textContent = old; }, 1800); }
  function fb() { var ta = document.createElement('textarea'); ta.value = t; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); done(); } catch (e) {} document.body.removeChild(ta); }
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(t).then(done, fb); else fb();
}
function copyFrom(id, btn) { copyText(document.getElementById(id).textContent, btn); }
"""


def page(title, body, js=""):
    return (f'<!doctype html><html lang="ru"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<meta name="robots" content="noindex,nofollow"><title>{esc(title)}</title><style>{CSS}</style></head>'
            f'<body>{body}<script>{JS_COMMON}{js}</script></body></html>')


def qr_svg(data, err="m"):
    buf = io.BytesIO()
    segno.make(data, error=err, micro=False).save(buf, kind="svg", xmldecl=False, svgns=True, omitsize=True,
                                                  border=1, dark="#000", light="#fff")
    return buf.getvalue().decode()


def apps():
    try:
        return json.load(open(os.path.join(APP_DIR, "apps.json")))
    except (OSError, ValueError):
        return {"versions": {}, "sizes": {}}


def invite_text(u):
    return (f"Персональная страница VPN-подключения:\n{BASE_URL}/sub/{u['page']}\n\n"
            f"Откройте её в браузере и следуйте инструкции.")


# ---------------------------------------------------------------- admin page
def render_admin(msg=None, err=None, hl=None, role="u", gfilter=None):
    m = monitoring()
    db = load_db()
    ru = {u["id"]: u for u in rw_users()}
    ast = awg_stats()
    mst = mt_stats()

    def pill(ok, yes="работает", no="сбой"):
        return f'<span class="pill {"on" if ok else "off"}">{yes if ok else no}</span>'

    # monitoring
    nodes = ""
    for n in m.get("nodes", []):
        nodes += (f'<div class="kv"><span>{esc(n["name"])} <span class="mut">{esc(n["address"])}</span></span>'
                  f'<span>{pill(n.get("isConnected"), "online", "offline")}'
                  f' <span class="mut">{n.get("usersOnline") or 0} онл. · {gb(n.get("trafficUsedBytes"))}</span></span></div>')
    chans = ""
    for eid, e in servers.exits_sorted(db):
        s = servers.STATUS.get(eid, {})
        _, erole = servers.role_of(db, eid)
        chans += (f'<div class="kv"><span>MSK → {esc(e["name"])} <span class="mut">{esc(erole)}</span></span>'
                  f'<span>{pill(s.get("ok")) if s else "<span class=pill no>проверка…</span>"}'
                  f' <span class="mut">{str(s.get("ms")) + " мс" if s.get("ok") else ""}</span></span></div>')
    chans += f'<div class="kv"><span>YouTube с MSK</span><span>{pill(m["youtube"])}</span></div>'
    svc = "".join(f'<div class="kv"><span>{esc(k)}</span><span>{pill(v == "active", v, v or "нет")}</span></div>'
                  for k, v in m["services"].items())
    svc += "".join(f'<div class="kv"><span>docker: {esc(k)}</span><span>{pill(v)}</span></div>' for k, v in m["containers"].items())
    h = m["host"]
    bk = m.get("backup")
    host = (f'<div class="kv"><span>Нагрузка</span><span>{esc(h["load"])}</span></div>'
            f'<div class="kv"><span>Память</span><span>{esc(h["mem"])}</span></div>'
            f'<div class="kv"><span>Диск</span><span>{esc(h["disk"])}</span></div>'
            f'<div class="kv"><span>Аптайм</span><span>{esc(h["uptime"])}</span></div>'
            f'<div class="kv"><span>Последний бэкап</span><span>'
            f'{pill(bk and (now_utc() - bk).days < 2, ago(bk), ago(bk))}</span></div>')

    # users (moderator: only MOD_GROUP; admin: all or the selected group)
    is_admin = role == "a"
    groups = sorted({ugroup(x) for x in db["users"].values()} | {MOD_GROUP})
    if not is_admin:
        gfilter = MOD_GROUP
    elif gfilter not in groups:
        gfilter = None
    visible = {s: x for s, x in db["users"].items() if not gfilter or ugroup(x) == gfilter}

    def group_cell(slug, u):
        g = ugroup(u)
        if not is_admin:
            return f'<span class="pill no">{esc(g)}</span>'
        opts = "".join(f'<option value="{esc(x)}"{" selected" if x == g else ""}>{esc(x)}</option>' for x in groups)
        return (f'<form method="post" action="/admin/u/{esc(slug)}/group" style="display:inline">'
                f'<select name="group" onchange="this.form.submit()" style="font:inherit;font-size:0.8rem;color:#e8e8e8;'
                f'background:#0e1015;border:1px solid #343a48;border-radius:6px;padding:3px 6px">{opts}</select></form>')
    rows = ""
    total_online = 0
    for slug, u in sorted(visible.items(), key=lambda kv: kv[1].get("created") or "", reverse=True):
        r = ru.get(u["rw_id"], {})
        stt = r.get("status", "—")
        spill = {"ACTIVE": ("on", "активен"), "DISABLED": ("off", "отключён"), "EXPIRED": ("warnp", "истёк"),
                 "LIMITED": ("warnp", "лимит")}.get(stt, ("no", stt))
        tr = r.get("userTraffic") or {}
        on_rw = parse_ts(tr.get("onlineAt"))
        a = ast.get((u.get("awg") or {}).get("pub"), {})
        hs = a.get("hs")
        mt = mst.get(slug, {})
        online = ((on_rw and (now_utc() - on_rw).total_seconds() < 180) or (hs and (now_utc() - hs).total_seconds() < 180)
                  or mt.get("curr", 0) > 0)
        total_online += 1 if online else 0
        exp = parse_ts(r.get("expireAt"))
        exp_cls = "mut" if not exp or (exp - now_utc()).days > 14 else "warn"
        is_active = stt == "ACTIVE"
        act = lambda a_, label, cls="alt", conf="": (
            f'<form method="post" action="/admin/u/{esc(slug)}/{a_}" style="display:inline"'
            f'{" onsubmit=" + chr(34) + "return confirm(" + esc(json.dumps(conf)) + ")" + chr(34) if conf else ""}>'
            f'<button class="btn sm {cls}">{label}</button></form>')
        rows += (
            f'<tr class="{"hl" if slug == hl else ""}"><td><div class="nm">{esc(u["name"])}</div>'
            f'<div class="mut">{esc(slug)}</div></td>'
            f'<td>{group_cell(slug, u)}</td>'
            f'<td><span class="pill {spill[0]}">{spill[1]}</span>{" <span class=\"pill on\">online</span>" if online else ""}</td>'
            f'<td><span class="{exp_cls}">{fmt_date(exp)}</span></td>'
            f'<td class="hide-sm">{gb(tr.get("lifetimeUsedTrafficBytes"))}<div class="mut">{ago(on_rw)}</div></td>'
            f'<td class="hide-sm">{gb((a.get("rx") or 0) + (a.get("tx") or 0))}<div class="mut">{ago(hs)}</div></td>'
            f'<td class="hide-sm">{gb(mt.get("octets"))}<div class="mut">{"подключён" if mt.get("curr") else "—"}</div></td>'
            f'<td><button class="btn sm" onclick="copyText({esc(json.dumps(invite_text(u), ensure_ascii=False))}, this)">Копировать</button>'
            f'<a class="btn sm alt" href="/sub/{esc(u["page"])}" target="_blank" rel="noopener">Страница</a>'
            f'{act("extend", "+1 год")}'
            f'{act("disable", "Отключить", "alt", "Отключить доступ " + u["name"] + "?") if is_active else act("enable", "Включить")}'
            f'{act("reissue", "Перевыпустить", "alt", "Перевыпустить доступ " + u["name"] + "? Старая ссылка, подписка и конфиг Amnezia перестанут работать.")}'
            f'{act("delete", "Удалить", "danger", "Удалить пользователя " + u["name"] + " безвозвратно?")}</td></tr>')

    alert = ""
    if msg:
        alert = f'<div class="card ok">{esc(msg)}</div>'
    if err:
        alert = f'<div class="card err">{esc(err)}</div>'
    newbox = ""
    if hl and hl in db["users"]:
        t = invite_text(db["users"][hl])
        newbox = (f'<div class="card"><h2>Приглашение для «{esc(db["users"][hl]["name"])}»</h2>'
                  f'<code id="inv" style="max-height:none;white-space:pre-wrap">{esc(t)}</code>'
                  f'<button class="btn" onclick="copyFrom(\'inv\', this)">Копировать приглашение</button></div>')
    counts = {g: sum(1 for x in db["users"].values() if ugroup(x) == g) for g in groups}
    n_all = len(m.get("nodes", []))
    n_on = sum(1 for n in m.get("nodes", []) if n.get("isConnected"))
    ex = [servers.STATUS.get(eid, {}).get("ok") for eid, _ in servers.exits_sorted(db, True)]
    svc_bad = [k for k, v in m["services"].items() if v != "active"] + [k for k, v in m["containers"].items() if not v]
    bk_ok = bool(bk and (now_utc() - bk).days < 2)
    all_ok = n_on == n_all and all(ex) and not svc_bad and m["youtube"] and bk_ok
    summary = (f'<span class="pill {"on" if all_ok else "off"}">{"всё в порядке" if all_ok else "есть проблемы"}</span>'
               f'<span class="mut">ноды {n_on}/{n_all} · выходы {sum(1 for x in ex if x)}/{len(ex)} · '
               f'YouTube {"ок" if m["youtube"] else "нет"} · службы {"ок" if not svc_bad else "сбой: " + esc(", ".join(svc_bad))} · '
               f'бэкап {ago(bk)}</span>')
    SEL = ('font:inherit;color:#e8e8e8;background:#0e1015;border:1px solid #343a48;border-radius:8px;'
           'padding:8px 10px;width:100%')
    group_tabs = ""
    if is_admin:
        group_tabs = ('<div class="row" style="margin-bottom:12px"><span class="mut">Группа:</span><div style="width:240px">'
                      f'<select style="{SEL}" onchange="location.href=this.value">'
                      + f'<option value="/admin"{"" if gfilter else " selected"}>все группы · {len(db["users"])}</option>'
                      + "".join(f'<option value="/admin?g={quote(g)}"{" selected" if g == gfilter else ""}>{esc(g)} · {counts[g]}</option>'
                                for g in groups)
                      + '</select></div></div>')
    body = f"""<div class="wrap">
<h1>{BRAND} — управление</h1>
<div class="sub">Пользователей{"" if is_admin and not gfilter else " в группе " + esc(gfilter)}: {len(visible)} · сейчас online: {total_online} · обновлено {m["ts"].astimezone(dt.timezone(dt.timedelta(hours=3))).strftime("%H:%M:%S")} МСК ·
<a class="inline" href="/admin">обновить</a> · <a class="inline" href="/admin/servers">серверы и балансировщик{"" if is_admin else " (просмотр)"}</a>{' · <a class="inline" href="/" target="_blank">панель Remnawave</a>' if is_admin else ""} ·
<span class="mut">вход: {ROLE_NAMES.get(role, "")}</span> · <a class="inline" href="/logout">выйти</a></div>
{alert}{newbox}
<div class="card"><h2>Новый пользователь</h2>
<form method="post" action="/admin/create" class="row">
<div style="flex:1;min-width:240px"><input type="text" name="name" placeholder="Фамилия Имя, например: Карбышев Дмитрий" required maxlength="60"></div>
{(f'<div style="width:190px"><select name="group" style="{SEL}" onchange="document.getElementById(\'gnew\').hidden = this.value !== \'__new\'">'
   + "".join(f'<option value="{esc(x)}"{" selected" if x == (gfilter or MOD_GROUP) else ""}>группа {esc(x)}</option>' for x in groups)
   + '<option value="__new">➕ новая группа…</option></select></div>'
   '<div id="gnew" hidden style="width:170px"><input type="text" name="group_new" placeholder="название группы" maxlength="20"></div>')
  if is_admin else f'<input type="hidden" name="group" value="{MOD_GROUP}"><span class="pill no">группа {MOD_GROUP}</span>'}
<button class="btn" style="margin:0">Создать — 1 год, без лимитов</button></form>
<p class="note">Создаётся подписка Happ/Hiddify (Reality + Hysteria2), конфигурация Amnezia и личный прокси для Telegram. После создания скопируйте приглашение и отправьте пользователю.</p></div>
<details class="card" style="padding:14px 18px"><summary style="cursor:pointer;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
<b>Состояние системы</b> {summary}</summary>
<div class="grid" style="margin-top:14px">
<div class="card"><h2>Ноды</h2>{nodes or '<span class="mut">нет данных</span>'}</div>
<div class="card"><h2>Каналы</h2>{chans}</div>
<div class="card"><h2>Службы MSK</h2>{svc}</div>
<div class="card"><h2>Сервер MSK</h2>{host}</div>
</div></details>
<div class="card"><h2>Пользователи</h2>{group_tabs}<div class="scroll"><table>
<tr><th>Пользователь</th><th>Группа</th><th>Статус</th><th>До</th><th class="hide-sm">Happ/Hiddify<br><span class="mut">трафик · активность</span></th>
<th class="hide-sm">Amnezia<br><span class="mut">трафик* · активность</span></th><th class="hide-sm">Telegram<br><span class="mut">трафик* · сейчас</span></th><th>Действия</th></tr>
{rows or '<tr><td colspan="8" class="mut">Пока никого нет</td></tr>'}
</table></div><p class="note">* трафик Amnezia и Telegram считается с последнего перезапуска службы. «+1 год» продлевает от текущей даты окончания.</p></div>
</div>"""
    return page(f"{BRAND} — управление", body)


# ---------------------------------------------------------------- user page
USER_CSS = """
.intro { font-size:0.93rem; color:#c9cfda; }
.intro b { color:#fff; }
.opts { display:flex; flex-direction:column; gap:12px; margin-bottom:16px; }
.opt { background:#1a1d24; border:1px solid #2a2e38; border-radius:12px; overflow:hidden; }
.opt.sel { border-color:#3866ff; box-shadow:0 0 0 1px #3866ff inset; }
.opt-head { all:unset; box-sizing:border-box; display:flex; gap:14px; align-items:flex-start; width:100%;
  padding:16px 18px; cursor:pointer; }
.opt-head:hover { background:#1e222b; }
.opt-head:focus-visible { outline:2px solid #7aa2ff; outline-offset:-2px; }
.opt-ico { flex:none; width:40px; height:40px; border-radius:10px; display:flex; align-items:center; justify-content:center;
  font-weight:700; font-size:1.05rem; color:#fff; }
.opt-main { flex:1; min-width:0; }
.opt-title { font-weight:600; font-size:1.02rem; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.opt-desc { color:#b9c0cc; font-size:0.88rem; margin-top:4px; }
.opt-plat { color:#6c7383; font-size:0.78rem; margin-top:6px; }
.badge { font-size:0.7rem; font-weight:600; padding:2px 8px; border-radius:999px; background:#26292f; color:#aab2c0; }
.badge.rec { background:#173a26; color:#5fd88a; }
.badge.tg { background:#1b2c44; color:#7ab8ff; }
.chev { flex:none; margin-top:10px; width:10px; height:10px; border-right:2px solid #6c7383; border-bottom:2px solid #6c7383;
  transform:rotate(45deg); transition:transform .15s; }
.opt.sel .chev { transform:rotate(-135deg); margin-top:14px; }
.opt-body { border-top:1px solid #2a2e38; padding:4px 18px 18px; }
.step { padding-top:16px; }
.step h3 { font-size:0.95rem; margin:0 0 10px; display:flex; gap:10px; align-items:center; }
.num { flex:none; width:24px; height:24px; border-radius:50%; background:#3866ff; color:#fff; font-size:0.8rem;
  display:inline-flex; align-items:center; justify-content:center; }
.dls { display:flex; flex-wrap:wrap; }
.mobile .qr-desk { display:none; }
.qr-toggle { display:none; } .mobile .qr-toggle { display:inline-block; }
.qr-shown .qr-desk { display:block !important; }
"""

USER_JS = """
var OS = (function () {
  var ua = navigator.userAgent || '';
  if (/android/i.test(ua)) return 'android';
  if (/iphone|ipad|ipod/i.test(ua) || (/macintosh/i.test(ua) && navigator.maxTouchPoints > 1)) return 'ios';
  if (/windows/i.test(ua)) return 'windows';
  if (/macintosh|mac os x/i.test(ua)) return 'mac';
  return 'other';
})();
if (OS === 'android' || OS === 'ios') document.documentElement.classList.add('mobile');
// the button for this device goes first and becomes primary
document.querySelectorAll('.dls').forEach(function (g) {
  var mine = g.querySelector('[data-os="' + OS + '"]');
  g.querySelectorAll('a.btn').forEach(function (a) { a.classList.add('alt'); });
  if (mine) { mine.classList.remove('alt'); g.insertBefore(mine, g.firstChild); }
  else if (g.firstElementChild) g.firstElementChild.classList.remove('alt');
});
document.querySelectorAll('.os-name').forEach(function (e) {
  e.textContent = {android: 'Android', ios: 'iPhone / iPad', windows: 'Windows', mac: 'Mac'}[OS] || 'вашего устройства';
});
function pick(id, scroll) {
  document.querySelectorAll('.opt').forEach(function (o) {
    var on = o.id === 'opt-' + id && !o.classList.contains('sel');
    o.classList.toggle('sel', on);
    o.querySelector('.opt-body').hidden = !on;
    o.querySelector('.opt-head').setAttribute('aria-expanded', on ? 'true' : 'false');
    if (on && scroll !== false) setTimeout(function () { o.scrollIntoView({behavior: 'smooth', block: 'start'}); }, 30);
  });
  var open = document.querySelector('.opt.sel');
  try { if (open) localStorage.setItem('vpn-opt', id); else localStorage.removeItem('vpn-opt'); } catch (e) {}
}
function showQr(btn) { btn.closest('.step').classList.add('qr-shown'); btn.hidden = true; }
(function () {
  var s = (location.hash || '').slice(1);
  if (!s) { try { s = localStorage.getItem('vpn-opt'); } catch (e) {} }
  if (s && document.getElementById('opt-' + s)) pick(s, false);
})();
"""


def dl(fname, label, os_=None):
    a = apps()
    size = a["sizes"].get(fname)
    if not size:
        return ""
    return (f'<a class="btn alt" href="/app/{fname}"{f" data-os={chr(34)}{os_}{chr(34)}" if os_ else ""}>{esc(label)}'
            f'<span class="sz">{size / 1e6:.0f} МБ</span></a>')


def store(url, label, os_="ios"):
    return f'<a class="btn alt" href="{url}" target="_blank" rel="noopener" data-os="{os_}">{esc(label)}</a>'


def step(n, title, body):
    return f'<div class="step"><h3><span class="num">{n}</span>{title}</h3>{body}</div>'


def connect_block(qr_data, qr_err, code_id, code_text, primary_btn, hint_desktop, extra_btn=""):
    """QR for desktop; on phones the in-app button comes first and QR is behind a toggle."""
    return f"""<div class="row" style="align-items:flex-start">
<div class="qr qr-desk">{qr_svg(qr_data, qr_err)}</div>
<div style="flex:1;min-width:230px">
{primary_btn}
<p class="hint" style="margin-top:6px">{hint_desktop}</p>
<code id="{code_id}">{esc(code_text)}</code>
<button class="btn alt" onclick="copyFrom('{code_id}', this)">Скопировать ссылку</button>{extra_btn}
<button class="btn alt qr-toggle" onclick="showQr(this)">Показать QR-код для другого устройства</button>
</div></div>"""


def option(oid, icon, color, title, badges, desc, plat, body):
    return f"""<div class="opt" id="opt-{oid}">
<button class="opt-head" onclick="pick('{oid}')" aria-expanded="false" aria-controls="body-{oid}">
<span class="opt-ico" style="background:{color}">{icon}</span>
<span class="opt-main"><span class="opt-title">{title} {badges}</span>
<span class="opt-desc" style="display:block">{desc}</span><span class="opt-plat" style="display:block">{plat}</span></span>
<span class="chev"></span></button>
<div class="opt-body" id="body-{oid}" hidden>{body}</div></div>"""


def render_user(u, client_ip):
    r = rw_user_by_id(u["rw_id"])
    name = u["name"]
    head = f'<div class="wrap narrow"><h1>{BRAND}</h1><div class="sub">Персональная страница подключения — {esc(name)}</div>'
    if not r or r["status"] != "ACTIVE":
        reason = {"EXPIRED": "Срок действия доступа истёк.", "DISABLED": "Доступ приостановлен.",
                  "LIMITED": "Исчерпан лимит трафика."}.get((r or {}).get("status"), "Доступ недоступен.")
        return page(f"{BRAND} — подключение", head + f'<div class="card"><h2>{reason}</h2>'
                    f'<p class="hint">Обратитесь к администратору.</p></div></div>')
    v = apps()["versions"]
    sub = r["subscriptionUrl"]
    sub_named = sub + "#" + quote(name)
    vpnkey = awg_vpn_key(u["awg"], f"{BRAND} — {name}")
    tg_link, _ = mt_links(u)
    android_note = '<p class="note">На Android при установке файла появится предупреждение о неизвестном источнике — это нормально, приложение скачивается с нашего сервера, а не из Google Play.</p>'

    happ = option("happ", "H", "#3866ff", "Happ", '<span class="badge">Альтернатива</span>',
        "Такой же VPN, но другое приложение. Выберите, если Hiddify не устанавливается или работает нестабильно. Российские сайты открываются напрямую, остальное — через VPN.",
        "Windows · Android · Mac · iPhone и iPad",
        step(1, "Установите приложение",
             f'<div class="dls">{dl("Happ-windows.exe", "Windows", "windows")}{dl("Happ-android.apk", "Android", "android")}'
             f'{dl("Happ-macos.dmg", "Mac", "mac")}{store("https://apps.apple.com/us/app/happ-proxy-utility/id6504287215", "iPhone / iPad — App Store")}</div>'
             f'<p class="note">Выделена кнопка для <span class="os-name"></span>. Версия Happ {esc(v.get("happ", ""))}.</p>{android_note}')
        + step(2, "Добавьте подключение",
             connect_block(sub, "m", "happ-uri", sub, f'<a class="btn" href="happ://add/{esc(sub)}">Открыть в Happ</a>',
                           "Кнопка сама добавит подключение в Happ. Или отсканируйте QR-код в приложении (кнопка «+» → QR), или скопируйте ссылку и добавьте её из буфера обмена:"))
        + step(3, "Подключитесь",
             '<ol><li>В списке выберите сервер <b>RU MSK Reality</b> и нажмите большую кнопку подключения.</li>'
             '<li>Если соединение нестабильно — выберите <b>RU MSK Hysteria2</b>.</li>'
             '<li>Для игр на Windows включите режим «Системный прокси» — игры пойдут мимо VPN. На Android игры можно исключить в «Раздельном туннелировании».</li></ol>'
             '<p class="note">Настройки обновляются сами: если на сервере что-то изменится, приложение получит это автоматически.</p>'))

    hiddify = option("hiddify", "Hi", "#6d4aff", "Hiddify", '<span class="badge rec">Рекомендуем</span>',
        "Основной вариант. Сам выбирает самый быстрый способ подключения; российские сайты при этом открываются напрямую, остальное — через VPN.",
        "Windows · Android · Mac · iPhone и iPad",
        step(1, "Установите приложение",
             f'<div class="dls">{dl("Hiddify-windows.exe", "Windows", "windows")}{dl("Hiddify-android.apk", "Android", "android")}'
             f'{dl("Hiddify-macos.dmg", "Mac", "mac")}{store("https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532", "iPhone / iPad — Hiddify")}</div>'
             f'<p class="note">Если Hiddify нет в App Store вашей страны, подойдёт '
             f'<a class="inline" href="https://apps.apple.com/us/app/incy/id6756943388" target="_blank" rel="noopener">INCY</a> — ссылка подключения та же. '
             f'Версия Hiddify {esc(v.get("hiddify", ""))}.</p>{android_note}')
        + step(2, "Добавьте подключение",
             connect_block(sub_named, "m", "hid-uri", sub_named, f'<a class="btn" href="hiddify://import/{esc(sub_named)}">Открыть в Hiddify</a>',
                           "Кнопка сама добавит подключение в Hiddify. Или в приложении нажмите «Добавить профиль» и отсканируйте QR-код / вставьте ссылку:"))
        + step(3, "Подключитесь",
             '<ol><li>При первом запуске выберите регион <b>Russia</b> — российские сайты будут работать напрямую.</li>'
             '<li>Нажмите большую кнопку подключения. Если соединение нестабильно — выберите в списке <b>RU MSK Hysteria2</b>.</li></ol>'))

    amnezia = option("amnezia", "A", "#0f9d74", "Amnezia", '<span class="badge">Другой протокол</span>',
        "Принципиально другой протокол (AmneziaWG), не связанный с Hiddify и Happ. Может работать, когда они не подключаются — например, если их блокирует провайдер, мобильная сеть или сеть на работе.",
        "Windows · Android · Mac · iPhone и iPad",
        step(1, "Установите приложение",
             f'<div class="dls">{dl("AmneziaVPN-windows.exe", "Windows", "windows")}{dl("AmneziaVPN-android.apk", "Android", "android")}'
             f'{dl("AmneziaVPN-macos.pkg", "Mac", "mac")}{store("https://apps.apple.com/us/app/amneziavpn/id1600529900", "iPhone / iPad — App Store")}</div>'
             f'<p class="note">Старый Android (9–10): {dl("AmneziaVPN-android-9-10.apk", "Android 9–10") or "—"} '
             f'Если Amnezia нет в App Store вашей страны: <a class="inline" href="https://apps.apple.com/us/app/defaultvpn/id6744725017" target="_blank" rel="noopener">DefaultVPN</a>. '
             f'Нужна версия 4.8.12.9 или новее, у нас {esc(v.get("amnezia", ""))}.</p>{android_note}')
        + step(2, "Добавьте подключение",
             connect_block(vpnkey[len("vpn://"):], "l", "awg-uri", vpnkey,
                           f'<a class="btn" href="/sub/{esc(u["page"])}/conf">Скачать файл подключения</a>',
                           "Откройте скачанный файл в Amnezia. Или в приложении нажмите «+» и отсканируйте QR-код / вставьте ссылку:"))
        + step(3, "Подключитесь",
             '<ol><li>Нажмите «Подключиться».</li>'
             '<li>Игры и отдельные приложения можно пустить мимо VPN в разделе «Раздельное туннелирование».</li></ol>'))

    telegram = option("telegram", "✈", "#229ed9", "Только Telegram", '<span class="badge tg">Не VPN</span>',
        "Прокси, чтобы Telegram работал без включённого VPN. Другие сайты и приложения он не открывает. Если у вас уже работает VPN — это не нужно.",
        "Везде, где есть Telegram",
        step(1, "Установите Telegram, если его ещё нет",
             f'<div class="dls">{dl("Telegram-windows.exe", "Windows", "windows")}{dl("Telegram-android.apk", "Android", "android")}'
             f'{dl("Telegram-macos.dmg", "Mac", "mac")}{store("https://apps.apple.com/app/telegram-messenger/id686449807", "iPhone / iPad — App Store")}</div>')
        + step(2, "Включите прокси",
             connect_block(tg_link, "m", "tg-uri", tg_link, f'<a class="btn" href="{esc(tg_link)}">Подключить в Telegram</a>',
                           "Кнопка откроет Telegram — нажмите там «Подключить прокси». Или отсканируйте QR-код камерой телефона:")
             + f'<p class="note">Вручную: Настройки → Данные и память → Прокси → Добавить прокси → MTProto. Сервер <b>{HOST}</b>, порт <b>{MTP_PORT}</b>, '
               f'ключ — часть ссылки после «secret=».</p>'
               '<p class="note">Звонки через прокси могут не работать — для звонков включите VPN.</p>'))

    body = head + f"""<div class="card intro">Здесь всё для подключения к VPN: заблокированные сайты и сервисы откроются,
а российские продолжат работать напрямую.<br><b>Достаточно одного приложения.</b> Выберите вариант ниже —
откроется пошаговая инструкция. Не знаете, что выбрать, — берите <b>Hiddify</b>.</div>
<div class="opts">{hiddify}{happ}{amnezia}{telegram}</div>
<div class="card"><div class="hint" style="margin:0">Доступ действует до <b>{fmt_date(r.get("expireAt"))}</b>.</div>
<div class="warn" style="margin-top:10px"><b>Страница является персональной.</b>
Подключиться по ней может любой, кто получит ссылку — пароль не запрашивается.<br>
Настоятельно не рекомендуется передавать ссылку третьим лицам. Это может привести как к замедлению работы вашего
подключения из-за большого числа одновременных сессий, так и к блокировке сервиса целиком.</div></div>
<div class="foot">{esc(client_ip)}</div></div>"""
    return page(f"{BRAND} — подключение", f"<style>{USER_CSS}</style>" + body, USER_JS)


def find_by_page(pid):
    for slug, u in load_db()["users"].items():
        if u["page"] == pid:
            return slug, u
    return None, None



# ---------------------------------------------------------------- login / roles
# role "u": users & monitoring (/admin);  role "a": everything incl. servers and Remnawave panel
ROLE_NAMES = {"u": f"модератор (группа {MOD_GROUP})", "a": "администратор"}


def password_role(pw):
    env = env_file(PORTAL_ENV)
    for role, key in (("a", "SERVERS_PASS"), ("u", "USERS_PASS")):
        if key in env:
            salt, h = env[key].split("$")
            if hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200000).hex(), h):
                return role
    return None


def session_sig(role, exp):
    return hmac.new(env_file(PORTAL_ENV)["SESSION_SECRET"].encode(), f"{role}.{exp}".encode(), "sha256").hexdigest()


def make_session(role):
    exp = int(time.time()) + SESSION_TTL
    return f"{role}.{exp}.{session_sig(role, exp)}"


def session_role(cookie_header):
    m = re.search(r"(?:^|;\s*)gvs=([ua])\.(\d+)\.([0-9a-f]{64})", cookie_header or "")
    if not m or int(m.group(2)) < time.time():
        return None
    return m.group(1) if hmac.compare_digest(session_sig(m.group(1), int(m.group(2))), m.group(3)) else None


def has_role(cookie_header, need):
    r = session_role(cookie_header)
    return r == "a" or (r == "u" and need == "u")


def safe_next(n):
    return n if n and n.startswith("/") and not n.startswith("//") else "/admin"


def need_for(path):
    # moderator ("u"): /admin (own group) and read-only /admin/servers; admin ("a"): everything, incl. Remnawave panel
    return "u" if path.startswith("/admin") else "a"


def render_login(err=None, nxt="/admin"):
    nxt = safe_next(nxt)
    what = "Панель Remnawave" if need_for(nxt) == "a" else "Управление GeoVPN"
    return page(f"{BRAND} — вход", f"""<div class="wrap" style="max-width:420px">
<h1>{BRAND} — вход</h1><div class="sub">{what}: требуется пароль.</div>
{f'<div class="card err">{esc(err)}</div>' if err else ''}
<div class="card"><form method="post" action="/login">
<input type="hidden" name="next" value="{esc(nxt)}">
<input type="password" name="password" placeholder="Пароль" required autofocus style="margin-bottom:12px">
<button class="btn" style="margin:0">Войти</button></form></div></div>""")


# ---------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    server_version = "geovpn"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Robots-Tag", "noindex")
        self.send_header("Referrer-Policy", "same-origin")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def redirect(self, loc):
        self.send_response(303)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def client_ip(self):
        return (self.headers.get("X-Forwarded-For") or self.client_address[0]).split(",")[0].strip()

    def not_found(self):
        self.send(404, page("Не найдено", '<div class="wrap narrow"><div class="card"><h2>Страница не найдена</h2>'
                                           '<p class="hint">Проверьте ссылку или обратитесь к администратору.</p></div></div>'))

    def do_GET(self):
        url = urlparse(self.path)
        p = url.path
        try:
            m = re.fullmatch(r"/(?:sub|c)/([a-z0-9-]+)(/conf)?/?", p)
            if m:
                slug, u = find_by_page(m.group(1))
                if not u:
                    return self.not_found()
                if m.group(2):
                    r = rw_user_by_id(u["rw_id"])
                    if not r or r["status"] != "ACTIVE":
                        return self.not_found()
                    return self.send(200, awg_client_conf(u["awg"]), "application/octet-stream",
                                     {"Content-Disposition": f'attachment; filename="geovpn-{slug}.conf"'})
                return self.send(200, render_user(u, self.client_ip()))
            if p == "/auth/check":   # Caddy forward_auth for the Remnawave panel
                if has_role(self.headers.get("Cookie"), "a"):
                    return self.send(200, "ok", "text/plain")
                back = self.headers.get("X-Forwarded-Uri") or "/"
                return self.send(302, "", extra={"Location": "/login?next=" + quote(back)})
            if p == "/login":
                return self.send(200, render_login(nxt=parse_qs(url.query).get("next", ["/admin"])[0]))
            if p == "/logout":
                return self.send(303, "", extra={"Location": "/login",
                                 "Set-Cookie": "gvs=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"})
            if p.startswith("/admin"):
                if not has_role(self.headers.get("Cookie"), need_for(p)):
                    return self.redirect("/login?next=" + quote(self.path))
                if p.startswith("/admin/servers"):
                    r = servers.handle_get(self, p, parse_qs(url.query), readonly=session_role(self.headers.get("Cookie")) != "a")
                    return r if r is not None else self.not_found()
                if p in ("/admin", "/admin/"):
                    q = parse_qs(url.query)
                    return self.send(200, render_admin(q.get("msg", [None])[0], q.get("err", [None])[0], q.get("new", [None])[0],
                                                       session_role(self.headers.get("Cookie")), q.get("g", [None])[0]))
            return self.not_found()
        except Exception as e:
            if not isinstance(e, (BrokenPipeError, ConnectionResetError)):
                log_error(f"Ошибка страницы {self.path.split('?')[0]}: {e!r}")
            self.send(500, page("Ошибка", f'<div class="wrap narrow"><div class="card err">Ошибка: {esc(e)}</div></div>'))

    def do_POST(self):
        p = urlparse(self.path).path
        origin = self.headers.get("Origin")
        if origin and origin != BASE_URL:
            return self.send(403, "forbidden", "text/plain")
        n = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(n).decode("utf-8", "replace")) if n else {}
        try:
            if p == "/login":
                nxt = safe_next(form.get("next", [""])[0])
                role = password_role(form.get("password", [""])[0])
                if not role:
                    time.sleep(2)
                    return self.send(200, render_login("Неверный пароль", nxt))
                if role == "u" and need_for(nxt) == "a":
                    return self.send(200, render_login("Этот пароль — модератора: панель Remnawave доступна только администратору", nxt))
                return self.send(303, "", extra={"Location": nxt, "Set-Cookie":
                                 f"gvs={make_session(role)}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; Secure; SameSite=Strict"})
            if p.startswith("/admin") and not has_role(self.headers.get("Cookie"), need_for(p)):
                return self.redirect("/login?next=" + quote("/admin/servers" if p.startswith("/admin/servers") else "/admin"))
            role = session_role(self.headers.get("Cookie"))
            if p.startswith("/admin/servers"):
                if role != "a":
                    return self.redirect("/admin/servers?err=" + quote("Модератор может только просматривать серверы и балансировщик"))
                try:
                    r = servers.handle_post(self, p, form)
                except Exception as e:
                    log_error(f"Управление серверами ({p}): {e}")
                    return self.redirect("/admin/servers?err=" + quote(str(e)[:300]))
                return r if r is not None else self.not_found()
            if p == "/admin/create":
                grp = form.get("group", [MOD_GROUP])[0] if role == "a" else MOD_GROUP
                if grp == "__new":
                    grp = form.get("group_new", [""])[0]
                slug = create_user(form.get("name", [""])[0], grp)
                return self.redirect(f"/admin?new={quote(slug)}&msg=" + quote("Пользователь создан"))
            m = re.fullmatch(r"/admin/u/([a-z0-9-]+)/(extend|disable|enable|reissue|delete|group)", p)
            if m:
                user_action(m.group(1), m.group(2), role, form.get("group", [None])[0])
                msgs = {"extend": "Доступ продлён на год", "disable": "Доступ отключён", "enable": "Доступ включён",
                        "group": "Пользователь перенесён в группу " + (form.get("group", [""])[0] or ""),
                        "reissue": "Доступ перевыпущен — отправьте пользователю новое приглашение", "delete": "Пользователь удалён"}
                hl = "" if m.group(2) == "delete" else f"&new={quote(m.group(1))}" if m.group(2) == "reissue" else ""
                return self.redirect("/admin?msg=" + quote(msgs[m.group(2)]) + hl)
            return self.not_found()
        except (BrokenPipeError, ConnectionResetError):
            return None  # the browser went away before reading the answer - nothing to report
        except Exception as e:
            if not isinstance(e, UserError):
                log_error(f"Действие в админке ({p}): {e}")
            return self.redirect("/admin?err=" + quote(str(e)[:300]))


if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    try:
        import_existing()
    except Exception as e:
        print("initial import failed:", e, flush=True)
    threading.Thread(target=background, daemon=True).start()
    threading.Thread(target=servers.watchdog, daemon=True).start()
    if DATA:
        threading.Thread(target=scheduler, daemon=True).start()
    print("geovpn-portal listening on %s:%d" % LISTEN, flush=True)
    ThreadingHTTPServer(LISTEN, H).serve_forever()
