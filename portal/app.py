#!/usr/bin/env python3
"""GeoVPN portal: admin page (/admin) + personal user pages (/c/<id>).

Remnawave is the source of truth for users (Happ/Hiddify). AmneziaWG peers are owned by this
portal: awg0.conf peers are regenerated from the portal DB for ACTIVE users only.
Listens on 127.0.0.1:8090 behind Caddy (/admin is protected by the Caddy cookie).
"""
import base64, datetime as dt, hashlib, hmac, html, io, json, os, re, secrets, subprocess, sys, threading, time, zlib, tempfile, socket, socketserver
import urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

import segno
from storage import ProcessLock, atomic_write, read_json
import public_state
import routing_policy

sys.modules.setdefault("app", sys.modules[__name__])

DATA = os.environ.get("GEOVPN_DATA")     # set in the docker image (/data); unset = legacy host install
PUBLIC = os.environ.get("GEOVPN_ROLE") == "public"
PUBLIC_DIR = os.environ.get("GEOVPN_PUBLIC_DIR")
PUBLIC_STATE = os.path.join(PUBLIC_DIR or "/public", "connections.json")


def P(docker_rel, legacy):
    return os.path.join(DATA, docker_rel) if DATA else legacy


SITE_ENV = P("geovpn.env", "/etc/geovpn/geovpn.env")


def _site():
    """Per-installation settings (written by the installer): geovpn.env"""
    out = {}
    if PUBLIC:
        return read_json(PUBLIC_STATE)["site"]
    try:
        for line in open(SITE_ENV, encoding="utf-8", errors="replace"):   # a broken byte must not stop the portal
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
LISTEN = ("0.0.0.0" if PUBLIC else "127.0.0.1", 8091 if PUBLIC else 8090)
DB_PATH = P("db.json", "/var/lib/geovpn-portal/db.json")
AWG_DIR = os.environ.get("AWG_DIR", "/etc/amnezia/amneziawg")
AWG_NET = "10.66.66"
AWG_NET6 = "fd66:66:66::"   # ULA: clients' IPv6 goes into the tunnel too (without it, it bypasses the VPN)
AWG_DNS = ("8.8.8.8", "77.88.8.8")   # any public resolver: xray on MSK answers port 53 itself (DoH + cache)
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
ADMIN_GROUP = "main"        # group the admin's user list opens with
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

LOCK = ProcessLock(lambda: DB_PATH + ".lock")
MEMORY_LOCK = threading.RLock()
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
             "страницы подключения": "geovpn-public",
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
        rc, out = sh(["docker", "kill", "-s", sig, name])
    else:
        rc, out = sh(["systemctl", "kill", "-s", "SIG" + sig, name])
    if rc:
        raise RuntimeError(f"{name}: signal {sig} failed: {out}")


# ---------------------------------------------------------------- storage
def load_db():
    if PUBLIC:
        return {"users": public_state.read(PUBLIC_STATE)["users"]}
    with LOCK:
        return read_json(DB_PATH, {"users": {}})


def save_db(db):
    if PUBLIC: raise RuntimeError("Public worker cannot write control state")
    with LOCK:
        previous = read_json(DB_PATH, {"users": {}})
        changed = any(previous.get(k) != db.get(k) for k in ("exits", "pins", "msk")) or (
            previous.get("routing", {}).get("rules") != db.get("routing", {}).get("rules"))
        invalidated = (previous.get("balancer", {}).get("plan") is not None
                       and db.get("balancer", {}).get("plan") is None)
        db["_routing_revision"] = previous.get("_routing_revision", 0) + int(changed or invalidated)
        if changed and "balancer" in db: db["balancer"]["plan"] = None
        atomic_write(DB_PATH, json.dumps(db, ensure_ascii=False, indent=1))
        publish_connections(db)


def publish_connections(db):
    if not PUBLIC_DIR or PUBLIC: return
    if not CACHE["users"][1]: return  # CLI processes have no user cache; don't erase the public snapshot.
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    try:
        public_state.publish(PUBLIC_STATE, db, CACHE["users"][0], awg_params(), awg_server(), SITE)
    except FileNotFoundError:
        pass  # provisioning has not generated server keys yet; public worker fails closed


def log_error(text):
    """Critical error log shown on /admin/servers. Same message within 30 min -> counter instead of a new line."""
    text = str(text)[:400]
    with LOCK:
        db = load_db()
        errs = db.setdefault("errors", [])
        now = now_utc()
        # also when other errors came in between (two nodes failing in turn made dozens of separate lines)
        same = next((i for i, x in enumerate(errs[:20]) if x["text"] == text
                     and (now - parse_ts(x["last"])).total_seconds() < 1800), None)
        if same is not None:
            e = errs.pop(same)
            e["count"] = e.get("count", 1) + 1
            e["last"] = now.isoformat()
            errs.insert(0, e)
        else:
            errs.insert(0, {"ts": now.isoformat(), "last": now.isoformat(), "text": text, "count": 1})
            del errs[100:]
        save_db(db)
    print("ERROR-LOG:", text, flush=True)


def env_file(path):
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
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
    if PUBLIC: return public_state.read(PUBLIC_STATE)["remote"]
    with LOCK:
        users, ts = CACHE["users"]
        if force or time.time() - ts > 20:
            users, start = [], 0
            while True:
                batch = rw("GET", f"/api/users?start={start}&size=1000")["users"]
                users.extend(u for u in batch if u["username"] not in SERVICE_USERS)
                if len(batch) < 1000: break
                start += len(batch)
            CACHE["users"] = (users, time.time())
        return users


def rw_user_by_id(uid):
    return next((u for u in rw_users() if u["id"] == uid), None)


# ---------------------------------------------------------------- AmneziaWG
def awg_params():
    if PUBLIC: return public_state.read(PUBLIC_STATE)["params"]
    return env_file(f"{AWG_DIR}/params.env")


def awg_server():
    if PUBLIC: return public_state.read(PUBLIC_STATE)["server"]
    conf = open(f"{AWG_DIR}/awg0.conf", encoding="utf-8").read()
    port = re.search(r"ListenPort\s*=\s*(\d+)", conf).group(1)
    return open(f"{AWG_DIR}/server.pub").read().strip(), port


def awg_keys():
    rc, priv = sh(["awg", "genkey"])
    if rc or not priv: raise RuntimeError("awg genkey failed")
    pub = subprocess.run(["awg", "pubkey"], input=priv, capture_output=True, text=True, check=True).stdout.strip()
    rc, psk = sh(["awg", "genpsk"])
    if rc or not psk or not pub: raise RuntimeError("awg key generation failed")
    return priv, pub, psk


def awg_new_peer(db):
    used = {peer["ip"] for u in db["users"].values()
            for peer in (u.get("awg"), u.get("replacement", {}).get("awg")) if peer}
    for i in range(2, 255):
        ip = f"{AWG_NET}.{i}"
        if ip not in used:
            priv, pub, psk = awg_keys()
            return {"ip": ip, "priv": priv, "pub": pub, "psk": psk}
    raise RuntimeError("Нет свободных адресов AmneziaWG")


def awg_ip6(ip4):
    return AWG_NET6 + ip4.rsplit(".", 1)[1]


def awg_client_conf(peer):
    p = awg_params()
    spub, port = awg_server()
    # MTU 1376 (as AmneziaVPN itself uses): default 1420 breaks big packets on mobile networks with smaller MTU
    lines = ["[Interface]", f"PrivateKey = {peer['priv']}", f"Address = {peer['ip']}/32, {awg_ip6(peer['ip'])}/128",
             "DNS = " + ", ".join(AWG_DNS), "MTU = 1376"]
    lines += [f"{k} = {v}" for k, v in p.items()]
    lines += ["", "[Peer]", f"PublicKey = {spub}", f"PresharedKey = {peer['psk']}", f"Endpoint = {HOST}:{port}",
              "AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25", ""]
    return "\n".join(lines)


def awg_vpn_key(peer, title):
    """AmneziaVPN import key: vpn:// + base64url(qCompress(json))."""
    p = awg_params()
    spub, port = awg_server()
    conf = awg_client_conf(peer)
    last = dict(p)
    last.update({"allowed_ips": ["0.0.0.0/0", "::/0"], "clientId": "", "client_ip": peer["ip"], "client_priv_key": peer["priv"],
                 "client_pub_key": peer["pub"], "config": conf, "hostName": HOST, "mtu": "1376",
                 "persistent_keep_alive": "25", "port": int(port), "psk_key": peer["psk"], "server_pub_key": spub})
    awg = dict(p)
    awg.update({"last_config": json.dumps(last, ensure_ascii=False), "port": port, "protocol_version": "2",
                "subnet_address": f"{AWG_NET}.0", "transport_proto": "udp"})
    data = {"containers": [{"awg": awg, "container": "amnezia-awg2"}], "defaultContainer": "amnezia-awg2",
            "description": title, "dns1": AWG_DNS[0], "dns2": AWG_DNS[1], "hostName": HOST}
    raw = json.dumps(data, ensure_ascii=False).encode()
    blob = len(raw).to_bytes(4, "big") + zlib.compress(raw, 8)
    return "vpn://" + base64.urlsafe_b64encode(blob).decode().rstrip("=")


def awg_apply(db):
    """Rewrite awg0.conf peers = portal users that are ACTIVE in Remnawave, then hot-reload."""
    active = active_user_ids()
    path = f"{AWG_DIR}/awg0.conf"
    with open(path, encoding="utf-8") as f: conf = f.read()
    head = conf.split("\n[Peer]")[0].rstrip() + "\n"
    if AWG_NET6 not in head:        # installs before IPv6 in the tunnel: the server's IPv6 tunnel address
        head = re.sub(r"(?m)^(Address\s*=\s*[^\n,]+)$", rf"\1, {AWG_NET6}1/64", head)
    peers = []
    for slug, u in sorted(db["users"].items()):
        if u.get("awg") and not u.get("blocked") and u.get("rw_id") in active:
            a = u["awg"]
            peers.append(f"\n[Peer]\n# {slug}\nPublicKey = {a['pub']}\nPresharedKey = {a['psk']}\n"
                         f"AllowedIPs = {a['ip']}/32, {awg_ip6(a['ip'])}/128\n")
    new = head + "".join(peers)
    if new != conf:
        with open(path + ".tmp", "w", encoding="utf-8") as f:
            f.write(new)
        os.chmod(path + ".tmp", 0o600)
        os.replace(path + ".tmp", path)
    # Reconcile the running interface, even when a previous attempt already wrote the file.
    errors = []
    rc, out = sh("awg syncconf awg0 <(awg-quick strip awg0)")
    if rc: errors.append("awg syncconf failed: " + out)
    try:
        mt_apply(db)
    except Exception as e:
        errors.append(str(e))
    if errors: raise RuntimeError("; ".join(errors))


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
    active = active_user_ids()
    users = {slug: u["mt"] for slug, u in sorted(db["users"].items())
             if u.get("mt") and not u.get("blocked") and u.get("rw_id") in active}
    if not users:                       # never let mtprotoproxy fall back to its default zero secret
        # Stable per installation, so an empty user list doesn't force a reload every minute.
        users = {"_disabled": hashlib.sha256((HOST + MTP_CONF).encode()).hexdigest()[:32]}
    conf = ("# generated by geovpn-portal, do not edit\n"
            f"PORT = {MTP_PORT}\n"
            f"USERS = {json.dumps(users, indent=1)}\n"
            'MODES = {"classic": False, "secure": False, "tls": True}\n'
            f'TLS_DOMAIN = "{MTP_DOMAIN}"\n'
            'SOCKS5_HOST = "127.0.0.1"\nSOCKS5_PORT = 10804\n'
            "USE_MIDDLE_PROXY = False\nPREFER_IPV6 = False\n"
            'METRICS_PORT = 9189\nMETRICS_LISTEN_ADDR_IPV4 = "127.0.0.1"\nMETRICS_WHITELIST = ["127.0.0.1"]\n'
            "STATS_PRINT_PERIOD = 3600\n")
    if os.path.exists(MTP_CONF):
        with open(MTP_CONF) as f: old = f.read()
    else: old = ""
    if conf != old:
        with open(MTP_CONF + ".tmp", "w") as f:
            f.write(conf)
        os.chmod(MTP_CONF + ".tmp", 0o640)
        if not DATA:
            sh(["chgrp", "mtproxy", MTP_CONF + ".tmp"])
        os.replace(MTP_CONF + ".tmp", MTP_CONF)
    digest = hashlib.sha256(conf.encode()).hexdigest()
    marker = MTP_CONF + ".applied"
    if os.path.exists(marker):
        with open(marker) as f: applied = f.read()
    else: applied = ""
    if applied != digest:
        if not svc_active("geovpn-mtproxy"):
            raise RuntimeError("MTProxy configuration pending: service is not running")
        svc_signal("geovpn-mtproxy", "USR2")
        if DATA:
            for _ in range(20):
                rc, ack = sh(["docker", "exec", "geovpn-mtproxy", "cat", "/run/mtproxy-applied"])
                if rc == 0 and ack == digest: break
                time.sleep(0.25)
            else:
                raise RuntimeError("MTProxy did not acknowledge configuration reload")
        atomic_write(marker, digest)


def active_user_ids():
    try:
        users = rw_users()
    except Exception:
        # Keep reconciling local revocations during a panel outage using the last known status.
        users = CACHE["users"][0]
    return {u["id"] for u in users if u["status"] == "ACTIVE"
            and (not parse_ts(u.get("expireAt")) or parse_ts(u["expireAt"]) > now_utc())}


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
def create_user(name, group=MOD_GROUP, operation_id=None, diagnostic=False):
    group = valid_group(group)
    name = " ".join(name.split())[:60]
    if len(name) < 2:
        raise UserError("Укажите имя пользователя")
    with LOCK:
        db = load_db()
        if operation_id:
            previous = next((s for s, u in db["users"].items() if u.get("create_operation") == operation_id), None)
            if previous:
                complete_user_create(db, previous)
                rw_users(force=True)
                awg_apply(db)
                return previous
        existing = {u["username"] for u in rw_users(force=True)} | set(db["users"]) | SERVICE_USERS
        base = slugify(name)
        base = base if len(base) >= 3 else base + "-vpn"
        slug, n = base, 2
        while slug in existing:
            slug, n = f"{base}-{n}", n + 1
        db["users"][slug] = {"name": name, "rw_id": None, "page": new_page_id(slug),
                             "created": now_utc().isoformat(), "awg": awg_new_peer(db), "mt": secrets.token_hex(16),
                             "group": group, "pending_create": True, "blocked": True,
                             "create_operation": operation_id or secrets.token_hex(16),
                             "vless_uuid": str(__import__("uuid").uuid4()), "diagnostic": diagnostic,
                             "expires": (now_utc() + dt.timedelta(minutes=30) if diagnostic else now_utc() + dt.timedelta(days=VALID_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")}
        save_db(db)
        complete_user_create(db, slug)
        rw_users(force=True)
        publish_connections(db)
        awg_apply(db)
        return slug


def complete_user_create(db, slug):
    u = db["users"][slug]
    if not u.get("pending_create"): return
    remote = next((r for r in rw_users(force=True) if r["username"] == slug), None)
    if remote is None:
        st = read_json(STATE)
        remote = rw("POST", "/api/users", {
            "username": slug, "description": u["name"], "vlessUuid": u["vless_uuid"],
            "trafficLimitBytes": 0, "trafficLimitStrategy": "NO_RESET",
            "expireAt": u["expires"],
            "activeInternalSquads": [st["squads"]["clients"]]})
    u["rw_id"] = remote["id"]
    u.pop("pending_create", None)
    if not u.get("pending_action"): u.pop("blocked", None)
    save_db(db)


def finish_user_action(db, slug):
    """Durable intent is retried after a crash; blocked records never grant local access."""
    u = db["users"][slug]
    action, uid = u.get("pending_action"), u["rw_id"]
    if not action: return
    if action in ("disable", "enable"):
        rw("POST", f"/api/users/{uid}/actions/{action}", {})
        u["blocked"] = action == "disable"
    elif action == "reissue":
        rw("POST", f"/api/users/{uid}/actions/revoke", {})
        u.update(u.pop("replacement"))
        u.pop("blocked", None)
    elif action == "delete":
        try:
            rw("DELETE", f"/api/users/{uid}")
        except RuntimeError as e:
            if "HTTP 404" not in str(e): raise
        del db["users"][slug]
    u.pop("pending_action", None)
    save_db(db)


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
        elif action in ("disable", "enable", "reissue", "delete"):
            if u.get("pending_action") and u["pending_action"] != action:
                raise UserError("Предыдущее действие ещё выполняется; дождитесь синхронизации")
            if action == "reissue" and not u.get("replacement"):
                u["replacement"] = {"awg": awg_new_peer(db), "mt": secrets.token_hex(16), "page": new_page_id(slug)}
            u["blocked"] = True
            u["pending_action"] = action
            save_db(db)
            # Local protocols are reconciled even when the remote panel is unavailable.
            failures = []
            try:
                finish_user_action(db, slug)
                rw_users(force=True)
                publish_connections(db)
            except Exception as e:
                failures.append(str(e))
            try:
                awg_apply(db)
            except Exception as e:
                failures.append(str(e))
            if failures:
                raise RuntimeError("Действие сохранено; синхронизация будет повторена: " + "; ".join(failures))
            return
        else:
            raise RuntimeError("Неизвестное действие")
        save_db(db)
        rw_users(force=True)
        awg_apply(db)


def import_existing():
    with LOCK:
        try:
            _import_existing()
        finally:
            # Retry local revocations even when refreshing the panel fails.
            db = load_db()
            publish_connections(db)
            awg_apply(db)


def _import_existing():
    """Adopt Remnawave users created outside the portal (e.g. test-admin)."""
    with LOCK:
        db = load_db()
        for slug in list(db["users"]):
            u = db["users"][slug]
            if u.get("diagnostic") and (now_utc() - parse_ts(u["created"])).total_seconds() > 1800:
                u["blocked"] = True; u["pending_action"] = "delete"; save_db(db)
            try:
                if u.get("pending_create"): complete_user_create(db, slug)
                if u.get("pending_action"): finish_user_action(db, slug)
            except Exception as e:
                print(f"user reconciliation {slug}: {e}", flush=True)
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
                                 "page": new_page_id(slug), "created": ru.get("createdAt"),
                                 "awg": peer or awg_new_peer(db)}
            changed = True
        for u in db["users"].values():          # MTProxy secret for users created before it existed
            if not u.get("mt"):
                u["mt"] = secrets.token_hex(16)
                changed = True
        # drop portal records whose Remnawave user was deleted in the panel
        alive = {u["id"] for u in rw_users()}
        for slug in [s for s, u in db["users"].items()
                     if not u.get("pending_create") and not u.get("pending_action") and u["rw_id"] not in alive]:
            del db["users"][slug]
            changed = True
        if changed:
            save_db(db)
        publish_connections(db)


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
    m["offsite"] = load_db().get("backup_offsite")
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
    """One portable project snapshot + a custom PostgreSQL dump, published only when complete."""
    import backups
    source = os.environ.get("GEOVPN_PROJECT_DATA")
    if not source: raise RuntimeError("GEOVPN_PROJECT_DATA mount is required for complete backups")
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = now_utc().strftime("%Y%m%d-%H%M%S-%f")
    out = os.path.join(BACKUP_DIR, f"msk-{ts}.tar.gz")
    with ProcessLock(os.path.join(BACKUP_DIR, ".backup.lock")), LOCK:
        with tempfile.TemporaryDirectory(dir=BACKUP_DIR, prefix=".dump-") as tmp:
            dump = os.path.join(tmp, "database.dump")
            with open(dump, "wb") as f:
                os.chmod(dump, 0o600)
                r = subprocess.run(["docker", "exec", "remnawave-db", "pg_dump", "-U", "postgres", "-d", "postgres", "-Fc"],
                                   stdout=f, stderr=subprocess.PIPE, timeout=600)
            if r.returncode: raise RuntimeError("pg_dump failed")
            backups.create(source, dump, out)
    for f in sorted(x for x in os.listdir(BACKUP_DIR) if x.startswith("msk-") and x.endswith(".tar.gz"))[:-14]:
        os.remove(os.path.join(BACKUP_DIR, f))
    return backup_offsite(out)


def backup_offsite(path):
    """Copy the backup to an exit: the lowest-priority one first (it carries the least traffic), then the others.
    The exit stores it via a restricted key (servers.HOST_EXTRAS: geovpn-backup-recv, 30 copies)."""
    import paramiko
    name = os.path.basename(path)
    expected_hash = sha256_file(path)
    db = load_db()
    exits = sorted(db.get("exits", {}).values(), key=lambda e: (not e.get("enabled"), -e.get("priority", 0)))
    if not exits:
        return None
    servers.backup_pubkey()
    errs = []
    for e in exits:
        for host in [h for h in (e.get("ip4"), e.get("ip6")) if h]:
            try:
                c = servers.ssh_trust.connect(host, e.get("ssh_port", 22), P("ssh/known_hosts", "/root/.ssh/geovpn_known_hosts"),
                                               key_filename=servers.BACKUP_KEY, expected=e.get("ssh_fingerprint"))
                ch = c.get_transport().open_session()
                ch.settimeout(300)
                ch.exec_command("put " + name + " " + expected_hash)
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        ch.sendall(chunk)
                ch.shutdown_write()
                res = ch.makefile("rb").read().decode(errors="replace").strip()
                c.close()
                if res == "ok " + expected_hash:
                    with LOCK:
                        fresh = load_db()
                        fresh["backup_offsite"] = {"ts": now_utc().isoformat(), "server": e["name"]}
                        save_db(fresh)
                    return e["name"]
                errs.append(f"{e['name']}: {res or 'нет ответа'}")
                break                       # reachable, but refused: the other address won't help
            except Exception as ex:
                errs.append(f"{e['name']} ({host}): {ex}")
    raise RuntimeError("копия бэкапа не отправлена ни на один выход (" + "; ".join(errs)[:300]
                       + "). Ключ приёма ставится при добавлении сервера или: geovpn host-extras <id>")


# ---------------------------------------------------------------- client-side routing audit
# Happ/Hiddify must open RU sites straight from the device (the user's own IP): from the MSK DC IP Avito answers
# "Доступ ограничен: проблема с IP" (2026-10-15), banks may refuse too. RU traffic of MSK_REALITY/MSK_HY2 users on MSK
# (outbound direct-ru) = Hiddify without region Russia or Happ without its routing profile. Amnezia is full-tunnel by design.
RU_AUDIT_AWK = r"""/\[MSK_(REALITY|HY2) -> / && / email: / { e = $NF; t[e]++
  if (index($0, "-> direct-ru]")) { r[e]++; l[e] = $1 "T" $2 } }
END { for (e in t) print e, t[e], r[e] + 0, l[e] }"""
RU_MIN, RU_SHARE = 20, 0.1      # RU connections in the log window (~10 MB, half a day) to call it misconfigured
RU_SHOW_DAYS = 3


def client_label(ua):
    m = re.match(r"(HiddifyNext|Happ)/([\d.]+)(?: \((\w+)\)|/(\w+))?", ua or "")
    if not m:
        return (ua or "")[:30]
    return " ".join(x for x in ("Hiddify" if m[1] == "HiddifyNext" else "Happ", m[2], m[3] or m[4]) if x)


def routing_audit():
    rc, out = sh(["docker", "exec", "remnanode", "awk", RU_AUDIT_AWK, "/var/log/xray/current"], timeout=120)
    if rc != 0:
        raise RuntimeError(f"разбор лога xray: rc={rc}")
    found = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) == 4 and int(p[2]) >= RU_MIN and int(p[2]) >= RU_SHARE * int(p[1]):
            found[p[0]] = {"last": p[3].replace("/", "-") + "+00:00", "ru": int(p[2]), "total": int(p[1])}
    clients = {}
    for rec in rw("GET", "/api/subscription-request-history?start=0&size=200").get("records", []):
        k = str(rec["userId"])
        if rec["requestAt"] > clients.get(k, {}).get("ts", ""):
            clients[k] = {"ts": rec["requestAt"], "app": client_label(rec.get("userAgent"))}
    with LOCK:
        db = load_db()
        seen = db.setdefault("ru_via_msk", {})
        seen.update(found)
        old = (now_utc() - dt.timedelta(days=RU_SHOW_DAYS)).isoformat()
        for k in [k for k, v in seen.items() if v["last"] < old]:
            del seen[k]
        db.setdefault("clients", {}).update(clients)
        save_db(db)


# ---------------------------------------------------------------- geoip/geosite for MSK routing (RU, YouTube, games...)
# The node image carries the lists of its build date and is pinned, so they would never change. Weekly: fetch fresh
# ones (same source as Xray's release), check them, copy into the node and restart xray; roll back if it breaks.
GEO_URL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/"
GEO_DIR = P("geo", "/var/lib/geovpn-portal/geo")
GEO_IN_NODE = "/usr/local/share/xray"
GEO_MUST = {"geosite.dat": (b"CATEGORY-RU", b"YOUTUBE", b"STEAM"), "geoip.dat": (b"PRIVATE",)}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def geo_fetch(name):
    """Download + verify against the published sha256; directly, or through the exits if GitHub is blocked."""
    tmp = os.path.join(GEO_DIR, name + ".new")
    for via in ([], ["--socks5-hostname", "127.0.0.1:10808"]):
        rc, _ = sh(["curl", "-fsSL", "-m", "300", *via, "-o", tmp, GEO_URL + name], timeout=330)
        rc2, sums = sh(["curl", "-fsSL", "-m", "60", *via, GEO_URL + name + ".sha256sum"])
        if rc == 0 and rc2 == 0 and sums.split() and sha256_file(tmp) == sums.split()[0]:
            data = open(tmp, "rb").read()
            if len(data) > (1 << 20) and all(m in data for m in GEO_MUST[name]):
                return tmp
    raise RuntimeError(f"{name}: не скачан или не прошёл проверку")


def node_geo_sha(name):
    rc, out = sh(["docker", "exec", "remnanode", "sha256sum", f"{GEO_IN_NODE}/{name}"])
    return out.split()[0] if rc == 0 and out else ""


def geo_install(files):
    """files: {name: local path}. Copy into the node, restart xray, check the channels; roll back on failure."""
    prev = os.path.join(GEO_DIR, "prev")
    os.makedirs(prev, exist_ok=True)
    for name in files:
        sh(["docker", "cp", f"remnanode:{GEO_IN_NODE}/{name}", os.path.join(prev, name)])

    def put(src):
        for name, path in src.items():
            rc, out = sh(["docker", "cp", path, f"remnanode:{GEO_IN_NODE}/{name}"], timeout=120)
            if rc != 0:
                raise RuntimeError(f"docker cp {name}: {out[-200:]}")
        st = json.load(open(STATE))
        rw("POST", f"/api/nodes/{st['nodes']['MSK']}/actions/restart", {"forceRestart": True})
        for _ in range(12):
            time.sleep(5)
            if probe(10808)[0] and sh(["curl", "-s", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}", "--socks5-hostname",
                                       "127.0.0.1:10803", "https://www.youtube.com/generate_204"])[1] == "204":
                return True
        return False

    try:
        if put(files):
            return True
    except Exception as e:
        print("geo install failed:", repr(e), flush=True)
    put({n: os.path.join(prev, n) for n in files})
    raise RuntimeError("после обновления geoip/geosite xray не заработал — возвращены прежние файлы")


def geo_update(force=False):
    os.makedirs(GEO_DIR, exist_ok=True)
    with ProcessLock(os.path.join(GEO_DIR, ".update.lock")):
        result = _geo_update(force)
        files = {name: {"sha256": sha256_file(os.path.join(GEO_DIR, name)),
                        "bytes": os.path.getsize(os.path.join(GEO_DIR, name))}
                 for name in GEO_MUST if os.path.isfile(os.path.join(GEO_DIR, name))}
        with LOCK:
            db = load_db()
            db["geo_update"] = {"checked": now_utc().isoformat(), "files": files, "source": GEO_URL, "result": result}
            save_db(db)
        return result


def _geo_update(force=False):
    os.makedirs(GEO_DIR, exist_ok=True)
    changed = {}
    for name in GEO_MUST:
        tmp = geo_fetch(name)
        if sha256_file(tmp) != node_geo_sha(name):
            changed[name] = tmp
        else:
            os.replace(tmp, os.path.join(GEO_DIR, name))
    if not changed:
        return "geoip/geosite: актуальны"
    geo_install(changed)
    for name, tmp in changed.items():
        os.replace(tmp, os.path.join(GEO_DIR, name))
    return "geoip/geosite обновлены: " + ", ".join(changed)


def geo_restore():
    """The node container was re-created (update/restart of the stack): it has the image's old lists again."""
    files = {n: os.path.join(GEO_DIR, n) for n in GEO_MUST if os.path.exists(os.path.join(GEO_DIR, n))}
    files = {n: p for n, p in files.items() if node_geo_sha(n) not in ("", sha256_file(p))}
    if files:
        geo_install(files)
        print("geo lists restored in the node:", ", ".join(files), flush=True)


def scheduler():
    """Docker mode only: heartbeat every minute, backup daily ~03:30 MSK, installers weekly."""
    last = {"backup": None, "apps": 0, "geo": None, "geo_check": 0, "audit": 0}
    while True:
        try:
            heartbeat()
        except Exception as e:
            log_error(f"Пульс мониторинга: {e!r}")
        msk = dt.datetime.now(dt.timezone(dt.timedelta(hours=3)))
        done = load_db().get("schedule", {})
        if (msk.hour, msk.minute) >= (3, 30) and done.get("backup") != str(msk.date()) and time.time() - last.get("backup_retry", 0) >= 300:
            last["backup_retry"] = time.time()
            try:
                backup()
                with LOCK:
                    db = load_db(); db.setdefault("schedule", {})["backup"] = str(msk.date()); save_db(db)
            except Exception as e:
                log_error(f"Бэкап не сделан: {e}")
        db = load_db()
        config = routing_policy.updates(db)
        due = routing_policy.last_due(config, msk)
        checked = parse_ts(db.get("geo_update", {}).get("checked"))
        if not checked:
            dates = [os.path.getmtime(os.path.join(GEO_DIR, n)) for n in GEO_MUST if os.path.isfile(os.path.join(GEO_DIR, n))]
            if dates: checked = dt.datetime.fromtimestamp(max(dates), dt.timezone.utc)
        if config["enabled"] and (not checked or checked < due) and time.time() - last.get("geo_retry", 0) >= 300:
            last["geo_retry"] = time.time()
            try:
                print(geo_update(), flush=True)
            except Exception as e:
                log_error(f"Обновление geoip/geosite: {e}")
        elif time.time() - last["geo_check"] > 3600 and time.time() - STARTED > STARTUP_GRACE:
            last["geo_check"] = time.time()
            try:
                geo_restore()
            except Exception as e:
                log_error(f"Возврат свежих geoip/geosite в ноду: {e}")
        if time.time() - last["audit"] > 600 and time.time() - STARTED > STARTUP_GRACE:
            last["audit"] = time.time()
            try:
                routing_audit()
            except Exception as e:
                print("routing audit:", repr(e), flush=True)     # diagnostics only: not worth an alarm
        if time.time() - last["apps"] > 7 * 86400:
            rc, out = sh(["bash", "/app/scripts/apps-update.sh"], timeout=3600)
            if rc != 0:
                log_error("Обновление установщиков приложений: " + out[-300:])
                last["apps"] = time.time() - 7 * 86400 + 300
            else:
                last["apps"] = time.time()
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
    if AWG_NET6 in open(f"{AWG_DIR}/awg0.conf", encoding="utf-8").read():     # IPv6 in the tunnel
        if AWG_NET6 + "1/64" not in sh(["ip", "-6", "addr", "show", "dev", "awg0"])[1]:
            sh(["ip", "-6", "addr", "add", AWG_NET6 + "1/64", "dev", "awg0"])
        if "lookup 100" not in sh(["ip", "-6", "rule"])[1]:
            sh(["ip", "-6", "rule", "add", "fwmark", "0x1", "lookup", "100"])
            log_error("Правило маршрутизации AmneziaWG IPv6 пропало — восстановлено автоматически")
        if "local default" not in sh(["ip", "-6", "route", "show", "table", "100"])[1]:
            sh(["ip", "-6", "route", "replace", "local", "::/0", "dev", "lo", "table", "100"])


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
            if time.time() - STARTED > STARTUP_GRACE:
                log_error(f"Фоновая задача портала: {e!r}")
            else:
                print("background (startup, not logged):", repr(e), flush=True)
        try:
            import diagnostics
            diagnostics.tick()
        except Exception as e:
            print("routing checks:", type(e).__name__, flush=True)
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
    with open(os.path.join(os.path.dirname(__file__), "ui.css"), encoding="utf-8") as f:
        styles = CSS + f.read()
    with open(os.path.join(os.path.dirname(__file__), "admin.js"), encoding="utf-8") as f:
        behavior = f.read()
    return (f'<!doctype html><html lang="ru"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<meta name="robots" content="noindex,nofollow"><title>{esc(title)}</title><style>{styles}</style></head>'
            f'<body>{body}<script>{JS_COMMON}{behavior}{js}</script></body></html>')


def admin_nav(current, role="a"):
    links = [("users", "/admin", "Пользователи"), ("servers", "/admin/servers", "Серверы")]
    if role == "a": links.append(("routing", "/admin/routing", "Маршрутизация"))
    return ('<nav class="site-nav" aria-label="Основная навигация">'
            f'<a class="brand" href="/admin">{esc(BRAND)}</a>'
            + "".join(f'<a class="{"active" if key == current else ""}" href="{url}"'
                      f'{" aria-current=page" if key == current else ""}>{label}</a>' for key, url, label in links)
            + '<a href="/logout">Выйти</a></nav>')


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
def render_admin(msg=None, err=None, hl=None, role="u", gfilter=None, live=False):
    m = CACHE["mon"][0] if live and CACHE["mon"][0] else monitoring()
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
    off = m.get("offsite") or {}
    ot = parse_ts(off.get("ts"))
    host += (f'<div class="kv"><span>Копия на выходе</span><span>'
             f'{pill(ot and (now_utc() - ot).days < 2, esc(off.get("server", "")) + ", " + ago(ot), "нет" if not ot else ago(ot))}</span></div>')

    # users (moderator: only MOD_GROUP; admin: ADMIN_GROUP by default, ?g=all for everyone)
    is_admin = role == "a"
    groups = sorted({ugroup(x) for x in db["users"].values() if not x.get("diagnostic")} | {MOD_GROUP})
    if not is_admin:
        gfilter = MOD_GROUP
    elif gfilter is None and ADMIN_GROUP in groups:
        gfilter = ADMIN_GROUP
    elif gfilter not in groups:
        gfilter = None
    visible = {s: x for s, x in db["users"].items() if not x.get("diagnostic") and (not gfilter or ugroup(x) == gfilter)}

    def group_cell(slug, u):
        g = ugroup(u)
        if not is_admin:
            return f'<span class="pill no">{esc(g)}</span>'
        opts = "".join(f'<option value="{esc(x)}"{" selected" if x == g else ""}>{esc(x)}</option>' for x in groups)
        return (f'<form method="post" action="/admin/u/{esc(slug)}/group" style="display:inline">'
                f'<input type="hidden" name="g" value="{esc(gfilter or "all")}">'
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
        if u.get("pending_create") or u.get("pending_action"):
            spill = ("warnp", "ожидает синхронизации")
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
        app_ = db.get("clients", {}).get(str(u["rw_id"]), {}).get("app")
        rv = db.get("ru_via_msk", {}).get(str(u["rw_id"]))
        ru_warn = (f' <span class="pill warnp" title="Российские сайты этого пользователя идут через сервер '
                   f'({rv["ru"]} из {rv["total"]} соединений), а не напрямую с устройства: в Hiddify не выбран регион '
                   f'«Россия», в Happ не включена маршрутизация {esc(BRAND)}. Avito и банки могут не открываться.">'
                   f'RU через сервер · {ago(parse_ts(rv["last"]))}</span>') if rv else ""
        act = lambda a_, label, cls="alt", conf="": (
            f'<form method="post" action="/admin/u/{esc(slug)}/{a_}" style="display:inline"'
            f'{" onsubmit=" + chr(34) + "return confirm(" + esc(json.dumps(conf)) + ")" + chr(34) if conf else ""}>'
            f'<input type="hidden" name="g" value="{esc(gfilter or "all")}">'
            f'<button class="btn sm {cls}">{label}</button></form>')
        # sort keys for the client-side ordering (status: online first, disabled last)
        st_rank = (0 if online else 1) if is_active else {"LIMITED": 2, "EXPIRED": 3, "DISABLED": 4}.get(stt, 5)
        rows += (
            f'<tr class="user-row {"hl" if slug == hl else ""}" tabindex="0" data-user="{esc(slug)}" data-title="{esc(u["name"])}" data-name="{esc(u["name"].lower())}" data-created="{esc(u.get("created") or "")}"'
            f' data-exp="{exp.isoformat() if exp else "9999"}" data-st="{st_rank}"><td><div class="nm">{esc(u["name"])}</div>'
            f'<div class="mut">{esc(slug)}</div></td>'
            f'<td>{group_cell(slug, u)}</td>'
            f'<td><span class="pill {spill[0]}">{spill[1]}</span>{" <span class=\"pill on\">online</span>" if online else ""}{ru_warn}</td>'
            f'<td><span class="{exp_cls}">{fmt_date(exp)}</span></td>'
            f'<td><span class="mut">{fmt_date(parse_ts(u.get("created")))}</span></td>'
            f'<td class="hide-sm">{gb(tr.get("lifetimeUsedTrafficBytes"))}<div class="mut">{ago(on_rw)}</div>'
            f'{f"<div class=mut>{esc(app_)}</div>" if app_ else ""}</td>'
            f'<td class="hide-sm">{gb((a.get("rx") or 0) + (a.get("tx") or 0))}<div class="mut">{ago(hs)}</div></td>'
            f'<td class="hide-sm">{gb(mt.get("octets"))}<div class="mut">{"подключён" if mt.get("curr") else "—"}</div></td>'
            f'<td><button class="btn sm" onclick="copyText({esc(json.dumps(invite_text(u), ensure_ascii=False))}, this)">Копировать</button>'
            f'<a class="btn sm alt" href="/sub/{esc(u["page"])}" target="_blank" rel="noopener">Страница</a>'
            f'<button type="button" class="btn sm alt" aria-label="Действия пользователя {esc(u["name"])}" onclick="openUserActions(this.closest(\'tr\'))">···</button>'
            f'<template id="actions-{esc(slug)}">{act("extend", "Продлить на год")}'
            f'{act("disable", "Отключить доступ", "alt", "Отключить доступ " + u["name"] + "?") if is_active else act("enable", "Включить доступ")}'
            f'{act("reissue", "Перевыпустить ключи", "alt", "Перевыпустить доступ " + u["name"] + "? Старая ссылка, подписка и конфиг Amnezia перестанут работать.")}'
            f'{act("delete", "Удалить пользователя", "danger", "Удалить пользователя " + u["name"] + " безвозвратно?")}</template></td></tr>')

    alert = ""
    if msg:
        alert = f'<div class="card ok">{esc(msg)}</div>'
    if err:
        alert = f'<div class="card err">{esc(err)}</div>'
    newbox = ""
    if hl and hl in db["users"] and (is_admin or ugroup(db["users"][hl]) == MOD_GROUP):
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
    group_sel = ""
    if is_admin:
        group_sel = ('<span class="mut">Группа:</span><div style="width:240px">'
                     f'<select style="{SEL}" onchange="location.href=this.value">'
                     + f'<option value="/admin?g=all"{"" if gfilter else " selected"}>все группы · {len(db["users"])}</option>'
                     + "".join(f'<option value="/admin?g={quote(g)}"{" selected" if g == gfilter else ""}>{esc(g)} · {counts[g]}</option>'
                               for g in groups)
                     + '</select></div>')
    group_tabs = (f'<div id="user-groups" class="row" style="margin-bottom:12px">{group_sel}</div>' if group_sel else "") + """<style>
#utab th.srt { cursor: pointer; user-select: none; white-space: nowrap; }
#utab th.srt:hover { color: #fff; }
#utab th.srt::after { content: " \\2195"; opacity: .35; }
#utab th.srt[data-dir="asc"]::after { content: " \\25B2"; opacity: 1; }
#utab th.srt[data-dir="desc"]::after { content: " \\25BC"; opacity: 1; }
</style><script>
// click a column header to sort (again - reverse); default: newest first; choice remembered in the browser
function sortUsers(k, dir) {
  const th = document.querySelector('#utab th[data-k="' + k + '"]');
  if (!th) return;
  if (!dir) dir = th.dataset.dir === "asc" ? "desc" : "asc";
  try { localStorage.setItem("gvSort", k + ":" + dir); } catch (e) {}
  const s = dir === "asc" ? 1 : -1;
  const rows = [...document.querySelectorAll("#utab tr[data-name]")];
  rows.sort((a, b) => s * a.dataset[k].localeCompare(b.dataset[k], "ru") || a.dataset.name.localeCompare(b.dataset.name, "ru"))
      .forEach(r => r.parentNode.appendChild(r));
  document.querySelectorAll("#utab th[data-k]").forEach(h => { h.dataset.dir = h === th ? dir : ""; });
}
document.addEventListener("DOMContentLoaded", () => {
  let v; try { v = localStorage.getItem("gvSort"); } catch (e) {}
  if (v && v.includes(":")) sortUsers(...v.split(":"));
});
</script>"""
    if live:
        return {"rows": rows or '<tr><td colspan="9" class="mut">Пока никого нет</td></tr>',
                "summary": summary, "count": len(visible), "online": total_online, "groups": group_sel,
                "updated": now_utc().astimezone(dt.timezone(dt.timedelta(hours=3))).strftime("%H:%M:%S")}
    body = f"""<div class="wrap">{admin_nav('users', role)}
<h1>Пользователи</h1>
<div class="sub">Пользователей{"" if is_admin and not gfilter else " в группе " + esc(gfilter)}: <span id="user-count">{len(visible)}</span> · сейчас online: <span id="user-online">{total_online}</span> · <span id="live-state">обновляется автоматически</span> <span id="live-updated"></span> · <span class="mut">{ROLE_NAMES.get(role, "")}</span>{' · <a class="inline" href="/" target="_blank">Remnawave</a>' if is_admin else ''}</div>
{alert}{newbox}
<div class="card"><h2>Создать пользователя</h2>
<form method="post" action="/admin/create" class="row">
<input type="hidden" name="operation" value="{secrets.token_hex(16)}">
<div style="flex:1;min-width:240px"><input type="text" name="name" placeholder="Фамилия Имя, например: Карбышев Дмитрий" required maxlength="60"></div>
{(f'<div style="width:190px"><select name="group" style="{SEL}" onchange="document.getElementById(\'gnew\').hidden = this.value !== \'__new\'">'
   + "".join(f'<option value="{esc(x)}"{" selected" if x == (gfilter or MOD_GROUP) else ""}>группа {esc(x)}</option>' for x in groups)
   + '<option value="__new">➕ новая группа…</option></select></div>'
   '<div id="gnew" hidden style="width:170px"><input type="text" name="group_new" placeholder="название группы" maxlength="20"></div>')
  if is_admin else f'<input type="hidden" name="group" value="{MOD_GROUP}"><span class="pill no">группа {MOD_GROUP}</span>'}
<button class="btn" style="margin:0">Создать — 1 год, без лимитов</button></form>
<p class="note">Happ/Hiddify, AmneziaWG и Telegram — одно приглашение для всех способов подключения.</p></div>
<details class="card" style="padding:14px 18px"><summary style="cursor:pointer;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
<b>Состояние системы</b> <span id="system-summary">{summary}</span></summary>
<div class="grid" style="margin-top:14px">
<div class="card"><h2>Ноды</h2>{nodes or '<span class="mut">нет данных</span>'}</div>
<div class="card"><h2>Каналы</h2>{chans}</div>
<div class="card"><h2>Службы MSK</h2>{svc}</div>
<div class="card"><h2>Сервер MSK</h2>{host}</div>
</div></details>
<div class="card"><div class="search-row"><h2>Список пользователей</h2><input type="search" aria-label="Найти пользователя" placeholder="Найти по имени…" oninput="document.querySelectorAll('#utab tr[data-name]').forEach(r=>r.hidden=!r.dataset.name.includes(this.value.toLowerCase()))"></div>{group_tabs}<div class="scroll"><table id="utab">
<thead><tr><th class="srt" data-k="name" onclick="sortUsers('name')">Пользователь</th><th>Группа</th>
<th class="srt" data-k="st" onclick="sortUsers('st')">Статус</th><th class="srt" data-k="exp" onclick="sortUsers('exp')">До</th>
<th class="srt" data-k="created" data-dir="desc" onclick="sortUsers('created')">Создан</th><th class="hide-sm">Happ/Hiddify<br><span class="mut">трафик · активность</span></th>
<th class="hide-sm">Amnezia<br><span class="mut">трафик* · активность</span></th><th class="hide-sm">Telegram<br><span class="mut">трафик* · сейчас</span></th><th>Подключение</th></tr></thead>
<tbody id="user-rows">{rows or '<tr><td colspan="9" class="mut">Пока никого нет</td></tr>'}</tbody>
</table></div><details><summary>О статусах и статистике</summary><p class="note">* трафик Amnezia и Telegram считается с последнего перезапуска службы. «+1 год» продлевает от текущей даты окончания.
«RU через сервер» — у пользователя российские сайты идут через сервер, а не напрямую: в Hiddify не выбран регион «Россия» (шаг 3 на его странице), в Happ не включена маршрутизация {esc(BRAND)}. Проверка раз в 10 минут, метка держится 3 дня.</p></details></div>
</div><dialog id="user-actions-dialog" class="user-dialog"><div class="dialog-heading"><div><h2 id="user-actions-title"></h2><p class="hint">Управление доступом</p></div><button class="dialog-close" type="button" aria-label="Закрыть" onclick="this.closest('dialog').close()">×</button></div><div id="user-actions-content" class="user-action-list"></div></dialog>"""
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
    version = a.get("file_versions", {}).get(fname, "")
    if not size:
        return f'<span class="btn alt download-pending" aria-disabled="true">{esc(label)}<span class="sz">файл готовится</span></span>'
    return (f'<a class="btn alt" href="/app/{fname}"{f" data-os={chr(34)}{os_}{chr(34)}" if os_ else ""}>{esc(label)}'
            f'<span class="sz">{esc(version)} · {size / 1e6:.0f} МБ</span></a>')


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
    head = f'<div class="wrap narrow"><h1>{esc(BRAND)}</h1><div class="sub">Персональная страница подключения — {esc(name)}</div>'
    if u.get("blocked") or not r or r["status"] != "ACTIVE":
        reason = {"EXPIRED": "Срок действия доступа истёк.", "DISABLED": "Доступ приостановлен.",
                  "LIMITED": "Исчерпан лимит трафика."}.get((r or {}).get("status"), "Доступ недоступен.")
        return page(f"{BRAND} — подключение", head + f'<div class="card"><h2>{reason}</h2>'
                    f'<p class="hint">Обратитесь к администратору.</p></div></div>')
    sub = r["subscriptionUrl"]
    sub_named = sub + "#" + quote(name)
    vpnkey = awg_vpn_key(u["awg"], f"{BRAND} — {name}")
    tg_link, _ = mt_links(u)
    android_note = '<p class="note">На Android при установке файла появится предупреждение о неизвестном источнике — это нормально, приложение скачивается с нашего сервера, а не из Google Play.</p>'

    # Happ first: it takes the routing profile from the subscription (RU sites straight from the device, updated by us);
    # Hiddify accepts no rules from a subscription - the user has to set the region by hand (cli.happ_routing)
    happ = option("happ", "H", "#3866ff", "Happ", '<span class="badge rec">Рекомендуем</span>',
        "Основной вариант. Российские сайты (банки, Госуслуги, Avito) открываются напрямую, остальное — через VPN. Ничего настраивать не нужно: правила приходят с сервера и обновляются сами.",
        "Windows · Android · Mac · iPhone и iPad",
        step(1, "Установите приложение",
             f'<div class="dls">{dl("Happ-windows.exe", "Windows", "windows")}{dl("Happ-android.apk", "Android", "android")}'
             f'{dl("Happ-macos.dmg", "Mac", "mac")}{store("https://apps.apple.com/us/app/happ-proxy-utility/id6504287215", "iPhone / iPad — App Store")}</div>'
             f'<p class="note">Выделена кнопка для <span class="os-name"></span>. Версия указана у файла для вашей платформы.</p>{android_note}')
        + step(2, "Добавьте подключение",
             connect_block(sub, "m", "happ-uri", sub, f'<a class="btn" href="happ://add/{esc(sub)}">Открыть в Happ</a>',
                           "Кнопка сама добавит подключение в Happ. Или отсканируйте QR-код в приложении (кнопка «+» → QR), или скопируйте ссылку и добавьте её из буфера обмена:"))
        + step(3, "Подключитесь",
             f'<ol><li>Если Happ спросит про профиль маршрутизации <b>{esc(BRAND)}</b> — согласитесь: с ним российские сайты работают напрямую.</li>'
             f'<li>В списке выберите <b>{esc(BRAND)} авто</b> и нажмите большую кнопку подключения. Happ сам выбирает лучший способ подключения '
             'и переключается, если один не работает в этой сети (например, на Wi-Fi, где его режут).</li>'
             '<li>Для игр на Windows включите режим «Системный прокси» — игры пойдут мимо VPN. На Android игры можно исключить в «Раздельном туннелировании».</li></ol>'
             '<p class="note">Настройки обновляются сами: если на сервере что-то изменится, приложение получит это автоматически.</p>'))

    hiddify = option("hiddify", "Hi", "#6d4aff", "Hiddify", '<span class="badge">Альтернатива</span>',
        "Если Happ не подходит. Сам выбирает самый быстрый способ подключения. Нужно один раз настроить регион и DNS (шаг 3), иначе российские сайты пойдут через VPN и некоторые (Avito, банки) не откроются.",
        "Windows · Android · Mac · iPhone и iPad",
        step(1, "Установите приложение",
             f'<div class="dls">{dl("Hiddify-windows.exe", "Windows", "windows")}{dl("Hiddify-android.apk", "Android", "android")}'
             f'{dl("Hiddify-macos.dmg", "Mac", "mac")}{store("https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532", "iPhone / iPad — Hiddify")}</div>'
             f'<p class="note">Если Hiddify нет в App Store вашей страны, подойдёт '
             f'<a class="inline" href="https://apps.apple.com/us/app/incy/id6756943388" target="_blank" rel="noopener">INCY</a> — ссылка подключения та же. '
             f'Версия указана у файла для вашей платформы.</p>{android_note}')
        + step(2, "Добавьте подключение",
             connect_block(sub_named, "m", "hid-uri", sub_named, f'<a class="btn" href="hiddify://import/{esc(sub_named)}">Открыть в Hiddify</a>',
                           "Кнопка сама добавит подключение в Hiddify. Или в приложении нажмите «Добавить профиль» и отсканируйте QR-код / вставьте ссылку:"))
        # labels as in Hiddify 4.1.1 (assets/translations/ru.i18n.json); DoH by IP: works where port 53 is blocked
        + step(3, "Настройте один раз и подключитесь",
             '<ol><li><b>Настройки → Маршрутизация → Регион</b>: выберите <b>Россия (ru)</b>. '
             '<b>Обязательно</b> — без этого банки, Госуслуги и Avito пойдут через VPN и могут не открыться.</li>'
             '<li>Там же <b>Маршрут IPv6</b>: <b>Включить</b> — иначе на некоторых Wi-Fi часть приложений (например, Instagram) пойдёт мимо VPN и не будет работать.</li>'
             '<li><b>Настройки → DNS → Распознаватель исходящего сервера (напрямую)</b>: впишите '
             '<code style="display:inline;padding:1px 6px">https://77.88.8.8/dns-query</code> — так интернет будет работать и в сетях, где закрыт обычный DNS (гостиницы, офисы).</li>'
             '<li>Нажмите большую кнопку подключения — Hiddify сам выберет работающий сервер.</li></ol>'
             '<p class="note">Если Wi-Fi просит войти через страницу (гостиница, кафе, метро) — отключите VPN, войдите, затем включите снова.</p>'))

    amnezia = option("amnezia", "A", "#0f9d74", "Amnezia", '<span class="badge">Другой протокол</span>',
        "Принципиально другой протокол (AmneziaWG), не связанный с Hiddify и Happ. Может работать, когда они не подключаются — например, если их блокирует провайдер, мобильная сеть или сеть на работе.",
        "Windows · Android · Mac · iPhone и iPad",
        step(1, "Установите приложение",
             f'<div class="dls">{dl("AmneziaVPN-windows.exe", "Windows", "windows")}{dl("AmneziaVPN-android.apk", "Android", "android")}'
             f'{dl("AmneziaVPN-macos.pkg", "Mac", "mac")}{store("https://apps.apple.com/us/app/amneziavpn/id1600529900", "iPhone / iPad — App Store")}</div>'
             f'<p class="note">Старый Android (9–10): {dl("AmneziaVPN-android-9-10.apk", "Android 9–10") or "—"} '
             f'Если Amnezia нет в App Store вашей страны: <a class="inline" href="https://apps.apple.com/us/app/defaultvpn/id6744725017" target="_blank" rel="noopener">DefaultVPN</a>. '
             f'Нужна версия 4.8.12.9 или новее. Версия файла указана у кнопки скачивания.</p>{android_note}')
        + step(2, "Добавьте подключение",
             connect_block(vpnkey[len("vpn://"):], "l", "awg-uri", vpnkey,
                           f'<a class="btn" href="/sub/{esc(u["page"])}/conf">Скачать файл подключения</a>',
                           "Откройте скачанный файл в Amnezia. Или в приложении нажмите «+» и отсканируйте QR-код / вставьте ссылку:"))
        + step(3, "Подключитесь",
             '<ol><li>Нажмите «Подключиться».</li>'
             '<li>Игры и отдельные приложения можно пустить мимо VPN в разделе «Раздельное туннелирование».</li></ol>'
             '<p class="note">В Amnezia через VPN идёт всё, в том числе российские сайты — а Avito и некоторые банки не пускают с адреса сервера. '
             'Для них отключайте VPN или добавьте их в «Раздельное туннелирование». Если такое мешает — выберите Happ.</p>'))

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
откроется пошаговая инструкция. Не знаете, что выбрать, — берите <b>Happ</b>.</div>
<div class="opts">{happ}{hiddify}{amnezia}{telegram}</div>
<div class="card"><div class="hint" style="margin:0">Доступ действует до <b>{fmt_date(r.get("expireAt"))}</b>.</div>
<div class="warn" style="margin-top:10px"><b>Страница является персональной.</b>
Подключиться по ней может любой, кто получит ссылку — пароль не запрашивается.<br>
Настоятельно не рекомендуется передавать ссылку третьим лицам. Это может привести как к замедлению работы вашего
подключения из-за большого числа одновременных сессий, так и к блокировке сервиса целиком.</div></div>
<div class="foot">{esc(client_ip)}</div></div>"""
    return page(f"{BRAND} — подключение", f"<style>{USER_CSS}</style>" + body, USER_JS)


def new_page_id(slug):
    # the personal page holds every key of the user: 128 random bits (it used to be 24 bits after a guessable name)
    return f"{slug}-{secrets.token_hex(16)}"


PAGE_MISSES = {}     # client ip -> [timestamps of unknown /sub/... ids]: throttles guessing of page addresses


def page_throttled(ip, miss=False):
    now = time.time()
    with MEMORY_LOCK:
        t = [x for x in PAGE_MISSES.get(ip, []) if now - x < 600]
        if miss:
            t.append(now)
        PAGE_MISSES[ip] = t
        if len(PAGE_MISSES) > 10000:
            PAGE_MISSES.clear()
        return len(t) > 20


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
    what = "Панель Remnawave" if need_for(nxt) == "a" else f"Управление {esc(BRAND)}"
    return page(f"{BRAND} — вход", f"""<div class="wrap" style="max-width:420px">
<h1>{esc(BRAND)} — вход</h1><div class="sub">{what}: требуется пароль.</div>
{f'<div class="card err">{esc(err)}</div>' if err else ''}
<div class="card"><form method="post" action="/login">
<input type="hidden" name="next" value="{esc(nxt)}">
<input type="password" name="password" placeholder="Пароль" required autofocus style="margin-bottom:12px">
<button class="btn" style="margin:0">Войти</button></form></div></div>""")


# ---------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    server_version = "geovpn"
    sys_version = ""

    def setup(self):
        self.request.settimeout(15)
        super().setup()

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
        fallback = self.client_address[0] if isinstance(self.client_address, tuple) else "127.0.0.1"
        return (self.headers.get("X-Forwarded-For") or fallback).split(",")[0].strip()

    def not_found(self):
        self.send(404, page("Не найдено", '<div class="wrap narrow"><div class="card"><h2>Страница не найдена</h2>'
                                           '<p class="hint">Проверьте ссылку или обратитесь к администратору.</p></div></div>'))

    def do_GET(self):
        url = urlparse(self.path)
        p = url.path
        if PUBLIC and not re.fullmatch(r"/(?:sub|c)/[a-z0-9-]+(?:/conf)?/?", p):
            return self.not_found()
        try:
            if p == "/healthz" and not PUBLIC:
                rw("GET", "/api/nodes")
                return self.send(200, "ready", "text/plain")
            m = re.fullmatch(r"/(?:sub|c)/([a-z0-9-]+)(/conf)?/?", p)
            if m:
                if not PUBLIC and PUBLIC_DIR: return self.not_found()
                ip = self.client_ip()
                if page_throttled(ip):
                    return self.send(429, "Too many requests, try again in 10 minutes", "text/plain")
                slug, u = find_by_page(m.group(1))
                if not u:
                    page_throttled(ip, miss=True)
                    return self.not_found()
                if m.group(2):
                    r = rw_user_by_id(u["rw_id"])
                    if u.get("blocked") or not r or r["status"] != "ACTIVE":
                        return self.not_found()
                    return self.send(200, awg_client_conf(u["awg"]), "application/octet-stream",
                                     {"Content-Disposition": f"attachment; filename=\"vpn-{slug}.conf\"; filename*=UTF-8''{quote(BRAND + '-' + slug + '.conf', safe='')}"})
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
                if p in ("/admin/routing", "/admin/routing/status", "/admin/routing/health"):
                    if session_role(self.headers.get("Cookie")) != "a": return self.send(403, "forbidden", "text/plain")
                    import routing_admin
                    if p.endswith("/health"):
                        summary, detail = routing_admin.check_summary(load_db())
                        return self.send(200, json.dumps({"summary": summary, "detail": detail}), "application/json")
                    if p.endswith("/status"):
                        return self.send(200, json.dumps(routing_admin.status(parse_qs(url.query))), "application/json")
                    return self.send(200, routing_admin.render(parse_qs(url.query)))
                if p.startswith("/admin/servers"):
                    r = servers.handle_get(self, p, parse_qs(url.query), readonly=session_role(self.headers.get("Cookie")) != "a")
                    return r if r is not None else self.not_found()
                if p in ("/admin", "/admin/", "/admin/live"):
                    q = parse_qs(url.query)
                    if p == "/admin/live":
                        return self.send(200, json.dumps(render_admin(role=session_role(self.headers.get("Cookie")), gfilter=q.get("g", [None])[0], live=True)), "application/json")
                    return self.send(200, render_admin(q.get("msg", [None])[0], q.get("err", [None])[0], q.get("new", [None])[0],
                                                       session_role(self.headers.get("Cookie")), q.get("g", [None])[0]))
            return self.not_found()
        except Exception as e:
            if PUBLIC:
                return self.send(503, "Connection pages temporarily unavailable", "text/plain")
            if not isinstance(e, (BrokenPipeError, ConnectionResetError)):
                log_error(f"Ошибка страницы {self.path.split('?')[0]}: {e!r}")
            self.send(500, page("Ошибка", f'<div class="wrap narrow"><div class="card err">Ошибка: {esc(e)}</div></div>'))

    def do_POST(self):
        if PUBLIC:
            # Drain small rejected bodies so callers receive a 404 rather than a reset.
            try: length = int(self.headers.get("Content-Length") or 0)
            except ValueError: length = 0
            if 0 < length <= 65536: self.rfile.read(length)
            return self.not_found()
        p = urlparse(self.path).path
        origin = self.headers.get("Origin")
        if origin and origin != BASE_URL:
            return self.send(403, "forbidden", "text/plain")
        try: n = int(self.headers.get("Content-Length") or 0)
        except ValueError: return self.send(400, "Invalid Content-Length", "text/plain")
        if not 0 <= n <= 65536 or self.headers.get("Transfer-Encoding"):
            return self.send(413, "Request body too large", "text/plain")
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
            if p.startswith("/admin/routing/"):
                if role != "a": return self.send(403, "forbidden", "text/plain")
                import routing_admin
                return routing_admin.handle_post(self, p, {k: v[0] for k, v in form.items()})
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
                operation = form.get("operation", [""])[0]
                if not re.fullmatch(r"[a-f0-9]{32}", operation):
                    raise UserError("Обновите страницу и повторите создание пользователя")
                slug = create_user(form.get("name", [""])[0], grp, operation)
                return self.redirect(f"/admin?g={quote(grp)}&new={quote(slug)}&msg=" + quote("Пользователь создан"))
            m = re.fullmatch(r"/admin/u/([a-z0-9-]+)/(extend|disable|enable|reissue|delete|group)", p)
            if m:
                user_action(m.group(1), m.group(2), role, form.get("group", [None])[0])
                msgs = {"extend": "Доступ продлён на год", "disable": "Доступ отключён", "enable": "Доступ включён",
                        "group": "Пользователь перенесён в группу " + (form.get("group", [""])[0] or ""),
                        "reissue": "Доступ перевыпущен — отправьте пользователю новое приглашение", "delete": "Пользователь удалён"}
                hl = "" if m.group(2) == "delete" else f"&new={quote(m.group(1))}" if m.group(2) == "reissue" else ""
                g = form.get("group" if m.group(2) == "group" else "g", ["all"])[0]
                return self.redirect("/admin?g=" + quote(g) + "&msg=" + quote(msgs[m.group(2)]) + hl)
            return self.not_found()
        except (BrokenPipeError, ConnectionResetError):
            return None  # the browser went away before reading the answer - nothing to report
        except Exception as e:
            if not isinstance(e, UserError):
                log_error(f"Действие в админке ({p}): {e}")
            return self.redirect("/admin?err=" + quote(str(e)[:300]))


class WebServer(ThreadingHTTPServer):
    """Bound memory/threads consumed by slow or unauthenticated clients."""
    daemon_threads = True

    def __init__(self, *args):
        self.slots = threading.BoundedSemaphore(64)
        super().__init__(*args)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try: super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try: super().process_request_thread(request, address)
        finally: self.slots.release()


class PublicServer(WebServer):
    address_family = getattr(socket, "AF_UNIX", socket.AF_INET)

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "public", 0


if __name__ == "__main__" and PUBLIC:
    if not hasattr(socket, "AF_UNIX"): raise RuntimeError("Public worker requires Unix sockets (Linux container)")
    path = os.environ.get("GEOVPN_PUBLIC_SOCKET", "/run/geovpn-public/http.sock")
    if os.path.exists(path): os.unlink(path)
    server = PublicServer(path, H)
    os.chmod(path, 0o660)
    server.serve_forever()
elif __name__ == "__main__":
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with LOCK:
        db = load_db()
        if routing_policy.migrate_legacy(db, read_json(DIRECT_JSON, {})):
            save_db(db)
    try:
        import_existing()
    except Exception as e:
        print("initial import failed:", e, flush=True)
    threading.Thread(target=background, daemon=True).start()
    threading.Thread(target=servers.watchdog, daemon=True).start()
    if DATA:
        threading.Thread(target=scheduler, daemon=True).start()
    print("geovpn-portal listening on %s:%d" % LISTEN, flush=True)
    WebServer(LISTEN, H).serve_forever()
