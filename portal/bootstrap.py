#!/usr/bin/env python3
"""First-time setup of a fresh entry server (run once by install.sh inside the portal image).

Remnawave: admin account, API token, Reality keys, MSK config profile, squads, MSK node, hosts, bridge user.
Local: AmneziaWG server keys + obfuscation params, MTProxy config, portal password hashes, state.json.
Idempotent: parts that already exist are skipped.
"""
import hashlib, json, os, random, secrets, subprocess, sys, time, urllib.error, urllib.request, uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app  # noqa: E402

D = app.HOST
NODE_GW = os.environ.get("NODE_GW", "172.28.0.1")      # docker gateway of remnawave-network (backend -> node)
AWG_PORT = int(os.environ.get("AWG_PORT", "0")) or random.randint(30000, 60000)


def env_set(path, **kv):
    lines = open(path).read().splitlines() if os.path.exists(path) else []
    lines = [l for l in lines if l.split("=", 1)[0] not in kv] + [f"{k}={v}" for k, v in kv.items()]
    open(path, "w").write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)


def api(method, path, body=None, token=None):
    h = {"Content-Type": "application/json", "X-Forwarded-For": "127.0.0.1", "X-Forwarded-Proto": "https",
         "x-remnawave-client-type": "browser"}
    if token:
        h["Authorization"] = "Bearer " + token
    req = urllib.request.Request("http://127.0.0.1:3000" + path, method=method, headers=h,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return json.loads(raw).get("response") if raw.strip() else None
    except urllib.error.HTTPError as e:
        raise SystemExit(f"Remnawave {method} {path}: HTTP {e.code} {e.read().decode()[:400]}")


def wait_api():
    for _ in range(90):
        try:
            if api("GET", "/api/auth/status") is not None:
                return
        except (SystemExit, OSError):
            pass
        time.sleep(3)
    raise SystemExit("Remnawave API did not come up")


def reality_in(tag, priv, sid):
    return {"tag": tag, "listen": "0.0.0.0", "port": 443, "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality",
                               "realitySettings": {"show": False, "target": "127.0.0.1:8443", "xver": 2, "serverNames": [D],
                                                   "privateKey": priv, "shortIds": [sid], "minClientVer": "1.0.0"}},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}}


def initial_msk_profile(k):
    """Minimal profile; the portal regenerates the full one (exits, balancer, monitoring) on start."""
    cert = f"/var/lib/remnawave/configs/xray/ssl/{D}"
    return {"log": {"loglevel": "warning"},
            "inbounds": [reality_in("MSK_REALITY", k["priv"], k["sid"]),
                         {"tag": "MSK_HY2", "listen": "0.0.0.0", "port": 443, "protocol": "hysteria",
                          "settings": {"version": 2, "clients": []},
                          "streamSettings": {"network": "hysteria", "security": "tls",
                                             "tlsSettings": {"alpn": ["h3"], "certificates": [
                                                 {"certificateFile": f"{cert}/{D}.crt", "keyFile": f"{cert}/{D}.key"}]},
                                             "hysteriaSettings": {"version": 2}},
                          "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
                         {"tag": "AWG_BRIDGE", "listen": "127.0.0.1", "port": 10808, "protocol": "mixed",
                          "settings": {"udp": True}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
                         {"tag": "MON_YT", "listen": "127.0.0.1", "port": 10803, "protocol": "mixed", "settings": {"udp": False}},
                         {"tag": "MTP_OUT", "listen": "127.0.0.1", "port": 10804, "protocol": "mixed", "settings": {"udp": False}}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"},
                          {"tag": "yt-dpi", "protocol": "freedom", "settings": {"domainStrategy": "ForceIPv6v4"}},
                          {"tag": "block", "protocol": "blackhole"}],
            "routing": {"domainStrategy": "IPIfNonMatch",
                        "rules": [{"ip": ["geoip:private"], "outboundTag": "block"},
                                  {"protocol": ["bittorrent"], "outboundTag": "block"}]}}


def provision_remnawave():
    if os.path.exists(app.STATE):
        print("state.json exists - Remnawave already provisioned, skipping")
        return
    wait_api()
    sec = app.env_file(app.SECRETS)
    admin_pw = sec.get("RW_ADMIN_PASS") or secrets.token_urlsafe(18)
    env_set(app.SECRETS, RW_ADMIN_PASS=admin_pw)
    r = api("POST", "/api/auth/register", {"username": os.environ.get("RW_ADMIN_USER", "geoadmin"), "password": admin_pw})
    jwt = r["accessToken"]
    tok = api("POST", "/api/tokens", {"name": "geovpn-portal", "expiresInDays": 3650}, token=jwt)["token"]
    env_set(app.SECRETS, RW_TOKEN=tok)
    rw = lambda m, p, b=None: api(m, p, b, token=tok)

    kp = rw("GET", "/api/system/tools/x25519/generate")["keypairs"][0]
    k = {"priv": kp["privateKey"], "pub": kp["publicKey"], "sid": secrets.token_hex(8)}
    prof = rw("POST", "/api/config-profiles", {"name": "MSK", "config": initial_msk_profile(k)})
    inb = {i["tag"]: i["uuid"] for i in prof["inbounds"]}
    clients = rw("POST", "/api/internal-squads", {"name": "clients", "inbounds": [inb["MSK_REALITY"], inb["MSK_HY2"]]})
    bridge = rw("POST", "/api/internal-squads", {"name": "bridge", "inbounds": []})
    node = rw("POST", "/api/nodes", {"name": "MSK", "address": NODE_GW, "port": 2222, "countryCode": "RU",
                                     "configProfile": {"activeConfigProfileUuid": prof["uuid"],
                                                       "activeInbounds": list(inb.values())}})
    secret = rw("GET", "/api/keygen")["secretKey"]
    open(os.path.join(app.DATA, "node.env"), "w").write(f"NODE_PORT=2222\nSECRET_KEY={secret}\n")
    for remark, tag, extra in (("RU MSK Reality", "MSK_REALITY", {"sni": D, "fingerprint": "chrome"}),
                               ("RU MSK Hysteria2", "MSK_HY2", {"sni": D, "alpn": "h3"})):
        rw("POST", "/api/hosts", {"inbound": {"configProfileUuid": prof["uuid"], "configProfileInboundUuid": inb[tag]},
                                  "remark": remark, "address": D, "port": 443, **extra})
    bridge_uuid = str(uuid.uuid4())
    rw("POST", "/api/users", {"username": "bridge-msk", "vlessUuid": bridge_uuid, "expireAt": "2099-01-01T00:00:00.000Z",
                              "activeInternalSquads": [bridge["uuid"]]})
    state = {"keys": {"MSK": k}, "bridge_uuid": bridge_uuid,
             "profiles": {"MSK": {"uuid": prof["uuid"], "inbounds": inb}},
             "squads": {"clients": clients["uuid"], "bridge": bridge["uuid"]}, "nodes": {"MSK": node["uuid"]}}
    json.dump(state, open(app.STATE, "w"), indent=1)
    os.chmod(app.STATE, 0o600)
    print("Remnawave provisioned: admin, token, MSK profile/node/hosts, squads, bridge user")


def awg_config():
    conf = os.path.join(app.AWG_DIR, "awg0.conf")
    if os.path.exists(conf):
        print("awg0.conf exists, skipping")
        return
    run = lambda *c, i=None: subprocess.run(c, input=i, capture_output=True, text=True, check=True).stdout.strip()
    sk = run("awg", "genkey")
    pk = run("awg", "pubkey", i=sk)
    r = random.randint
    b = r(100_000_000, 400_000_000)
    hs = []
    for _ in range(4):
        hs.append(f"{b}-{b + 50_000_000}")
        b += 100_000_000 + r(1, 50_000_000)
    s1, s2 = r(15, 60), r(70, 150)
    s2 += 1 if s1 + 56 == s2 else 0
    params = {"Jc": 5, "Jmin": 40, "Jmax": 70, "S1": s1, "S2": s2, "S3": r(10, 40), "S4": r(5, 20),
              "H1": hs[0], "H2": hs[1], "H3": hs[2], "H4": hs[3],
              "I1": f"<b 0xc30000000108{secrets.token_hex(8)}00><r 80>", "I2": "<b 0x160303><r 110>",
              "I3": "<t><r 30>", "I4": "<r 140>", "I5": "<r 90>"}
    os.makedirs(app.AWG_DIR, exist_ok=True)
    open(os.path.join(app.AWG_DIR, "params.env"), "w").write("".join(f"{k}={v}\n" for k, v in params.items()))
    open(os.path.join(app.AWG_DIR, "server.pub"), "w").write(pk + "\n")
    open(conf, "w").write("[Interface]\n" f"PrivateKey = {sk}\nAddress = {app.AWG_NET}.1/24, {app.AWG_NET6}1/64\nListenPort = {AWG_PORT}\n"
                          + "".join(f"{k} = {v}\n" for k, v in params.items())
                          + "PostUp = /usr/local/bin/tproxy.sh up\nPostDown = /usr/local/bin/tproxy.sh down\n")
    for f in os.listdir(app.AWG_DIR):
        os.chmod(os.path.join(app.AWG_DIR, f), 0o600)
    print(f"AmneziaWG: keys + AWG 2.0 params generated, UDP port {AWG_PORT}")


def portal_files():
    sec = app.env_file(app.SECRETS)
    penv = app.env_file(app.PORTAL_ENV) if os.path.exists(app.PORTAL_ENV) else {}
    kv = {}
    for key, plain in (("SERVERS_PASS", "SERVERS_PAGE_PASS"), ("USERS_PASS", "USERS_PAGE_PASS")):
        if key not in penv:
            salt = secrets.token_hex(16)
            kv[key] = salt + "$" + hashlib.pbkdf2_hmac("sha256", sec[plain].encode(), bytes.fromhex(salt), 200000).hex()
    if "SESSION_SECRET" not in penv:
        kv["SESSION_SECRET"] = secrets.token_hex(32)
    if kv:
        env_set(app.PORTAL_ENV, **kv)
    if not os.path.exists(app.DIRECT_JSON):
        open(app.DIRECT_JSON, "w").write(open("/app/config/direct.json").read())
    os.makedirs(os.path.dirname(app.MTP_CONF), exist_ok=True)
    if not os.path.exists(app.MTP_CONF):            # the portal rewrites it with real per-user secrets on start
        open(app.MTP_CONF, "w").write(
            f"PORT = {app.MTP_PORT}\nUSERS = {{\"_disabled\": \"{secrets.token_hex(16)}\"}}\n"
            'MODES = {"classic": False, "secure": False, "tls": True}\n'
            f'TLS_DOMAIN = "{app.MTP_DOMAIN}"\nSOCKS5_HOST = "127.0.0.1"\nSOCKS5_PORT = 10804\n'
            'USE_MIDDLE_PROXY = False\nPREFER_IPV6 = False\nMETRICS_PORT = 9189\n'
            'METRICS_LISTEN_ADDR_IPV4 = "127.0.0.1"\nMETRICS_WHITELIST = ["127.0.0.1"]\n')
    print("portal: password hashes, session secret, direct.json, MTProxy config")


if __name__ == "__main__":
    os.makedirs(app.DATA, exist_ok=True)
    provision_remnawave()
    awg_config()
    portal_files()
    print("bootstrap: done")
