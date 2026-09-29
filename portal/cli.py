#!/usr/bin/env python3
"""geovpn — admin commands inside the portal container.

  docker exec geovpn-portal geovpn apply-direct          # apply direct.json (games etc. bypass the VPN) everywhere
  docker exec geovpn-portal geovpn happ-routing          # re-send the Happ routing profile in the subscription
  docker exec geovpn-portal geovpn set-password admin|users 'NEW'
  docker exec geovpn-portal geovpn backup                # make a backup now (+ copy to the lowest-priority exit)
  docker exec -it geovpn-portal geovpn host-extras <id>  # exit: fail2ban, MTU probing, backup receiver (asks root password)
  docker exec geovpn-portal geovpn geo-update            # refresh geoip/geosite on MSK now (normally weekly)
  docker exec geovpn-portal geovpn status
"""
import base64, hashlib, json, os, secrets, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app  # noqa: E402  (config, Remnawave API helper, portal db)


def happ_routing():
    direct = json.load(open(app.DIRECT_JSON))
    profile = {
        "Name": app.BRAND, "GlobalProxy": "true",
        "RemoteDNSType": "DoH", "RemoteDNSDomain": "https://dns.google/dns-query", "RemoteDNSIP": "8.8.8.8",
        "DomesticDNSType": "DoU", "DomesticDNSDomain": "", "DomesticDNSIP": "77.88.8.8",
        "Geoipurl": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
        "Geositeurl": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
        "DnsHosts": {},
        # RU + games go direct from the device (low ping, RU IP for banks/gosuslugi)
        "DirectSites": ["geosite:category-ru", "domain:ru", "domain:su", "domain:xn--p1ai"]
                       + ["geosite:" + g for g in direct.get("geosite", [])] + ["domain:" + d for d in direct["domains"]],
        "DirectIp": ["geoip:ru", "geoip:private"] + direct["ips"],
        # YouTube via MSK: RU IP (no ads) + DPI bypass there
        "ProxySites": ["geosite:youtube"], "ProxyIp": [], "BlockSites": [], "BlockIp": [],
        "DomainStrategy": "IPIfNonMatch", "FakeDNS": "false",
    }
    link = "happ://routing/onadd/" + base64.b64encode(json.dumps(profile, separators=(",", ":")).encode()).decode()
    s = app.rw("GET", "/api/subscription-settings")
    h = dict(s["customResponseHeaders"])
    h.pop("support-url", None)
    h.update({"routing": link, "profile-title": "rwEncodeBase64:" + app.BRAND, "profile-update-interval": "6"})
    app.rw("PATCH", "/api/subscription-settings", {"uuid": s["uuid"], "customResponseHeaders": h})
    print("happ routing profile: ok")


def templates():
    """DNS without Cloudflare (throttled in RU) + direct rules for sing-box clients."""
    direct = json.load(open(app.DIRECT_JSON))
    for t in app.rw("GET", "/api/subscription-templates")["templates"]:
        if t["templateType"] not in ("XRAY_JSON", "SINGBOX"):
            continue
        tj = app.rw("GET", "/api/subscription-templates/" + t["uuid"])["templateJson"]
        if t["templateType"] == "XRAY_JSON":
            tj.setdefault("dns", {})["servers"] = ["8.8.8.8", "8.8.4.4"]
        else:
            for srv in tj.get("dns", {}).get("servers", []):
                if srv.get("tag") == "cf-dns":
                    srv.update({"type": "tls", "server": "8.8.8.8"})
                if srv.get("tag") == "local":
                    srv.update({"type": "udp", "server": "77.88.8.8"})
            rules = [r for r in tj["route"]["rules"]
                     if not (r.get("outbound") == "direct" and ("domain_suffix" in r or "ip_cidr" in r))]
            pos = next((i + 1 for i, r in enumerate(rules) if r.get("action") == "hijack-dns"), len(rules))
            rules.insert(pos, {"domain_suffix": direct["domains"], "ip_cidr": direct["ips"], "outbound": "direct"})
            tj["route"]["rules"] = rules
        app.rw("PATCH", "/api/subscription-templates", {"uuid": t["uuid"], "templateJson": tj})
        print(f"template {t['templateType']}: ok")


def apply_direct():
    happ_routing()
    templates()
    with app.LOCK:
        db = app.load_db()
        db.setdefault("balancer", {})["plan"] = None      # watchdog re-applies the MSK profile within ~30 s
        app.save_db(db)
    print("MSK profile: will be re-applied by the portal within ~30 s (xray restart, 1-2 s blip)")


def set_password(which, pw):
    key, plain = {"admin": ("SERVERS_PASS", "SERVERS_PAGE_PASS"), "users": ("USERS_PASS", "USERS_PAGE_PASS")}[which]
    if len(pw) < 6:
        sys.exit("password too short (min 6)")
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200000).hex()
    for path, k, v in ((app.PORTAL_ENV, key, f"{salt}${h}"), (app.SECRETS, plain, pw)):
        lines = [l for l in open(path).read().splitlines() if not l.startswith(k + "=")] if os.path.exists(path) else []
        lines.append(f"{k}={v}")
        open(path, "w").write("\n".join(lines) + "\n")
        os.chmod(path, 0o600)
    print(f"password for '{which}' changed (open sessions stay valid up to 12 h)")


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help", "help"):
        print(__doc__)
    elif a[0] == "apply-direct":
        apply_direct()
    elif a[0] == "happ-routing":
        happ_routing()
    elif a[0] == "templates":
        templates()
    elif a[0] == "set-password" and len(a) == 3 and a[1] in ("admin", "users"):
        set_password(a[1], a[2])
    elif a[0] == "ensure-node":        # the panel disables a node after repeated failed connects (e.g. during install)
        st = json.load(open(app.STATE))
        n = next(x for x in app.rw("GET", "/api/nodes") if x["uuid"] == st["nodes"]["MSK"])
        if n.get("isDisabled"):
            app.rw("POST", f"/api/nodes/{n['uuid']}/actions/enable", {})
            print("MSK node was disabled by the panel - enabled")
        print("MSK node connected:", n.get("isConnected"))
    elif a[0] == "backup":
        where = app.backup()
        print("backup: ok ->", app.BACKUP_DIR, f"+ copy on exit {where}" if where else "(no exits for a copy)")
    elif a[0] == "host-extras" and len(a) == 2:
        import getpass
        import servers
        db = app.load_db()
        e = db.get("exits", {}).get(a[1])
        if not e:
            sys.exit("unknown exit id; ids: " + ", ".join(db.get("exits", {})))
        pw = getpass.getpass(f"root password of {e['name']}: ") if sys.stdin.isatty() else sys.stdin.readline().strip()
        c = None
        for h in [x for x in (e.get("ip4"), e.get("ip6")) if x]:
            try:
                c = servers.ssh_connect(h, e.get("ssh_port", 22), pw)
                break
            except Exception as ex:
                print(f"{h}: {ex}")
        if not c:
            sys.exit("SSH failed")
        servers.host_extras(c, db)
        c.close()
    elif a[0] == "geo-update":
        print(app.geo_update(force=True))
    elif a[0] == "status":
        m = app.collect_monitoring()
        for k, v in m["services"].items():
            print(f"{k:16} {v}")
        print("YouTube:", "ok" if m["youtube"] else "FAIL")
        db = app.load_db()
        print("exits:", {e["name"]: e["priority"] for e in db.get("exits", {}).values()} or "none yet")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
