"""Validated routing policy shared by the server, client generator and admin UI."""
import datetime as dt
import ipaddress
import re
import secrets

MSK = dt.timezone(dt.timedelta(hours=3))
DEFAULT_UPDATES = {"enabled": True, "weekday": 0, "hour": 4, "minute": 0}
ACTIONS = {"ru": "Из России", "vpn": "Через VPN", "block": "Блокировать"}
DIRECT_CHECKS = ["ya.ru", "gosuslugi.ru", "ozon.ru", "avito.ru", "wildberries.ru", "sberbank.ru", "nalog.gov.ru", "pochta.ru"]
VPN_CHECKS = ["chatgpt.com", "openai.com", "instagram.com", "facebook.com", "x.com", "discord.com",
              "telegram.org", "t.me", "linkedin.com", "medium.com", "bbc.com", "dw.com", "spotify.com",
              "netflix.com", "reddit.com", "github.com", "google.com", "en.wikipedia.org", "cloudflare.com", "speedtest.net"]


def parse_targets(text):
    domains, ips = [], []
    for raw in re.split(r"[\s,;]+", text.strip()):
        if not raw: continue
        value = raw.strip().lower().rstrip(".")
        try:
            network = ipaddress.ip_network(value, strict=False)
            ips.append(str(network)); continue
        except ValueError: pass
        if "-" in value:
            pair = value.split("-", 1)
            try:
                first, last = map(ipaddress.ip_address, pair)
            except ValueError: pass
            else:
                if first.version != last.version or int(last) < int(first): raise ValueError("Неверный диапазон IP")
                ips.extend(str(n) for n in ipaddress.summarize_address_range(first, last)); continue
        if value.startswith(("geosite:", "geoip:")):
            if not re.fullmatch(r"(?:geosite|geoip):[a-z0-9_@!-]+", value): raise ValueError("Неверная категория")
            (domains if value.startswith("geosite:") else ips).append(value); continue
        if "/" in value or ":" in value or re.fullmatch(r"[0-9.]+", value):
            raise ValueError("Укажите домен, IP или подсеть CIDR без URL: " + raw)
        try: value = value.removeprefix("*.").encode("idna").decode()
        except UnicodeError: raise ValueError("Неверный домен: " + raw)
        if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value) or ".." in value:
            raise ValueError("Неверный домен: " + raw)
        domains.append("domain:" + value)
    if not (domains or ips): raise ValueError("Добавьте хотя бы один домен или адрес")
    if len(domains) + len(ips) > 2000: raise ValueError("В одном правиле допускается до 2000 записей")
    return list(dict.fromkeys(domains)), list(dict.fromkeys(ips))


def new_rule(name, action, targets, rule_id=None):
    if action not in ACTIONS: raise ValueError("Выберите действие")
    name = " ".join(name.split())[:60]
    if not name: raise ValueError("Укажите название")
    ports, others = [], []
    for entry in re.split(r"[\s,;]+", targets.strip()):
        if entry.startswith("udp:"):
            port = entry[4:]
            if not re.fullmatch(r"\d{1,5}(?:-\d{1,5})?", port): raise ValueError("Неверные UDP-порты")
            limits = list(map(int, port.split("-")))
            if not all(1 <= p <= 65535 for p in limits) or limits[-1] < limits[0]: raise ValueError("Неверные UDP-порты")
            ports.append(port)
        elif entry: others.append(entry)
    domains, ips = parse_targets("\n".join(others)) if others else ([], [])
    if not (domains or ips or ports): raise ValueError("Добавьте хотя бы одну запись")
    return {"id": rule_id or secrets.token_hex(8), "name": name, "action": action,
            "domains": domains, "ips": ips, "udp_ports": list(dict.fromkeys(ports)), "enabled": True}


def rules(db, to_exits, client=False):
    result = []
    for rule in db.get("routing", {}).get("rules", []):
        if not rule.get("enabled", True): continue
        if rule["action"] == "block": target = {"outboundTag": "block"}
        elif client and rule["action"] == "ru" and rule.get("device_direct"): target = {"outboundTag": "direct"}
        elif client: target = {"balancerTag": "auto"}
        elif rule["action"] == "ru": target = {"outboundTag": "direct"}
        else: target = to_exits
        for field, values in (("domain", rule["domains"]), ("ip", rule["ips"])):
            if values: result.append({field: values, **target})
        if rule.get("udp_ports"):
            result.append({"network": "udp", "port": ",".join(rule["udp_ports"]), **target})
    return result


def migrate_legacy(db, source):
    settings = db.setdefault("routing", {})
    if settings.get("legacy_migrated"): return False
    imported = []
    entries = [(d, d) for d in source.get("domains", [])]
    entries += [(ip, ip) for ip in source.get("ips", [])]
    entries += [("Категория " + cat, "geosite:" + cat) for cat in source.get("geosite", [])]
    entries += [("UDP " + port, "udp:" + port) for port in source.get("udp_ports", [])]
    for name, target in entries:
        imported.append({**new_rule(name, "ru", target), "origin": "direct.json", "device_direct": True})
    settings.setdefault("rules", []).extend(imported)
    settings["legacy_migrated"] = True
    db["routing_pending"] = True
    return True


def direct_config(db, source):
    if not db.get("routing", {}).get("legacy_migrated"): return source
    direct = {"domains": [], "ips": [], "geosite": [], "udp_ports": []}
    for r in db["routing"].get("rules", []):
        if r.get("enabled", True) and r["action"] == "ru" and r.get("device_direct"):
            for domain in r["domains"]:
                if domain.startswith("domain:"): direct["domains"].append(domain[7:])
                elif domain.startswith("geosite:"): direct["geosite"].append(domain[8:])
            direct["ips"].extend(r["ips"])
            direct["udp_ports"].extend(r.get("udp_ports", []))
    return direct


def checks(db):
    return {"enabled": True, "interval": 3600, "direct": DIRECT_CHECKS, "vpn": VPN_CHECKS,
            **db.get("routing", {}).get("checks", {})}


def updates(db):
    return {**DEFAULT_UPDATES, **db.get("routing", {}).get("updates", {})}


def last_due(config, now):
    now = now.astimezone(MSK)
    day = now.date() - dt.timedelta(days=(now.weekday() - config["weekday"]) % 7)
    due = dt.datetime.combine(day, dt.time(config["hour"], config["minute"]), MSK)
    return due if due <= now else due - dt.timedelta(days=7)


def next_update(config, now):
    return last_due(config, now) + dt.timedelta(days=7) if config["enabled"] else None
