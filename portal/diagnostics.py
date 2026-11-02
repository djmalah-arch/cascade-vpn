"""Real protocol clients in disposable network namespaces; never substitute a monitor SOCKS inbound."""
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
import app as C
import servers
import routing_policy


def validate_target(value):
    value = value.strip().lower().rstrip(".")
    if not value: return ""
    if len(value) > 253 or any(c in value for c in "/\\@?#\r\n "):
        raise ValueError("Укажите только домен или публичный IP, без URL")
    try:
        address = ipaddress.ip_address(value)
        if not address.is_global: raise ValueError("Проверять можно только публичные адреса")
        return str(address)
    except ValueError:
        if ":" in value or re.fullmatch(r"[0-9.]+", value): raise ValueError("Неверный публичный IP")
    try: value = value.encode("idna").decode()
    except UnicodeError: raise ValueError("Неверный домен")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value) or ".." in value:
        raise ValueError("Неверный домен")
    return value


def public_target(value):
    if not value: return
    resolved = socket.getaddrinfo(value, 443, type=socket.SOCK_STREAM)
    if not resolved or any(not ipaddress.ip_address(row[4][0]).is_global for row in resolved):
        raise ValueError("Домен указывает на непубличный адрес; проверка запрещена")


def trace_result(body, db):
    fields = dict(re.findall(r"^([a-z]+)=([^\r\n]+)$", body, re.M))
    try: ip = str(ipaddress.ip_address(fields.get("ip", body.strip())))
    except ValueError: return None
    entry = set(db.get("msk", {}).values())
    path, name = ("ru", "входной сервер") if ip in entry else ("unknown", "неизвестный выход")
    for exit in db.get("exits", {}).values():
        if ip in (exit.get("ip4"), exit.get("ip6")): path, name = "vpn", exit["name"]
    return {"ip": ip, "country": fields.get("loc", "?"), "path": path, "name": name}


def route_from_log(body, uid, inbound, target):
    """Only an authenticated, dedicated diagnostic user's exact destination is evidence."""
    found = []
    for line in body.splitlines():
        if not re.search(r" email: " + re.escape(str(uid)) + r"\s*$", line): continue
        match = re.search(r"\[" + re.escape(inbound) + r" -> ([^\]]+)\]", line)
        if match and re.search(r"(?:tcp|udp):" + re.escape(target) + r":443\b", line):
            found.append(match.group(1))
    return found[-1] if found else None


def monitor_sites(client, user, settings, log):
    targets = [(host, "ru") for host in settings["direct"]] + [(host, "vpn") for host in settings["vpn"]]
    def probe(item):
        host, expected = item
        start = time.monotonic()
        result = {"host": host, "expected": expected, "verified": False, "http": 0}
        try:
            public_target(host)
            response = client.request("https://" + host + "/", head=True)
            code = response.stdout.strip()
            result["http"] = int(code) if code.isdigit() else 0
            result["reachable"] = response.returncode == 0 and 100 <= result["http"] <= 599
        except Exception:
            result["reachable"] = False
        result["ms"] = round((time.monotonic() - start) * 1000)
        return result
    log(f"Проверяю {len(targets)} контрольных сайтов реальными запросами через Reality…")
    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(probe, targets))
    time.sleep(0.5)
    access = C.sh(["docker", "exec", "remnanode", "tail", "-n", "20000", "/var/log/xray/current"])[1]
    for result in results:
        route = route_from_log(access, user["id"], "MSK_REALITY", result["host"])
        path = "ru" if route in ("direct", "direct-ru", "yt-dpi") else "vpn" if route and route.startswith(("x-", "pin-", "exits")) else "block" if route == "block" else None
        result.update(outbound=route, path=path, verified=path is not None,
                      matches=path == result["expected"] if path else False)
    confirmed = sum(r["verified"] and r["matches"] for r in results)
    log(f"Сайты: маршрут подтверждён и соответствует ожиданию для {confirmed} из {len(results)}. HTTP-ограничения отображаются отдельно.")
    return results


def docker(args, timeout=60, check=True):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        # Container output may include authentication details. Never put it in web-visible jobs.
        raise RuntimeError("Диагностический контейнер не выполнил команду (код " + str(result.returncode) + ")")
    return result


def subscription_outbounds(user):
    request = urllib.request.Request(user["subscriptionUrl"], headers={"User-Agent": "Happ/GeoVPN-diagnostics"})
    with urllib.request.urlopen(request, timeout=30) as response: config = json.load(response)
    configs = config if isinstance(config, list) else [config]
    outbounds = [o for item in configs for o in item.get("outbounds", [])]
    result = {}
    for label, protocol in (("Reality", "vless"), ("Hysteria2", "hysteria")):
        outbound = next((o for o in outbounds if o.get("protocol") == protocol), None)
        if not outbound: raise RuntimeError("В управляемой подписке отсутствует " + label)
        result[label] = {**copy.deepcopy(outbound), "tag": "test"}
    return result


class Client:
    def __init__(self, kind, user, peer, outbound=None):
        self.kind, self.user, self.peer, self.outbound = kind, user, peer, outbound
        self.name = "geovpn-check-" + secrets.token_hex(6)
        self.tmp = None

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="geovpn-check-")
        path = Path(self.tmp.name)
        common = ["create", "--name", self.name, "--label", "geovpn.diagnostic=true", "--network", "bridge",
                  "--memory", "128m", "--pids-limit", "128", "--security-opt", "no-new-privileges:true"]
        try:
            if self.kind == "AmneziaWG":
                conf = "\n".join(line for line in C.awg_client_conf(self.peer).splitlines() if not line.startswith("DNS =")) + "\n"
                conf = conf.replace("[Interface]\n", "[Interface]\nTable = off\n")
                file = path / "awg0.conf"; file.write_text(conf); os.chmod(file, 0o600)
                docker(common + ["--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
                                 "--sysctl", "net.ipv4.conf.all.src_valid_mark=1", "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
                                 "--entrypoint", "/bin/bash", "geovpn/awg", "-c",
                                 "set -e; awg-quick up /tmp/awg0.conf; awg set awg0 fwmark 51820; "
                                 "for family in 4 6; do ip -$family route add default dev awg0 table 51820; "
                                 "ip -$family rule add not fwmark 51820 table 51820; "
                                 "ip -$family rule add table main suppress_prefixlength 0; done; sleep 600"])
                docker(["cp", str(file), self.name + ":/tmp/awg0.conf"])
            else:
                config = {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1", "port": 1080,
                          "protocol": "socks", "settings": {"udp": True}}], "outbounds": [self.outbound]}
                file = path / "client.json"; file.write_text(json.dumps(config)); os.chmod(file, 0o600)
                docker(common + ["--cap-drop", "ALL", "--entrypoint", "/usr/local/bin/xray", servers.node_image(),
                                 "run", "-config", "/tmp/client.json"])
                docker(["cp", str(file), self.name + ":/tmp/client.json"])
            docker(["start", self.name])
            for _ in range(20):
                if self.kind == "AmneziaWG":
                    result = docker(["exec", self.name, "awg", "show", "awg0"], check=False)
                    if result.returncode == 0: break
                else:
                    state = docker(["inspect", "--format", "{{.State.Running}}", self.name]).stdout.strip()
                    if state != "true": raise RuntimeError(self.kind + ": тестовый клиент не запустился")
                    time.sleep(0.5); break
                time.sleep(0.5)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def request(self, url, head=False):
        args = ["run", "--rm", "--network", "container:" + self.name, "--cap-drop", "ALL", "--memory", "64m",
                "--entrypoint", "curl", "geovpn/portal", "-sS", "--connect-timeout", "8", "--max-time", "20"]
        if self.kind != "AmneziaWG": args += ["--socks5-hostname", "127.0.0.1:1080"]
        if head: args += ["--head", "--output", "/dev/null", "--write-out", "%{http_code}"]
        return docker(args + ["--url", url], timeout=40, check=False)

    def __exit__(self, *args):
        docker(["rm", "-f", self.name], check=False)
        if self.tmp: self.tmp.cleanup()


def run(log, target="", check_ipv6=True):
    public_target(target)
    with C.LOCK:
        initial = C.load_db()
        revision = initial.get("_routing_revision", 0)
        initial["routing_check_started"] = C.now_utc().isoformat(); C.save_db(initial)
    slug = None
    results = []
    websites = []
    try:
        log("Создаю временную учётную запись; существующие пользователи не меняются.")
        slug = C.create_user("route-check-" + secrets.token_hex(4), "diagnostics", diagnostic=True)
        with C.LOCK:
            db = C.load_db()
            peer = db["users"][slug]["awg"]
            user = C.rw_user_by_id(db["users"][slug]["rw_id"])
            if not db.get("msk"): db["msk"] = dict(zip(("v4", "v6"), servers.detect_msk_addrs()))
        outbounds = subscription_outbounds(user)
        for kind in ("Reality", "Hysteria2", "AmneziaWG"):
            log(kind + ": устанавливаю настоящее подключение…")
            record = {"protocol": kind, "verified": False}
            try:
                with Client(kind, user, peer, outbounds.get(kind)) as client:
                    domestic = client.request(C.BASE_URL + "/route-check")
                    domestic_evidence = trace_result(domestic.stdout, db) if domestic.returncode == 0 else None
                    if not domestic_evidence: raise RuntimeError("российский контрольный адрес не подтвердил IP")
                    response = client.request("https://www.cloudflare.com/cdn-cgi/trace")
                    evidence = trace_result(response.stdout, db) if response.returncode == 0 else None
                    if not evidence: raise RuntimeError("не получен IP от внешнего сервиса; маршрут не подтверждён")
                    if kind == "AmneziaWG":
                        hs = docker(["exec", client.name, "awg", "show", "awg0", "latest-handshakes"]).stdout
                        if not any(int(line.split()[-1]) > 0 for line in hs.splitlines() if line.split()):
                            raise RuntimeError("нет подтверждённого handshake AmneziaWG")
                    record.update(evidence, verified=True, domestic=domestic_evidence)
                    log(f"{kind} · российский контрольный адрес: IP {domestic_evidence['ip']} ({domestic_evidence['name']}).")
                    where = {"ru": "Из России", "vpn": "Через VPN", "unknown": "Выход не распознан"}[evidence["path"]]
                    log(f"{kind}: {where} · {evidence['name']} · IP {evidence['ip']} · страна по Cloudflare {evidence['country']}.")
                    if check_ipv6:
                        ipv6 = client.request("https://api6.ipify.org")
                        observed6 = trace_result(ipv6.stdout, db) if ipv6.returncode == 0 else None
                        if observed6 and ipaddress.ip_address(observed6["ip"]).version == 6:
                            record["ipv6"] = {**observed6, "verified": True}
                            log(f"{kind} · IPv6: {observed6['ip']} ({observed6['name']}).")
                        else:
                            record["ipv6"] = {"verified": False}
                            log(kind + " · IPv6: не подтверждён (основная проверка IPv4 показана выше).")
                    if kind == "Reality":
                        websites = monitor_sites(client, user, routing_policy.checks(db), log)
                    if target:
                        host = "[" + target + "]" if ":" in target else target
                        probe = client.request("https://" + host + "/cdn-cgi/trace")
                        observed = trace_result(probe.stdout, db) if probe.returncode == 0 else None
                        if observed:
                            record["target"] = {"host": target, **observed, "verified": True}
                            log(f"{kind} → {target}: внешний сервер подтвердил IP {observed['ip']} ({observed['name']}).")
                        else:
                            response = client.request("https://" + host + "/", head=True)
                            log(f"{kind} → {target}: HTTP {response.stdout.strip() or 'нет ответа'}. Доступность сама по себе не доказывает маршрут.")
                            if kind != "AmneziaWG":
                                time.sleep(0.5)
                                access = C.sh(["docker", "exec", "remnanode", "tail", "-n", "3000", "/var/log/xray/current"])[1]
                                route = route_from_log(access, user["id"], "MSK_REALITY" if kind == "Reality" else "MSK_HY2", target)
                                if route:
                                    record["target"] = {"host": target, "outbound": route, "verified": True}
                                    log(f"{kind} → {target}: подтверждённый outbound в журнале: {route}.")
                            if not record.get("target"):
                                record["target"] = {"host": target, "verified": False}
                                log(f"{kind} → {target}: фактический выход к этому сайту не подтверждён; предположение не выдаётся за проверку.")
            except Exception as e:
                record["error"] = str(e); log(kind + ": " + str(e))
            results.append(record)
    finally:
        if slug:
            try: C.user_action(slug, "delete")
            except Exception:
                log("Удаление временной записи ожидает повторной синхронизации.")
    with C.LOCK:
        db = C.load_db(); db["routing_check"] = {"ts": C.now_utc().isoformat(), "results": results, "websites": websites,
                                                "revision": revision, "stale": db.get("_routing_revision", 0) != revision}; C.save_db(db)
    if not all(r["verified"] for r in results) or len(results) != 3:
        raise RuntimeError("Не все три протокола прошли проверку; подробности выше")


def tick():
    """Hourly low-concurrency checks run outside the heartbeat/scheduler thread."""
    if servers.starting_up(): return
    with C.LOCK:
        db = C.load_db()
        settings = routing_policy.checks(db)
        checked = C.parse_ts(db.get("routing_check", {}).get("ts"))
        attempted = C.parse_ts(db.get("routing_check_started"))
        if not settings["enabled"]: return
        if attempted and (C.now_utc() - attempted).total_seconds() < 300: return
        if (checked and db.get("routing_check", {}).get("websites") and not db["routing_check"].get("stale")
                and db["routing_check"].get("revision") == db.get("_routing_revision", 0)
                and (C.now_utc() - checked).total_seconds() < settings["interval"]): return
        db["routing_check_started"] = C.now_utc().isoformat(); C.save_db(db)
    servers.job("Плановая проверка маршрутизации", run)
