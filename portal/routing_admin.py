"""Small admin surface for policy, live checks and geo-list maintenance."""
import json
import os
from pathlib import Path
import re
import app as C
import routing_policy as policy
import servers

DAYS = ("Понедельник", "Вторник", "Среда", "Четверг", "Пятница", "Суббота", "Воскресенье")


def synchronize(log=print):
    import cli
    with C.LOCK:
        db = C.load_db()
        if not db.get("routing_pending"):
            log("Правила уже применены.")
            return
        log("Обновляю управляемую подписку Happ и профиль MSK…")
        cli.happ_routing(); cli.templates(); cli.happ_auto()
        servers.apply(db, servers.compute_plan(db))
        db = C.load_db(); db.pop("routing_pending", None); C.save_db(db)
    log("Правила применены. Happ получит их при обновлении подписки.")


def targets(rule):
    return "\n".join([d.removeprefix("domain:") for d in rule["domains"]] + rule["ips"] + ["udp:" + p for p in rule.get("udp_ports", [])])


def check_summary(db):
    record = db.get("routing_check", {})
    rows = record.get("websites", [])
    confirmed = sum(r.get("verified") and r.get("matches") for r in rows)
    accessible = sum(200 <= r.get("http", 0) < 400 for r in rows)
    text = f"Маршрут {confirmed}/{len(rows)} · доступны {accessible}/{len(rows)}" if rows else "Ещё не проверено"
    if record.get("stale") or (rows and record.get("revision") != db.get("_routing_revision", 0)):
        text = "Правила изменились — нужна новая проверка"
    protocols = []
    for result in record.get("results", []):
        domestic = result.get("domestic", {})
        ok = result.get("verified", False)
        protocols.append(f'<div class="kv"><b>{C.esc(result["protocol"])}</b><span class="pill {"on" if ok else "warnp"}">{"подключение подтверждено" if ok else "не подтверждено"}</span></div>'
                         f'<p class="note">Россия: {C.esc(domestic.get("ip", "—"))} · VPN: {C.esc(result.get("ip", "—"))} · IPv6: {C.esc(result.get("ipv6", {}).get("ip", "не подтверждён"))}</p>')
    table = []
    for r in rows:
        expected = "Из России (MSK)" if r["expected"] == "ru" else "VPN"
        route = {"ru": "Из России (MSK)", "vpn": "VPN", "block": "Блокировка"}.get(r.get("path"), "Не подтверждён")
        code = r.get("http", 0)
        label = {401: "нужен вход", 403: "отказ в доступе", 404: "страница не найдена", 405: "HEAD не поддержан", 429: "ограничение запросов"}.get(code)
        if 500 <= code < 600: label = "ошибка сайта или шлюза"
        http = (str(code) + (" · " + label if label else "")) if code else "нет ответа HTTPS"
        table.append(f'<tr><td>{C.esc(r["host"])}</td><td>{expected}</td><td><span class="pill {"on" if r.get("matches") else "warnp"}">{route}</span></td><td>{http}</td></tr>')
    checked = C.ago(C.parse_ts(record.get("ts")))
    detail = ''.join(protocols) + f'<p class="note">Последняя проверка: {checked}. Контрольные адреса проверяются всеми тремя протоколами. Сайты — реальными запросами через Reality с подтверждением outbound в журнале.</p>'
    if table:
        detail += '<div class="scroll"><table><thead><tr><th>Сайт</th><th>Ожидание</th><th>Фактически</th><th>HTTPS</th></tr></thead><tbody>' + ''.join(table) + '</tbody></table></div>'
    return text, detail


def geo_summary(db):
    meta = db.get("geo_update", {})
    items = []
    for name in C.GEO_MUST:
        path = Path(C.GEO_DIR) / name
        saved = meta.get("files", {}).get(name, {})
        size = path.stat().st_size if path.exists() else 0
        digest = saved.get("sha256") or (C.sha256_file(path) if path.exists() else "")
        node = C.node_geo_sha(name)
        label = f"{size / 1e6:.1f} МБ" if size else "из образа ноды"
        applied = "применён" if node and (not digest or node == digest) else "состояние ноды не подтверждено"
        items.append(f'<div class="kv"><b>{name}</b><span>{label} · {applied}</span></div><code>{C.esc(node or digest or "хэш недоступен")}</code>')
    direct = C.read_json(C.DIRECT_JSON, {"domains": [], "ips": [], "geosite": [], "udp_ports": []})
    return "".join(items), direct


def render(query):
    db = C.load_db()
    rules = db.get("routing", {}).get("rules", [])
    cfg = policy.updates(db)
    geo, direct = geo_summary(db)
    checked = C.parse_ts(db.get("geo_update", {}).get("checked"))
    next_run = policy.next_update(cfg, C.now_utc())
    next_text = next_run.strftime("%d.%m в %H:%M МСК") if next_run else "выключено"
    cards = []
    for index, rule in enumerate(rules):
        enabled = rule.get("enabled", True)
        data = C.esc(json.dumps({**rule, "targets": targets(rule)}, ensure_ascii=False))
        count = len(rule["domains"]) + len(rule["ips"]) + len(rule.get("udp_ports", []))
        cards.append(f'''<article class="card route"><div class="row" style="justify-content:space-between">
<div><b>{C.esc(rule['name'])}</b> <span class="pill {'on' if enabled else 'no'}">{policy.ACTIONS[rule['action']] if enabled else 'выключено'}</span>
<div class="mut">{count} записей · приоритет {index + 1}</div></div>
<div><button class="btn sm alt" data-rule="{data}" onclick="editRule(JSON.parse(this.dataset.rule))">Изменить</button><button type="button" class="btn sm danger" data-id="{rule['id']}" data-name="{C.esc(rule['name'])}" onclick="deleteRule(this.dataset.id,this.dataset.name)">Удалить</button></div></div>
<details><summary>Домены и адреса</summary><pre>{C.esc(targets(rule))}</pre>
<div class="row"><form method="post" action="/admin/routing/toggle"><input type="hidden" name="id" value="{rule['id']}"><button class="btn sm alt">{'Выключить' if enabled else 'Включить'}</button></form>
<form method="post" action="/admin/routing/move"><input type="hidden" name="id" value="{rule['id']}"><button class="btn sm alt" name="direction" value="up">↑ Выше</button><button class="btn sm alt" name="direction" value="down">↓ Ниже</button></form>
<form method="post" action="/admin/routing/delete" onsubmit="return confirm('Удалить правило и применить изменения?')"><input type="hidden" name="id" value="{rule['id']}"><button class="btn sm danger">Удалить</button></form></div></details></article>''')
    job = query.get("job", [""])[0]
    message = query.get("msg", [""])[0]
    check_text, check_detail = check_summary(db)
    check_cfg = policy.checks(db)
    pending = '<p class="note">Изменения сохранены и ожидают применения. При ошибке сторож повторит попытку.</p>' if db.get("routing_pending") else ""
    options = "".join(f'<option value="{i}"{" selected" if cfg["weekday"] == i else ""}>{day}</option>' for i, day in enumerate(DAYS))
    body = f'''<div class="wrap narrow">{C.admin_nav('routing')}<h1>Маршрутизация</h1>
<div class="sub">Правила трафика, проверка подключений и обновление списков</div>
{f'<div class="card ok">{C.esc(message)}</div>' if message else ''}
<div class="card"><h2>Куда направлять трафик</h2><p>По умолчанию российские сайты идут из России, YouTube — через российский сервер, остальное — через зарубежный VPN.</p>
<button class="btn" onclick="editRule()">+ Добавить правило</button><details><summary>Как применяются правила</summary><p class="hint">«Из России» в ваших правилах означает IP входного сервера. В Happ обычные российские сайты могут открываться напрямую с устройства. Hiddify с региональными правилами тоже может отправлять трафик мимо сервера — сервер не может изменить такой маршрут.</p></details>{pending}</div>
<details class="card"><summary>Свои правила · {len(rules)} <span class="mut">редактирование и удаление</span></summary><p class="hint">Исключения из direct.json перенесены сюда. Удаление возвращает стандартный маршрут. Чтобы принудительно направить сайт через VPN, измените направление правила.</p><div class="route-list">{''.join(cards) or '<p class="mut">Своих правил пока нет.</p>'}</div></details>
<details class="card"><summary>Состояние трафика · <span id="check-summary">{check_text}</span></summary><div id="routing-health">{check_detail}</div><h2 style="margin-top:18px">Проверить сейчас</h2><p class="hint">Проверим 2 прямых и 20 VPN-сайтов, а также три протокола и IPv6. Обычно это занимает 1–3 минуты.</p>
<form method="post" action="/admin/routing/check"><label>Сайт или IP <input name="target" placeholder="example.com — необязательно"></label><button class="btn">Проверить три протокола</button></form>
<p class="hint">Проверка с сервера подтверждает протокол и серверные правила. Настройки маршрутизации на личном устройстве проверяются отдельно.</p>
<p id="check-progress" class="note">{C.esc('Выполняется…' if job else '')}</p><details><summary>Журнал проверки</summary><pre id="check-result" style="white-space:pre-wrap">{C.esc('Ожидание результата…' if job else 'Журнал появится после запуска проверки.')}</pre></details>
<details><summary>Настроить мониторинг сайтов</summary><form method="post" action="/admin/routing/check-settings"><label><input type="checkbox" name="enabled" value="1" {'checked' if check_cfg['enabled'] else ''}> Проверять автоматически</label><label>Интервал<select name="interval">{''.join(f'<option value="{m*60}"{" selected" if check_cfg["interval"]==m*60 else ""}>{m} мин</option>' for m in (15,30,60,180,360,1440))}</select></label>
<label>Ожидается напрямую<textarea name="direct" rows="3">{C.esc(chr(10).join(check_cfg['direct']))}</textarea></label><label>Ожидается через VPN<textarea name="vpn" rows="7">{C.esc(chr(10).join(check_cfg['vpn']))}</textarea></label><p class="hint">Это адреса для наблюдения, а не дополнительные правила. Проверка не меняет ваши маршруты и закрепления выходов.</p><button class="btn">Сохранить</button></form></details></details>
<div class="card"><h2>Списки и обновления</h2><p><b>Loyalsoldier / v2ray-rules-dat</b><br><span class="mut">Российские сети, категории сайтов и сервисов</span></p>
<div class="kv"><span>Последняя успешная проверка</span><span>{C.ago(checked)}</span></div>
<div class="kv"><span>Следующее обновление</span><span>{next_text}</span></div>
<details><summary>Настроить автообновление</summary><form method="post" action="/admin/routing/schedule">
<label><input type="checkbox" name="enabled" value="1" {'checked' if cfg['enabled'] else ''}> Обновлять автоматически</label>
<div class="row"><select name="weekday">{options}</select><input type="time" name="time" value="{cfg['hour']:02}:{cfg['minute']:02}" required></div>
<p class="hint">Время московское. Новые файлы проходят проверку SHA-256; если каналы не заработают, возвращаются прежние списки. Применение может кратко переподключить клиентов.</p><button class="btn">Сохранить расписание</button></form></details>
<details><summary>Файлы, источник и дополнительные исключения</summary>{geo}
<p class="hint">Источник: <a class="inline" href="https://github.com/Loyalsoldier/v2ray-rules-dat">Loyalsoldier/v2ray-rules-dat</a>. Файлы: data/portal/geo/. Пользовательские правила: data/portal/db.json → routing.</p>
<p class="hint">direct.json сохранён как исходный файл для отката. Его исключения теперь управляются в разделе «Свои правила»; удалённые записи не возвращаются из старого файла.</p>
<form method="post" action="/admin/routing/geo" onsubmit="return confirm('Обновить списки сейчас? Применение новых файлов может кратко прервать подключения.')"><button class="btn alt">Проверить и обновить сейчас</button></form></details></div>
<dialog id="rule-dialog"><form method="post" action="/admin/routing/save" onsubmit="return confirm('Сохранить и применить правила? Переподключение VPN может занять несколько секунд.')">
<h2 id="rule-title">Новое правило</h2><input type="hidden" name="id" id="rule-id">
<label>Название<input name="name" id="rule-name" placeholder="Например: рабочие сервисы" required maxlength="60"></label>
<label>Направление<select name="action" id="rule-action"><option value="vpn">Через зарубежный VPN</option><option value="ru">Напрямую из России</option><option value="block">Блокировать</option></select></label>
<label>Домены и адреса<textarea name="targets" id="rule-targets" rows="7" placeholder="example.com&#10;203.0.113.0/24&#10;2001:db8::/32" required></textarea></label>
<p class="hint">По одной записи в строке. Домен включает поддомены. Несколько IP или подсетей в одном правиле образуют группу адресов. Поддерживаются диапазоны IP.</p>
<details><summary>Дополнительно</summary><p class="hint">Можно указать категории: geosite:steam, geosite:youtube, geoip:ru. Правила проверяются сверху вниз; частные сети и BitTorrent блокируются отдельно.</p></details>
<div class="row"><button class="btn">Сохранить и применить</button><button type="button" class="btn alt" onclick="document.getElementById('rule-dialog').close()">Отмена</button><button type="button" id="rule-delete" class="btn danger" hidden onclick="deleteRule(document.getElementById('rule-id').value,document.getElementById('rule-name').value)">Удалить правило</button></div></form></dialog>
<form id="delete-rule-form" method="post" action="/admin/routing/delete" hidden><input type="hidden" name="id"></form>
</div><style>dialog{{max-width:560px;width:calc(100% - 48px);background:#171923;color:#eee;border:1px solid #343a48;border-radius:14px;padding:24px}}dialog::backdrop{{background:#0009}}textarea,select{{box-sizing:border-box;width:100%;background:#0e1015;color:#eee;border:1px solid #343a48;border-radius:8px;padding:10px;font:inherit}}label{{display:block;margin:12px 0}}details{{margin-top:14px}}summary{{cursor:pointer;color:#aab9db}}pre{{max-height:340px;overflow:auto;font-size:12px}}.route{{padding:18px}}.row form{{margin:0}}</style>'''
    js = f'''function deleteRule(id,name){{if(!confirm('Удалить правило «'+name+'»? Вернётся стандартная маршрутизация.'))return;const f=document.getElementById('delete-rule-form');f.elements.id.value=id;f.submit();}}
function editRule(r){{document.getElementById('rule-title').textContent=r?'Изменить правило':'Новое правило';document.getElementById('rule-delete').hidden=!r;
for(const [key,id] of [['id','rule-id'],['name','rule-name'],['action','rule-action'],['targets','rule-targets']])document.getElementById(id).value=r?r[key]:(key==='action'?'vpn':'');document.getElementById('rule-dialog').showModal();}}
async function health(){{try{{const r=await fetch('/admin/routing/health');const data=await r.json();document.getElementById('check-summary').textContent=data.summary;document.getElementById('routing-health').innerHTML=data.detail;}}catch(e){{}}}}setInterval(()=>{{if(!document.hidden)health();}},15000);
const job={json.dumps(job)};async function poll(){{if(!job)return;try{{const r=await fetch('/admin/routing/status?job='+encodeURIComponent(job));const j=await r.json();document.getElementById('check-result').textContent=j.log.join('\\n');document.getElementById('check-progress').textContent=j.done?(j.ok?'Завершено':'Завершено с ошибкой'):'Выполняется…';if(!j.done)setTimeout(poll,2500);else health();}}catch(e){{document.getElementById('check-result').textContent='Не удалось получить результат. Повторяем подключение…';setTimeout(poll,5000);}}}}poll();'''
    return C.page("Маршрутизация", body, js)


def status(query):
    jid = query.get("job", [""])[0]
    job = servers.JOBS.get(jid)
    return {"log": job["log"], "done": job["done"], "ok": job["ok"]} if job else {"log": ["Задание не найдено или портал перезапущен"], "done": True, "ok": False}


def handle_post(h, path, form):
    try:
        action = path.rsplit("/", 1)[-1]
        if action == "geo":
            jid = servers.job("Обновление списков", lambda log: log(C.geo_update(force=True)))
        elif action == "check":
            import diagnostics
            target = diagnostics.validate_target(form.get("target", ""))
            jid = servers.job("Проверка трёх протоколов", diagnostics.run, target)
        elif action == "schedule":
            weekday = int(form["weekday"])
            hour, minute = map(int, form["time"].split(":"))
            if not (0 <= weekday <= 6 and 0 <= hour <= 23 and 0 <= minute <= 59): raise ValueError("Неверное время")
            with C.LOCK:
                db = C.load_db(); db.setdefault("routing", {})["updates"] = {"enabled": form.get("enabled") == "1", "weekday": weekday, "hour": hour, "minute": minute}; C.save_db(db)
            return h.redirect("/admin/routing?msg=" + C.quote("Расписание сохранено"))
        elif action == "check-settings":
            import diagnostics
            interval = int(form.get("interval", "3600"))
            if interval not in (900,1800,3600,10800,21600,86400): raise ValueError("Неверный интервал")
            direct = [diagnostics.validate_target(v) for v in form.get("direct", "").split()]
            vpn = [diagnostics.validate_target(v) for v in form.get("vpn", "").split()]
            if len(direct) + len(vpn) > 64: raise ValueError("Не более 64 контрольных адресов")
            with C.LOCK:
                db = C.load_db(); db.setdefault("routing", {})["checks"] = {"enabled": form.get("enabled") == "1", "interval": interval, "direct": list(dict.fromkeys(direct)), "vpn": list(dict.fromkeys(vpn))}; C.save_db(db)
            return h.redirect("/admin/routing?msg=" + C.quote("Мониторинг сохранён"))
        elif action in ("save", "delete", "toggle", "move"):
            with C.LOCK:
                db = C.load_db(); rules = db.setdefault("routing", {}).setdefault("rules", [])
                index = next((i for i, r in enumerate(rules) if r["id"] == form.get("id")), None)
                if action == "save":
                    rule = policy.new_rule(form.get("name", ""), form.get("action"), form.get("targets", ""), rules[index]["id"] if index is not None else None)
                    if index is None: rules.insert(0, rule)
                    else: rules[index] = {**rules[index], **rule, "enabled": rules[index].get("enabled", True)}
                elif index is None: raise ValueError("Правило уже удалено")
                elif action == "delete": rules.pop(index)
                elif action == "toggle": rules[index]["enabled"] = not rules[index].get("enabled", True)
                else:
                    dest = max(0, min(len(rules) - 1, index + (-1 if form.get("direction") == "up" else 1)))
                    rules.insert(dest, rules.pop(index))
                servers.validate_profile(servers.msk_profile(db, servers.compute_plan(db)))
                db["routing_pending"] = True; C.save_db(db)
            jid = servers.job("Применение правил", synchronize)
        else: return h.not_found()
        return h.redirect("/admin/routing?job=" + jid)
    except (ValueError, KeyError, C.UserError) as e:
        return h.redirect("/admin/routing?msg=" + C.quote(str(e)))
