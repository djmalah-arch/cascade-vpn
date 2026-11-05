"""Independent bounded maintenance jobs: slow downloads cannot delay backups or heartbeat."""
import datetime as dt
import os
import time
import app as C
import health
import routing_policy


def backup_tick():
    now = C.now_utc().astimezone(routing_policy.MSK)
    if (now.hour, now.minute) < (3, 30) or C.load_db().get('schedule', {}).get('backup') == str(now.date()): return
    C.backup()
    with C.LOCK:
        db = C.load_db(); db.setdefault('schedule', {})['backup'] = str(now.date()); C.save_db(db)


def geo_tick():
    db = C.load_db()
    config = routing_policy.updates(db)
    checked = C.parse_ts(db.get('geo_update', {}).get('checked'))
    due = routing_policy.last_due(config, C.now_utc())
    if config['enabled'] and (not checked or checked < due): C.geo_update()
    elif time.time() - C.STARTED > C.STARTUP_GRACE: C.geo_restore()


def apps_tick():
    last = C.parse_ts(C.load_db().get('schedule', {}).get('apps'))
    if last and (C.now_utc() - last).total_seconds() < 7 * 86400: return
    rc, error = C.sh(['python3', '/app/mirror.py'], timeout=3600)
    if rc:
        C.log_error('Обновление установщиков: ' + error)
        raise RuntimeError('installer verification/update failed')
    with C.LOCK:
        db = C.load_db(); db.setdefault('schedule', {})['apps'] = C.now_utc().isoformat(); C.save_db(db)


def start():
    health.start('heartbeat', C.heartbeat, 60)
    health.start('backup', backup_tick, 300)
    health.start('geo', geo_tick, 300)
    health.start('apps', apps_tick, 300)
    health.start('routing-audit', C.routing_audit, 600)
