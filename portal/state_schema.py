"""Forward-only, explicit migrations. Unknown versions fail before writing anything."""
VERSION = 2


def migrate(db):
    version = db.get('schema_version', 0)
    if not isinstance(version, int) or version < 0 or version > VERSION:
        raise ValueError('Unsupported portal state schema; use compatible code')
    changed = version != VERSION
    if version < 1:
        db.setdefault('users', {})
    if version < 2:
        policy_changed = False
        for rule in db.get('routing', {}).get('rules', []):
            if (rule.get('action') == 'ru' and rule.get('udp_ports') == ['19000-20999']
                    and not rule.get('domains') and not rule.get('ips') and rule.get('enabled', True)):
                rule['enabled'] = False
                rule['disabled_reason'] = 'Broad UDP exception disabled; add verified game server addresses'
                policy_changed = True
        if policy_changed:
            db['routing_pending'] = True
            db['_routing_revision'] = db.get('_routing_revision', 0) + 1
            db.setdefault('balancer', {})['plan'] = None
    db['schema_version'] = VERSION
    return changed
