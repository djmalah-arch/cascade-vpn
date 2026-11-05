"""Recover a lost revoke response by comparing persisted remote credential state."""
import hashlib
import json


def marker(user):
    values = {k: user.get(k) for k in ('shortUuid', 'vlessUuid', 'subRevokedAt')}
    if not values['shortUuid'] or not values['vlessUuid']:
        raise RuntimeError('Remote user has no revocation identity')
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def reissue(db, slug, api, save):
    user = db['users'][slug]
    path = '/api/users/' + str(user['rw_id'])
    current = api('GET', path)
    if not user.get('revoke_before'):
        user['revoke_before'] = marker(current)
        save(db)
    if marker(current) == user['revoke_before']:
        api('POST', path + '/actions/revoke', {})
        if marker(api('GET', path)) == user['revoke_before']:
            raise RuntimeError('Remote revocation not confirmed; retry pending')
    user.update(user.pop('replacement'))
    user.pop('blocked', None)
    user.pop('revoke_before', None)
