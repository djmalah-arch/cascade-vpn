"""Close only sessions whose personal secret was removed or rotated on reload."""
import hashlib
import os
import weakref

sessions = weakref.WeakKeyDictionary()


def register(transport, user, secret, current_users=None):
    if current_users is not None and current_users.get(user) != secret:
        transport.abort()
        return
    sessions[transport] = (user, secret)


def reconcile(users, config_path, marker="/run/mtproxy-applied"):
    for transport, (user, secret) in list(sessions.items()):
        if users.get(user) != secret:
            transport.abort()
        if transport.is_closing():
            sessions.pop(transport, None)
    with open(config_path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    with open(marker + ".tmp", "w") as f:
        f.write(digest)
    os.replace(marker + ".tmp", marker)
