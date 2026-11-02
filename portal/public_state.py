"""The public web worker receives only expiring connection data, never control credentials."""
import time
from storage import atomic_write, read_json
import json


def publish(path, db, users, params, server, site):
    remotes = {u["id"]: u for u in users if u["status"] == "ACTIVE"}
    visible = {s: {k: u[k] for k in ("name", "rw_id", "page", "awg", "mt")}
               for s, u in db["users"].items()
               if not u.get("blocked") and not u.get("diagnostic") and u.get("rw_id") in remotes and u.get("awg") and u.get("mt")}
    ids = {u["rw_id"] for u in visible.values()}
    remote = [{k: u[k] for k in ("id", "status", "expireAt", "subscriptionUrl") if k in u}
              for uid, u in remotes.items() if uid in ids]
    atomic_write(path, json.dumps({"expires": time.time() + 120, "users": visible, "remote": remote,
                                  "params": params, "server": server, "site": site}), mode=0o644)


def read(path):
    snapshot = read_json(path)
    if snapshot["expires"] < time.time():
        raise RuntimeError("Connection pages temporarily unavailable; controller data expired")
    return snapshot
