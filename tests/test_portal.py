"""Behavioral regression tests; no Docker, SSH or live panel required."""
import datetime as dt
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import importlib.util
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))
import app
import servers
import public_state


class PortalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for key, value in {"DB_PATH": str(self.root / "db.json"), "AWG_DIR": str(self.root),
                           "MTP_CONF": str(self.root / "mt.py"), "DATA": str(self.root)}.items():
            p = patch.object(app, key, value); p.start(); self.addCleanup(p.stop)
        self.user = {"name": "Private user", "rw_id": 1, "page": "secret-page", "group": "main",
                     "awg": {"pub": "pub", "priv": "priv", "psk": "psk", "ip": "10.66.66.2"}, "mt": "secret"}
        self.db = {"users": {"private": self.user}}
        self.active = [{"id": 1, "status": "ACTIVE"}]
        (self.root / "awg0.conf").write_text("[Interface]\nAddress = 10.66.66.1/24, fd66:66:66::1/64\n")

    def test_moderator_cannot_obtain_other_group_invitation(self):
        mon = {"nodes": [], "youtube": True, "services": {}, "containers": {},
               "host": dict.fromkeys(("load", "mem", "disk", "uptime"), "ok"), "ts": app.now_utc()}
        with patch.object(app, "load_db", return_value=self.db), patch.object(app, "monitoring", return_value=mon), \
             patch.object(app, "rw_users", return_value=[]), patch.object(app, "awg_stats", return_value={}), \
             patch.object(app, "mt_stats", return_value={}):
            body = app.render_admin(hl="private", role="u")
            live = app.render_admin(role="u", live=True)
        self.assertNotIn("secret-page", body)
        self.assertNotIn("secret-page", live["rows"])
        self.assertEqual(live["count"], 0)

    def test_awg_retries_failed_apply_without_file_change(self):
        with patch.object(app, "rw_users", return_value=self.active), patch.object(app, "mt_apply"), \
             patch.object(app, "sh", side_effect=[(0, "[Interface]"), (1, "failure"), (0, "[Interface]"), (0, "")]) as run:
            with self.assertRaises(RuntimeError): app.awg_apply(self.db)
            app.awg_apply(self.db)
        self.assertEqual(run.call_count, 4)

    def test_user_creation_resumes_after_lost_api_response_without_duplicate(self):
        remote = []
        state = self.root / "state.json"; state.write_text(json.dumps({"squads": {"clients": "squad"}}))
        def create(method, path, body):
            remote.append({"id": 2, "username": body["username"], "status": "ACTIVE"})
            raise RuntimeError("response lost after server commit")
        with patch.object(app, "STATE", str(state)), patch.object(app, "rw_users", side_effect=lambda **kw: remote.copy()), \
             patch.object(app, "awg_keys", return_value=("private", "public", "psk")), patch.object(app, "awg_apply"), \
             patch.object(app, "rw", side_effect=create) as post:
            with self.assertRaises(RuntimeError): app.create_user("New person", "main", "operation")
            slug = app.create_user("New person", "main", "operation")
        self.assertEqual(post.call_count, 1)
        self.assertEqual(app.load_db()["users"][slug]["rw_id"], 2)

    def test_mt_reload_failure_is_retried(self):
        with patch.object(app, "rw_users", return_value=self.active), patch.object(app, "svc_active", return_value=True), \
             patch.object(app, "sh", return_value=(0, "")), patch.object(app, "DATA", None), \
             patch.object(app, "svc_signal", side_effect=[RuntimeError("failure"), None]) as signal:
            with self.assertRaises(RuntimeError): app.mt_apply(self.db)
            app.mt_apply(self.db)
        self.assertEqual(signal.call_count, 2)

    def profile(self, pins=None):
        e = {"enabled": True, "priority": 1, "ip4": "203.0.113.1", "sni": "example.com",
             "pub": "pub", "sid": "sid", "mon_port": 10810}
        db = {"exits": {"a": e, "disabled": {**e, "enabled": False, "mon_port": 10811}}, "pins": pins or {}}
        state = {"keys": {"MSK": {"priv": "priv", "sid": "sid"}}, "bridge_uuid": "uuid"}
        direct = Path(__file__).resolve().parents[1] / "config" / "direct.json"
        with patch.object(servers, "state", return_value=state), patch.object(app, "DIRECT_JSON", str(direct)):
            return servers.msk_profile(db, {"primary": ["a"], "fam": {}, "fallback": None})

    def test_disabled_pin_is_not_used(self):
        cfg = self.profile({"disabled": ["geosite:openai"]})
        self.assertFalse(any(b["tag"] == "pin-disabled" for b in cfg["routing"]["balancers"]))

    def test_private_block_precedes_direct_udp(self):
        rules = self.profile()["routing"]["rules"]
        private = next(i for i, r in enumerate(rules) if r.get("ip") == ["geoip:private"])
        udp = next(i for i, r in enumerate(rules) if r.get("network") == "udp" and r.get("outboundTag") == "direct")
        self.assertLess(private, udp)

    def test_failed_disable_revokes_local_protocols_and_keeps_retry(self):
        app.save_db(self.db)
        with patch.object(app, "rw", side_effect=RuntimeError("panel down")), \
             patch.object(app, "rw_users", return_value=self.active), patch.object(app, "awg_apply") as apply:
            with self.assertRaises(RuntimeError): app.user_action("private", "disable")
        saved = app.load_db()["users"]["private"]
        self.assertTrue(saved["blocked"])
        self.assertEqual(saved["pending_action"], "disable")
        self.assertTrue(apply.called)

    def test_blocked_peer_removed_even_if_panel_is_down(self):
        self.user["blocked"] = True
        (self.root / "awg0.conf").write_text("[Interface]\nAddress = 10.66.66.1/24, fd66:66:66::1/64\n\n[Peer]\nPublicKey = pub\n")
        with patch.object(app, "rw_users", side_effect=RuntimeError("offline")), \
             patch.dict(app.CACHE, {"users": (self.active, 0)}), patch.object(app, "mt_apply"), \
             patch.object(app, "sh", return_value=(0, "")):
            app.awg_apply(self.db)
        self.assertNotIn("[Peer]", (self.root / "awg0.conf").read_text())

    def test_public_snapshot_excludes_control_secrets_and_blocked_users(self):
        self.db["exits"] = {"secret": {"priv": "exit-private-key"}}
        self.db["users"]["blocked"] = {**self.user, "blocked": True}
        self.user["pending_action"] = "internal-data"
        path = str(self.root / "public.json")
        public_state.publish(path, self.db, self.active, {}, ["server-public", "443"], {"DOMAIN": "test.invalid"})
        snapshot = public_state.read(path)
        self.assertEqual(set(snapshot["users"]), {"private"})
        self.assertNotIn("pending_action", snapshot["users"]["private"])
        self.assertNotIn("exit-private-key", Path(path).read_text())
        data = json.loads(Path(path).read_text()); data["expires"] = 0
        Path(path).write_text(json.dumps(data))
        with self.assertRaises(RuntimeError): public_state.read(path)

    def test_mt_revoke_closes_only_changed_user_sessions(self):
        path = Path(__file__).resolve().parents[1] / "images" / "mtproxy" / "revocation.py"
        spec = importlib.util.spec_from_file_location("revocation", path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        class Transport:
            closed = False
            def abort(self): self.closed = True
            def is_closing(self): return self.closed
        revoked, other = Transport(), Transport()
        module.register(revoked, "alice", "old")
        module.register(other, "bob", "unchanged")
        cfg = self.root / "config.py"; cfg.write_text("USERS = {}")
        marker = self.root / "ack"
        module.reconcile({"alice": "new", "bob": "unchanged"}, cfg, str(marker))
        self.assertTrue(revoked.closed)
        self.assertFalse(other.closed)
        self.assertTrue(marker.exists())

    def test_stale_apply_uses_latest_exit_address(self):
        old = {"users": {}, "exits": {"a": {"ip4": "203.0.113.1", "enabled": True, "priority": 1}},
               "balancer": {"plan": None, "events": []}}
        import copy
        current = copy.deepcopy(old); current["exits"]["a"]["ip4"] = "203.0.113.2"
        app.save_db(current)
        st = {"profiles": {"MSK": {"uuid": "profile"}}, "nodes": {"MSK": "node"}, "squads": {"bridge": "squad"}}
        with patch.object(servers, "state", return_value=st), patch.object(servers, "keep_enabled"), \
             patch.object(servers, "validate_profile"), \
             patch.object(servers, "msk_profile", return_value={}) as profile, \
             patch.object(app, "rw", return_value={"inbounds": []}):
            servers.apply(old)
        self.assertEqual(profile.call_args.args[0]["exits"]["a"]["ip4"], "203.0.113.2")

    def test_stale_balancer_cannot_undo_cli_invalidation(self):
        old = {"users": {}, "balancer": {"plan": {"primary": ["a"]}, "events": []}}
        app.save_db(old)
        current = app.load_db(); current["balancer"]["plan"] = None; app.save_db(current)
        servers.save_balancer(old)
        self.assertIsNone(app.load_db()["balancer"]["plan"])


if __name__ == "__main__":
    unittest.main()
