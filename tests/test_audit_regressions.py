from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))
import app
import servers


class AuditRegressions(unittest.TestCase):
    def test_firewall_retry_only_resends_failed_exit(self):
        db = {"msk": {"v4": "192.0.2.1", "v6": ""}, "exits": {"a": {"name": "a"}, "b": {"name": "b"}}}
        with patch.object(servers, "detect_msk_addrs", return_value=("192.0.2.2", "")), \
             patch.object(servers, "push_msk_addrs", side_effect=[{"a": True, "b": False}, {"b": True}]) as push, \
             patch.object(servers, "event"):
            self.assertTrue(servers.check_msk_ip(db))
            self.assertEqual(db["msk_firewall_pending"], ["b"])
            self.assertTrue(servers.check_msk_ip(db))
            self.assertEqual(set(push.call_args.args[0]["exits"]), {"b"})
            self.assertFalse(servers.check_msk_ip(db))

    def test_stale_profile_uses_current_rules(self):
        old = {"_routing_revision": 1, "routing": {"rules": ["old"]}, "balancer": {}}
        current = {"_routing_revision": 2, "routing": {"rules": ["new"]}, "balancer": {}}
        plan = {"primary": []}
        with patch.object(app, "LOCK", threading.RLock()), patch.object(app, "load_db", return_value=current), \
             patch.object(servers, "compute_plan", return_value=plan), patch.object(servers, "state"), \
             patch.object(servers, "msk_profile", side_effect=RuntimeError("stop before I/O")) as build:
            with self.assertRaisesRegex(RuntimeError, "stop before I/O"):
                servers.apply(old)
            self.assertEqual(build.call_args.args[0]["routing"], {"rules": ["new"]})

    def test_replace_dead_reserve_family_with_live_primary(self):
        old = {"primary": ["main"], "fam": {"main": "6"}, "fallback": "b", "fb_tag": "x-b-6"}
        new = {**old, "fb_tag": "x-b-4"}
        db = {"exits": {"main": {"priority": 1}}}
        with patch.object(servers, "COUNTERS", {"main": {"up": True}, "b": {"up": True}}), \
             patch.object(servers, "STATUS", {"b": {"v4": True, "v6": False}}):
            self.assertTrue(servers.must_switch(db, old, new))

    def test_password_reset_revokes_only_that_role(self):
        settings = {"SESSION_SECRET": "test", "SERVERS_PASS": "admin-old", "USERS_PASS": "mod"}
        with patch.object(app, "env_file", return_value=settings):
            admin = "gvs=" + app.make_session("a")
            moderator = "gvs=" + app.make_session("u")
            self.assertEqual(app.session_role(admin), "a")
            settings["SERVERS_PASS"] = "admin-new"
            self.assertIsNone(app.session_role(admin))
            self.assertEqual(app.session_role(moderator), "u")
