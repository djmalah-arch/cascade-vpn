from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))
import app
import routing_admin
import routing_policy
import servers


class Handler:
    def redirect(self, url): return url
    def not_found(self): raise AssertionError("unexpected route")


class RoutingAdminTests(unittest.TestCase):
    def test_create_edit_toggle_and_delete_rule_without_legacy_resurrection(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app, "DB_PATH", str(Path(directory) / "db.json")), \
             patch.object(servers, "msk_profile", return_value={}), patch.object(servers, "validate_profile"), \
             patch.object(servers, "job", return_value="test-job"):
            app.save_db({"users": {}, "routing": {"legacy_migrated": True, "rules": []}})
            form = {"name": "Work", "action": "ru", "targets": "example.com 203.0.113.0/24"}
            routing_admin.handle_post(Handler(), "/admin/routing/save", form)
            rule = app.load_db()["routing"]["rules"][0]
            routing_admin.handle_post(Handler(), "/admin/routing/save", {**form, "id": rule["id"], "action": "vpn"})
            self.assertEqual(app.load_db()["routing"]["rules"][0]["action"], "vpn")
            routing_admin.handle_post(Handler(), "/admin/routing/toggle", {"id": rule["id"]})
            self.assertFalse(app.load_db()["routing"]["rules"][0]["enabled"])
            routing_admin.handle_post(Handler(), "/admin/routing/delete", {"id": rule["id"]})
            db = app.load_db()
            self.assertEqual(db["routing"]["rules"], [])
            self.assertEqual(routing_policy.direct_config(db, {"domains": ["example.com"]})["domains"], [])
