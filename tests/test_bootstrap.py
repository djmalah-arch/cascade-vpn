import copy
import json
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))
import bootstrap
import app


class BootstrapTests(unittest.TestCase):
    def test_resume_after_profile_created_before_response_saved(self):
        with tempfile.TemporaryDirectory() as d:
            objects = {"/api/config-profiles": [], "/api/internal-squads": [], "/api/nodes": [], "/api/hosts": [],
                       "/api/users?start=0&size=1000": []}
            fail = [True]
            def api(method, path, body=None, token=None):
                if path == "/api/auth/status": return {"isRegisterAllowed": False}
                if path == "/api/auth/login": return {"accessToken": "jwt"}
                if path == "/api/tokens": return {"token": "token"}
                if path == "/api/system/tools/x25519/generate":
                    return {"keypairs": [{"privateKey": "private", "publicKey": "public"}]}
                if path == "/api/keygen": return {"secretKey": "node-secret"}
                if method == "GET":
                    items = objects[path]
                    return {"configProfiles": items} if path.endswith("config-profiles") else \
                           {"internalSquads": items} if path.endswith("internal-squads") else \
                           {"users": items} if path.startswith("/api/users?") else items
                target = "/api/users?start=0&size=1000" if path == "/api/users" else path
                obj = {**copy.deepcopy(body), "uuid": str(sum(map(len, objects.values())))}
                if path == "/api/config-profiles":
                    obj["inbounds"] = [{"tag": i["tag"], "uuid": i["tag"]} for i in body["config"]["inbounds"]]
                objects[target].append(obj)
                if path == "/api/config-profiles" and fail[0]:
                    fail[0] = False
                    raise RuntimeError("connection lost after commit")
                return obj
            secret = Path(d) / "secrets.env"; secret.write_text("RW_ADMIN_PASS=password\n")
            with patch.object(app, "DATA", d), patch.object(app, "STATE", str(Path(d) / "state.json")), \
                 patch.object(app, "SECRETS", str(secret)), patch.object(bootstrap, "wait_api"), \
                 patch.object(bootstrap, "api", side_effect=api):
                with self.assertRaises(RuntimeError): bootstrap.provision_remnawave()
                bootstrap.provision_remnawave()
                bootstrap.provision_remnawave()
                self.assertTrue(Path(app.STATE).exists())
            self.assertEqual(len(objects["/api/config-profiles"]), 1)
            self.assertEqual(len(objects["/api/nodes"]), 1)
            self.assertEqual(len(objects["/api/hosts"]), 2)
