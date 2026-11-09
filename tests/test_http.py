import http.client
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))
import app


class LoginHTTPTests(unittest.TestCase):
    def test_login_form_preserves_same_origin_and_rejects_foreign_posts(self):
        with patch.object(app, "PUBLIC", False), patch.object(app, "password_role", return_value="a"), \
             patch.object(app, "make_session", return_value="test-session"), \
             patch.object(app.LOGIN_LIMITS, "allowed", return_value=True):
            server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.H)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            client = http.client.HTTPConnection(*server.server_address)
            try:
                client.request("GET", "/login")
                response = client.getresponse(); response.read()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.getheader("Referrer-Policy"), "same-origin")
                for origin, expected in ((app.BASE_URL, 303), ("https://foreign.example", 403), ("null", 403)):
                    client.close()
                    client.request("POST", "/login", "password=test&next=/admin", {"Origin": origin})
                    response = client.getresponse(); response.read()
                    self.assertEqual(response.status, expected)
                    if expected == 303:
                        self.assertEqual(response.getheader("Location"), "/admin")
                        self.assertIn("gvs=test-session;", response.getheader("Set-Cookie"))
            finally:
                client.close(); server.shutdown(); server.server_close(); thread.join()


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Production Unix socket is tested in the Linux image")
class PublicHTTPTests(unittest.TestCase):
    def test_rejected_post_returns_404_even_when_body_arrives_later(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app, "PUBLIC", True):
            address = str(Path(directory) / "http.sock")
            server = app.PublicServer(address, app.H)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            class Unix(http.client.HTTPConnection):
                def connect(self):
                    self.sock = socket.socket(socket.AF_UNIX); self.sock.connect(address)
            client = Unix("public")
            try:
                client.putrequest("POST", "/admin/create")
                client.putheader("Content-Length", "9"); client.endheaders()
                time.sleep(0.05)
                client.send(b"name=test")
                response = client.getresponse()
                self.assertEqual(response.status, 404)
                self.assertTrue(response.read())
            finally:
                client.close(); server.shutdown(); server.server_close(); thread.join()
