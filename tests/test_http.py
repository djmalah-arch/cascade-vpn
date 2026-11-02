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
