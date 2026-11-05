import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'portal'))
import backups
import health
import mirror
import downloads


class MaintenanceTests(unittest.TestCase):
    def test_download_requires_current_capability_and_verified_bytes(self):
        import io
        class Handler:
            def __init__(self): self.wfile=io.BytesIO(); self.status=None; self.headers={}
            def not_found(self): self.status=404
            def send_response(self, code): self.status=code
            def send_header(self, key, value): self.headers[key]=value
            def end_headers(self): pass
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); file=root/'app.exe'; file.write_bytes(b'verified')
            (root/'apps.json').write_text(json.dumps({'verified': {'app.exe': {'size':8,'sha256':mirror.digest(file)}}}))
            denied=Handler(); downloads.send(denied,root,'app.exe',False); self.assertEqual(denied.status,404)
            allowed=Handler(); downloads.send(allowed,root,'app.exe',True)
            self.assertEqual(allowed.status,200);self.assertEqual(allowed.wfile.getvalue(),b'verified')
            file.write_bytes(b'tampered')
            bad=Handler(); downloads.send(bad,root,'app.exe',True);self.assertEqual(bad.status,404)

    def test_health_detects_stopped_worker_and_failed_work(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {'GEOVPN_DATA': d}):
            for task in health.TASKS: health.checkpoint(task, True)
            self.assertEqual(health.failures(), [])
            health.checkpoint('watchdog', False, 'test')
            self.assertEqual(health.failures(), ['watchdog'])
            health.checkpoint('watchdog', True)
            self.assertEqual(set(health.failures(now=__import__('time').time()+5000)), set(health.TASKS))

    def test_installer_without_published_digest_is_withheld(self):
        with self.assertRaises(ValueError): mirror.expected_digest({'browser_download_url':'https://github.com/a'})

    def test_bad_download_never_overwrites_verified_version(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); target=root/'app.exe'; target.write_bytes(b'old')
            asset={'digest':'sha256:'+'0'*64,'browser_download_url':'https://github.com/example/app.exe'}
            def download(command, **kwargs):
                Path(command[command.index('-o')+1]).write_bytes(b'tampered'); return 0,''
            with patch.object(mirror, 'run', side_effect=download):
                with self.assertRaises(ValueError): mirror.publish(root, 'app.exe', asset, 'v1')
            self.assertEqual(target.read_bytes(), b'old')

    def test_encrypted_backup_authenticates_content(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); key=root/'key.pem'; cert=root/'cert.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),
                '-out',str(cert),'-days','1','-subj','/CN=test'],check=True,capture_output=True)
            source=root/'backup.tar.gz'; source.write_bytes(b'private-backup-data')
            encrypted=Path(backups.encrypt(source,cert))
            self.assertNotIn(b'private-backup-data',encrypted.read_bytes())
            restored=root/'restored'; backups.decrypt(encrypted,key,restored)
            self.assertEqual(restored.read_bytes(),source.read_bytes())
            data=bytearray(encrypted.read_bytes()); data[-1]^=1; encrypted.write_bytes(data)
            with self.assertRaises(ValueError): backups.decrypt(encrypted,key,restored)
            self.assertFalse(restored.exists())
