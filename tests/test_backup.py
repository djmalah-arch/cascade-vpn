import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import re
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))
import backups


class BackupTests(unittest.TestCase):
    def test_offsite_receiver_accepts_old_and_unique_new_backup_names(self):
        self.assertRegex("msk-20261102-1234.tar.gz", backups.BACKUP_NAME_RE)
        self.assertRegex("msk-20261102-123456-123456.tar.gz", backups.BACKUP_NAME_RE)
        self.assertRegex("msk-20261102-123456-123456.tar.gz.enc", backups.BACKUP_NAME_RE)
        self.assertIsNone(re.fullmatch(backups.BACKUP_NAME_RE, "../../escape.tar.gz"))
    def test_round_trip_preserves_project_layout_and_database(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); data = root / "data"; data.mkdir()
            files = {"install.env": "DOMAIN=test.invalid", "remnawave.env": "PASSWORD=test",
                     "Caddyfile": "test.invalid {}", "portal/db.json": '{"users":{}}', "portal/state.json": "{}",
                     "awg/awg0.conf": "PrivateKey=test", "mtproxy/config.py": "USERS={}", "caddy/cert.pem": "cert"}
            for name, text in files.items():
                p = data / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text)
            old = data / "portal/backups/old.tar.gz"; old.parent.mkdir(); old.write_bytes(b"old")
            dump = root / "database.dump"; dump.write_bytes(b"PGDMP-test")
            archive = root / "backup.tar.gz"
            backups.create(data, dump, archive, {'commit':'a'*40,'state_schema':2,'images':{'portal':'sha256:test'}})
            with tarfile.open(archive) as tf:
                self.assertEqual(json.load(tf.extractfile('manifest.json'))['provenance']['commit'], 'a'*40)
            restored = root / "restored"
            backups.restore(archive, restored)
            for name, text in files.items(): self.assertEqual((restored / name).read_text(), text)
            self.assertEqual((restored / "restore.dump").read_bytes(), b"PGDMP-test")
            self.assertFalse((restored / "portal/backups/old.tar.gz").exists())
            with self.assertRaises(ValueError): backups.restore(archive, restored)

    def test_restore_rejects_traversal_and_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name in ("../../escape", "data/link"):
                archive = root / "bad.tar.gz"
                with tarfile.open(archive, "w:gz") as tf:
                    info = tarfile.TarInfo(name)
                    if name.endswith("link"):
                        info.type = tarfile.SYMTYPE; info.linkname = "/etc/passwd"
                    tf.addfile(info)
                with self.assertRaises(ValueError): backups.restore(archive, root / "target")
