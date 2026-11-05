import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'portal'))
import app
import servers


class SelectedFixes(unittest.TestCase):
    def test_awg_sync_uses_waited_processes_and_removes_temporary_config(self):
        paths = []
        def run(command, **kwargs):
            self.assertIsInstance(command, list)
            if command[:2] == ['awg-quick', 'strip']:
                return 0, '[Interface]\nPrivateKey = test'
            self.assertEqual(command[:3], ['awg', 'syncconf', 'awg0'])
            paths.append(command[3])
            self.assertIn('PrivateKey = test', Path(command[3]).read_text())
            return 0, ''
        with tempfile.TemporaryDirectory() as d, patch.object(app, 'AWG_DIR', d), \
             patch.object(app, 'active_user_ids', return_value=set()), patch.object(app, 'mt_apply'), \
             patch.object(app, 'sh', side_effect=run):
            Path(d, 'awg0.conf').write_text('[Interface]\n')
            app.awg_apply({'users': {}})
        self.assertEqual(len(paths), 1)
        self.assertFalse(Path(paths[0]).exists())

    def test_empty_mtproxy_secret_is_random_and_stable(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d, patch.object(app, 'MTP_CONF', d + '/config.py'), \
             patch.object(app, 'active_user_ids', return_value=set()), \
             patch.object(app, 'svc_active', return_value=False):
            for _ in range(2):
                with self.assertRaises(RuntimeError): app.mt_apply({'users': {}})
                text = Path(app.MTP_CONF).read_text()
                self.assertNotIn(hashlib.sha256((app.HOST + app.MTP_CONF).encode()).hexdigest()[:32], text)
                if _ == 0: first = text
            self.assertEqual(first, text)

    def test_recovered_ipv6_returns_to_preferred_family(self):
        old = {'primary': ['a'], 'fam': {'a': ''}, 'fallback': None, 'fb_tag': None}
        new = {**old, 'fam': {'a': '6'}}
        with patch.object(servers, 'is_up', return_value=True), patch.object(servers, 'v6_dead', return_value=False):
            self.assertTrue(servers.must_switch({'exits': {'a': {'priority': 1}}}, old, new))
