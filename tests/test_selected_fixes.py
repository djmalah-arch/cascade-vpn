import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'portal'))
import app
import servers
import user_operations
import auth_limits
import state_schema
import processes


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

    def test_lost_revoke_response_is_not_repeated(self):
        remote = {'shortUuid': 'before', 'vlessUuid': 'credential'}
        db = {'users': {'u': {'rw_id': 1, 'replacement': {'page': 'new'}, 'blocked': True}}}
        calls = []
        def api(method, path, body=None):
            if method == 'GET': return dict(remote)
            calls.append(path); remote['shortUuid'] = 'after'
            raise RuntimeError('response lost after commit')
        with self.assertRaises(RuntimeError): user_operations.reissue(db, 'u', api, lambda db: None)
        user_operations.reissue(db, 'u', api, lambda db: None)
        self.assertEqual(len(calls), 1)
        self.assertEqual(db['users']['u']['page'], 'new')
        self.assertNotIn('blocked', db['users']['u'])

    def test_login_attempts_expire_without_ip_rotation_bypass(self):
        clock = [0]
        limiter = auth_limits.LoginLimits(lambda: clock[0])
        for _ in range(5): self.assertTrue(limiter.allowed('client'))
        self.assertFalse(limiter.allowed('client'))
        clock[0] = 601
        self.assertTrue(limiter.allowed('client'))
        for n in range(99): self.assertTrue(limiter.allowed(str(n)))
        self.assertFalse(limiter.allowed('new-address'))

    def test_schema_migration_disables_only_unscoped_udp_exception(self):
        broad = {'action': 'ru', 'udp_ports': ['19000-20999'], 'domains': [], 'ips': [], 'enabled': True}
        scoped = {**broad, 'ips': ['203.0.113.0/24']}
        db = {'routing': {'rules': [broad, scoped]}}
        self.assertTrue(state_schema.migrate(db))
        self.assertFalse(broad['enabled']); self.assertTrue(scoped['enabled'])
        self.assertFalse(state_schema.migrate(db))
        with self.assertRaises(ValueError): state_schema.migrate({'schema_version': 999})

    @unittest.skipIf(os.name == 'nt', 'POSIX process group')
    def test_timeout_terminates_descendant_holding_stdout(self):
        import time
        start = time.monotonic()
        rc, error = processes.run(['bash', '-c', 'sleep 30 & wait'], timeout=.1)
        self.assertEqual(rc, 124)
        self.assertLess(time.monotonic() - start, 3)

    def test_unknown_ipv6_is_not_a_confirmed_vpn_route(self):
        import diagnostics
        self.assertFalse(diagnostics.ipv6_verified({'ip': '2001:db8::1', 'path': 'unknown'}))
        self.assertFalse(diagnostics.ipv6_verified({'ip': '198.51.100.1', 'path': 'vpn'}))
        self.assertTrue(diagnostics.ipv6_verified({'ip': '2001:db8::1', 'path': 'vpn'}))

    def test_user_save_preserves_concurrent_routing_change(self):
        import json
        with tempfile.TemporaryDirectory() as d, patch.object(app, 'DB_PATH', d + '/db.json'), \
             patch.object(app, 'publish_connections'):
            app.save_db({'users': {}, 'routing': {'rules': []}})
            stale = app.load_db()
            current = app.load_db(); current['routing']['rules'] = [{'action': 'vpn'}]; app.save_db(current)
            stale['users']['new'] = {'name': 'New'}; app.save_users(stale)
            self.assertEqual(app.load_db()['routing']['rules'], [{'action': 'vpn'}])
            self.assertIn('new', app.load_db()['users'])

    def test_profile_network_io_does_not_hold_global_state_lock(self):
        import threading
        lock=threading.RLock()
        db={'exits': {}, 'balancer': {'plan':None}}
        state={'profiles': {'MSK': {'uuid':'profile'}}, 'nodes': {'MSK':'node'}, 'squads': {'bridge':'squad'}}
        def api(*args):
            event=threading.Event()
            def reader():
                with lock: event.set()
            thread=threading.Thread(target=reader);thread.start()
            self.assertTrue(event.wait(1), 'network operation blocks unrelated state reader')
            thread.join();return {'inbounds':[]}
        with patch.object(app,'LOCK',lock),patch.object(app,'load_db',return_value=db), \
             patch.object(app,'save_db'),patch.object(app,'rw',side_effect=api), \
             patch.object(servers,'state',return_value=state),patch.object(servers,'validate_profile'), \
             patch.object(servers,'msk_profile',return_value={}),patch.object(servers,'keep_enabled'):
            servers.apply(db,{'primary':[],'fallback':None})
