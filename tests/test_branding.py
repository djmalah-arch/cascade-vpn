from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'portal'))
import app
import cli


class BrandingTests(unittest.TestCase):
    def test_custom_brand_in_connection_instructions(self):
        with patch.object(app, 'BRAND', 'Север & VPN'), patch.object(app, 'rw_user_by_id', return_value={
                'status': 'ACTIVE', 'subscriptionUrl': 'https://vpn.example/sub/test'}), \
             patch.object(app, 'awg_vpn_key', return_value='key'), patch.object(app, 'mt_links', return_value=('https://t.me/test', '')):
            html = app.render_user({'rw_id': 'id', 'name': 'Test', 'awg': {}, 'page': 'test'}, '127.0.0.1')
        self.assertIn('Север &amp; VPN авто', html)
        self.assertNotIn('GeoVPN', html)

    def test_existing_auto_host_is_renamed_without_duplicate(self):
        calls = []
        hosts = [{'remark': name, 'uuid': str(i), 'address': 'vpn.example', 'port': 443,
                  'inbound': {}, 'sni': 'vpn.example'} for i, name in enumerate(
                      ('RU MSK Hysteria2', 'RU MSK Reality', 'GeoVPN авто'))]
        def api(method, path, body=None):
            calls.append((method, path, body))
            if method == 'GET':
                return {'/api/hosts': hosts, '/api/subscription-templates': {'templates': [
                    {'uuid': 'template', 'templateType': 'XRAY_JSON', 'name': 'GeoVPN Happ auto'}]},
                    '/api/subscription-settings': {'uuid': 'settings', 'responseRules': {'rules': [
                        {'name': 'fallback', 'responseType': 'XRAY_BASE64'}]}}}[path]
            return body
        with patch.object(app, 'BRAND', 'North VPN'), patch.object(app, 'rw', side_effect=api), \
             patch.object(app, 'load_db', return_value={}), patch.object(app, 'read_json', return_value={'domains': [], 'ips': []}):
            cli.happ_auto()
        self.assertFalse(any(m == 'POST' and p == '/api/hosts' for m, p, _ in calls))
        self.assertTrue(any(m == 'PATCH' and p == '/api/hosts' and b.get('uuid') == '2'
                            and b.get('remark') == 'North VPN авто' for m, p, b in calls))
