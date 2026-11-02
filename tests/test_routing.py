import datetime as dt
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))
import routing_policy as policy


class RoutingTests(unittest.TestCase):
    def test_legacy_exceptions_are_imported_once_and_deletions_stay_deleted(self):
        source = {"domains": ["game.example"], "ips": ["203.0.113.0/24"], "geosite": ["steam"], "udp_ports": ["19000-20999"]}
        db = {"routing": {"rules": []}}
        self.assertTrue(policy.migrate_legacy(db, source))
        self.assertEqual(len(db["routing"]["rules"]), 4)
        self.assertFalse(policy.migrate_legacy(db, source))
        db["routing"]["rules"] = [r for r in db["routing"]["rules"] if "domain:game.example" not in r["domains"]]
        self.assertNotIn("game.example", policy.direct_config(db, source)["domains"])
        db["routing"]["rules"] = []
        self.assertEqual(policy.direct_config(db, source), dict.fromkeys(("domains", "ips", "geosite", "udp_ports"), []))

    def test_imported_direct_rules_preserve_device_routing_and_udp_ports(self):
        db = {}
        policy.migrate_legacy(db, {"domains": ["game.example"], "udp_ports": ["19000-20999"]})
        client = policy.rules(db, {}, client=True)
        self.assertTrue(all(r.get("outboundTag") == "direct" for r in client))
        self.assertEqual(client[-1]["port"], "19000-20999")
        with self.assertRaises(ValueError): policy.new_rule("Bad", "ru", "udp:99999")

    def test_monitor_defaults_are_two_direct_and_twenty_vpn_sites(self):
        settings = policy.checks({})
        self.assertEqual(len(settings["direct"]), 2)
        self.assertEqual(len(settings["vpn"]), 20)
        self.assertEqual(len(set(settings["direct"] + settings["vpn"])), 22)

    def test_domains_networks_ranges_and_clusters(self):
        r = policy.new_rule("Офис", "ru", "пример.рф\n10.2.3.9/24\n203.0.113.4-203.0.113.7\n2001:db8::/32")
        self.assertIn("domain:xn--e1afmkfd.xn--p1ai", r["domains"])
        self.assertEqual(r["ips"], ["10.2.3.0/24", "203.0.113.4/30", "2001:db8::/32"])

    def test_invalid_input_never_becomes_shell_or_xray_configuration(self):
        for text in ("https://example.com/a", "1.2.3.4/99", "8.8.8.8;$(id)", "a..b", "geosite:a\"b"):
            with self.subTest(text=text), self.assertRaises(ValueError): policy.parse_targets(text)

    def test_domain_and_ip_are_separate_or_rules_for_xray(self):
        rule = policy.new_rule("Custom", "vpn", "example.ru 203.0.113.0/24")
        result = policy.rules({"routing": {"rules": [rule]}}, {"balancerTag": "exits"})
        self.assertEqual(len(result), 2)
        self.assertNotIn("ip", result[0]); self.assertNotIn("domain", result[1])

    def test_client_sends_custom_ru_and_vpn_overrides_to_server(self):
        rules = [policy.new_rule(a, a, "example.ru") for a in ("ru", "vpn", "block")]
        result = policy.rules({"routing": {"rules": rules}}, {}, client=True)
        self.assertEqual([r.get("balancerTag") for r in result], ["auto", "auto", None])
        self.assertEqual(result[-1]["outboundTag"], "block")

    def test_schedule_catches_missed_run_and_handles_disabled(self):
        now = dt.datetime(2026, 11, 2, 8, tzinfo=policy.MSK)
        self.assertEqual(policy.last_due(policy.DEFAULT_UPDATES, now).hour, 4)
        self.assertEqual(policy.next_update(policy.DEFAULT_UPDATES, now).day, 9)
        self.assertIsNone(policy.next_update({**policy.DEFAULT_UPDATES, "enabled": False}, now))
