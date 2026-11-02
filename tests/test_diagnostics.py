from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))
import diagnostics


class DiagnosticsTests(unittest.TestCase):
    def test_echo_identifies_observed_entry_and_exit_not_country_guess(self):
        db = {"msk": {"v4": "198.51.100.1"}, "exits": {"x": {"name": "Exit", "ip4": "203.0.113.1"}}}
        self.assertEqual(diagnostics.trace_result("ip=198.51.100.1\nloc=RU\n", db)["path"], "ru")
        self.assertEqual(diagnostics.trace_result("198.51.100.1\n", db)["path"], "ru")
        self.assertEqual(diagnostics.trace_result("ip=203.0.113.1\nloc=SC\n", db)["path"], "vpn")
        self.assertIsNone(diagnostics.trace_result("HTTP 200 OK", db))

    def test_log_evidence_requires_diagnostic_user_protocol_and_destination(self):
        line = "2026/11/02 12:00:00 accepted tcp:example.com:443 [MSK_REALITY -> x-exit-6] email: 501"
        self.assertEqual(diagnostics.route_from_log(line, 501, "MSK_REALITY", "example.com"), "x-exit-6")
        self.assertIsNone(diagnostics.route_from_log(line, 502, "MSK_REALITY", "example.com"))
        self.assertIsNone(diagnostics.route_from_log(line, 501, "MSK_HY2", "example.com"))
        self.assertIsNone(diagnostics.route_from_log(line, 501, "MSK_REALITY", "other.com"))

    def test_target_validation_rejects_urls_and_internal_ips(self):
        for target in ("https://example.com", "127.0.0.1", "::1", "169.254.169.254", "example.com/;id"):
            with self.subTest(target=target), self.assertRaises(ValueError): diagnostics.validate_target(target)
        self.assertEqual(diagnostics.validate_target("EXAMPLE.COM."), "example.com")
