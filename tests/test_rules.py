import json
import tempfile
import unittest
from pathlib import Path

from rules import Rule, RuleEngine, RuleValidationError


class TestRuleValidation(unittest.TestCase):
    def test_valid_rule_is_normalized(self):
        rule = Rule(
            action=" ALLOW ",
            ip=" 93.184.216.34 ",
            port=443,
            proto=" TCP ",
            note=" Example HTTPS ",
        )

        self.assertEqual(rule.action, "allow")
        self.assertEqual(rule.ip, "93.184.216.34")
        self.assertEqual(rule.port, 443)
        self.assertEqual(rule.proto, "tcp")
        self.assertEqual(rule.note, "Example HTTPS")

    def test_invalid_action_is_rejected(self):
        with self.assertRaises(RuleValidationError):
            Rule(action="deny")

    def test_invalid_ip_is_rejected(self):
        with self.assertRaises(RuleValidationError):
            Rule(action="allow", ip="not-an-ip")

    def test_invalid_port_is_rejected(self):
        for port in (0, 65536, "443", True):
            with self.subTest(port=port):
                with self.assertRaises(RuleValidationError):
                    Rule(action="allow", port=port)

    def test_invalid_protocol_is_rejected(self):
        with self.assertRaises(RuleValidationError):
            Rule(action="allow", proto="icmp")

    def test_unknown_field_is_rejected(self):
        with self.assertRaises(RuleValidationError):
            Rule.from_dict({"action": "allow", "hostname": "example.com"})

    def test_missing_action_is_rejected(self):
        with self.assertRaises(RuleValidationError):
            Rule.from_dict({"port": 443})

    def test_cidr_network_is_accepted(self):
        rule = Rule(action="allow", ip="192.0.2.0/24")
        self.assertEqual(rule.ip, "192.0.2.0/24")

    def test_cidr_with_host_bits_is_rejected(self):
        with self.assertRaises(RuleValidationError):
            Rule(action="allow", ip="192.0.2.10/24")


class TestRuleMatching(unittest.TestCase):
    def test_matching_all_fields(self):
        rule = Rule(action="allow", ip="93.184.216.34", port=443, proto="tcp")
        self.assertTrue(rule.matches("93.184.216.34", 443, "tcp"))

    def test_non_matching_field_returns_false(self):
        rule = Rule(action="allow", ip="93.184.216.34", port=443, proto="tcp")
        self.assertFalse(rule.matches("93.184.216.34", 80, "tcp"))
        self.assertFalse(rule.matches("192.0.2.1", 443, "tcp"))
        self.assertFalse(rule.matches("93.184.216.34", 443, "udp"))

    def test_omitted_fields_are_wildcards(self):
        rule = Rule(action="block", port=443)
        self.assertTrue(rule.matches("192.0.2.10", 443, "tcp"))
        self.assertTrue(rule.matches("198.51.100.20", 443, "udp"))
        self.assertFalse(rule.matches("192.0.2.10", 80, "tcp"))

    def test_cidr_matches_members_and_rejects_outside_addresses(self):
        rule = Rule(action="allow", ip="192.0.2.0/24")
        self.assertTrue(rule.matches("192.0.2.1", None, "tcp"))
        self.assertTrue(rule.matches("192.0.2.254", None, "tcp"))
        self.assertFalse(rule.matches("192.0.3.1", None, "tcp"))

    def test_ipv6_exact_address_still_matches(self):
        rule = Rule(action="allow", ip="2001:db8::1")
        self.assertTrue(rule.matches("2001:db8::1", None, "tcp"))
        self.assertFalse(rule.matches("2001:db8::2", None, "tcp"))


class TestRuleEngine(unittest.TestCase):
    def write_rules(self, data):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        path = Path(temp_dir.name) / "rules.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_first_match_wins(self):
        path = self.write_rules(
            [
                {"action": "block", "ip": "192.0.2.10", "port": 443, "proto": "tcp"},
                {"action": "allow", "ip": "192.0.2.10", "port": 443, "proto": "tcp"},
            ]
        )
        engine = RuleEngine(path, default_policy="allow")

        action, rule = engine.decide("192.0.2.10", 443, "tcp")

        self.assertEqual(action, "block")
        self.assertIs(engine.rules[0], rule)

    def test_default_policy_is_used_when_no_rule_matches(self):
        path = self.write_rules([{"action": "allow", "port": 443, "proto": "tcp"}])
        engine = RuleEngine(path, default_policy="block")

        action, rule = engine.decide("192.0.2.10", 80, "tcp")

        self.assertEqual(action, "block")
        self.assertIsNone(rule)

    def test_malformed_json_is_rejected(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        path = Path(temp_dir.name) / "rules.json"
        path.write_text('{"action": "allow"', encoding="utf-8")

        with self.assertRaises(RuleValidationError) as ctx:
            RuleEngine(path)

        self.assertIn("Invalid JSON", str(ctx.exception))

    def test_rules_file_must_be_array(self):
        path = self.write_rules({"action": "allow"})

        with self.assertRaises(RuleValidationError):
            RuleEngine(path)

    def test_invalid_default_policy_is_rejected(self):
        path = self.write_rules([])

        with self.assertRaises(RuleValidationError):
            RuleEngine(path, default_policy="deny")

    def test_reload_replaces_rules(self):
        path = self.write_rules([{"action": "block", "port": 80}])
        engine = RuleEngine(path)

        path.write_text(
            json.dumps([{"action": "allow", "port": 443, "proto": "tcp"}]),
            encoding="utf-8",
        )
        engine.reload()

        self.assertEqual(len(engine.rules), 1)
        self.assertEqual(engine.rules[0].action, "allow")
        self.assertEqual(engine.rules[0].port, 443)


if __name__ == "__main__":
    unittest.main()
