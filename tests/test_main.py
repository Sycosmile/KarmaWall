import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from main import build_parser, main, process_packet
from rules import RuleEngine


class TestCommandLine(unittest.TestCase):
    def test_dry_run_flag_is_false_by_default(self):
        args = build_parser().parse_args([])
        self.assertFalse(args.dry_run)

    def test_dry_run_flag_is_enabled(self):
        args = build_parser().parse_args(["--dry-run"])
        self.assertTrue(args.dry_run)


class TestPacketProcessing(unittest.TestCase):
    def make_packet(self, dst_ip="93.184.216.34", dst_port=443):
        return SimpleNamespace(
            src_addr="192.0.2.10",
            dst_addr=dst_ip,
            dst_port=dst_port,
            tcp=object(),
            udp=None,
        )

    def make_engine(self, rules, default_policy="block"):
        import tempfile
        import json
        from pathlib import Path

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        path = Path(temp_dir.name) / "rules.json"
        path.write_text(json.dumps(rules), encoding="utf-8")
        return RuleEngine(path, default_policy=default_policy)

    def test_allowed_packet_should_be_reinjected(self):
        engine = self.make_engine(
            [
                {
                    "id": "allow-https",
                    "action": "allow",
                    "ip": "93.184.216.34",
                    "port": 443,
                    "proto": "tcp",
                }
            ]
        )
        log = Mock()

        should_reinject = process_packet(
            self.make_packet(),
            engine,
            log,
            dry_run=False,
        )

        self.assertTrue(should_reinject)
        log.info.assert_called_once()
        self.assertIn("ALLOWED", log.info.call_args.args[0])
        self.assertIn("allow-https", log.info.call_args.args)

    def test_blocked_packet_should_not_be_reinjected(self):
        engine = self.make_engine(
            [
                {
                    "id": "block-https",
                    "action": "block",
                    "ip": "93.184.216.34",
                    "port": 443,
                    "proto": "tcp",
                }
            ]
        )
        log = Mock()

        should_reinject = process_packet(
            self.make_packet(),
            engine,
            log,
            dry_run=False,
        )

        self.assertFalse(should_reinject)
        log.warning.assert_called_once()
        self.assertIn("BLOCKED", log.warning.call_args.args[0])

    def test_dry_run_block_should_be_reinjected(self):
        engine = self.make_engine(
            [
                {
                    "id": "block-https",
                    "action": "block",
                    "ip": "93.184.216.34",
                    "port": 443,
                    "proto": "tcp",
                }
            ]
        )
        log = Mock()

        should_reinject = process_packet(
            self.make_packet(),
            engine,
            log,
            dry_run=True,
        )

        self.assertTrue(should_reinject)
        log.warning.assert_called_once()
        self.assertIn("DRY-RUN WOULD-BLOCK", log.warning.call_args.args[0])

    def test_default_policy_block_is_not_reinjected(self):
        engine = self.make_engine([], default_policy="block")
        log = Mock()

        should_reinject = process_packet(
            self.make_packet(dst_ip="198.51.100.20", dst_port=80),
            engine,
            log,
            dry_run=False,
        )

        self.assertFalse(should_reinject)
        self.assertIn("default-policy", log.warning.call_args.args)


class TestStartup(unittest.TestCase):
    def test_logger_initialization_failure_returns_error(self):
        with patch("main.sys.platform", "win32"), patch(
            "main.setup_logger", side_effect=OSError("permission denied")
        ):
            result = main([])

        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
