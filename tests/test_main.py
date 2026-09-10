import unittest

from main import build_parser


class TestCommandLine(unittest.TestCase):
    def test_dry_run_flag_is_false_by_default(self):
        args = build_parser().parse_args([])
        self.assertFalse(args.dry_run)

    def test_dry_run_flag_is_enabled(self):
        args = build_parser().parse_args(["--dry-run"])
        self.assertTrue(args.dry_run)


if __name__ == "__main__":
    unittest.main()
