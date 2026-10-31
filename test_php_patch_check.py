#!/usr/bin/env python3
"""Tests for php_patch_check. Run: python -m unittest -v"""

import unittest
from datetime import date

from php_patch_check import check, check_text, parse_build_date, parse_version


class ParseTests(unittest.TestCase):
    def test_plain_version(self):
        self.assertEqual(parse_version("8.4.27"), (8, 4, 27))

    def test_php_v_line(self):
        line = "PHP 8.3.35 (cli) (built: Oct 14 2026 12:00:00) (NTS)"
        self.assertEqual(parse_version(line), (8, 3, 35))

    def test_distro_suffix_ignored(self):
        self.assertEqual(parse_version("8.2.35-1+deb12u1"), (8, 2, 35))

    def test_no_version(self):
        self.assertIsNone(parse_version("no version here"))

    def test_build_date(self):
        line = "PHP 8.3.30 (cli) (built: Oct 25 2026 09:15:00) (NTS)"
        self.assertEqual(parse_build_date(line), date(2026, 10, 25))

    def test_no_build_date(self):
        self.assertIsNone(parse_build_date("PHP 8.3.36 (cli)"))


class VerdictTests(unittest.TestCase):
    def test_patched_exact(self):
        self.assertEqual(check((8, 4, 27))["verdict"], "PATCHED")

    def test_patched_newer(self):
        self.assertEqual(check((8, 5, 13))["verdict"], "PATCHED")

    def test_vulnerable_one_below(self):
        self.assertEqual(check((8, 4, 26))["verdict"], "VULNERABLE")

    def test_vulnerable_82(self):
        r = check((8, 2, 20))
        self.assertEqual(r["verdict"], "VULNERABLE")
        self.assertEqual(r["fixed_version"], "8.2.35")

    def test_backport_possible_is_check(self):
        r = check((8, 3, 30), build_date=date(2026, 10, 25))
        self.assertEqual(r["verdict"], "CHECK")

    def test_old_build_stays_vulnerable(self):
        r = check((8, 3, 30), build_date=date(2026, 9, 1))
        self.assertEqual(r["verdict"], "VULNERABLE")

    def test_eol_backport_only_branch(self):
        self.assertEqual(check((8, 1, 30))["verdict"], "VULNERABLE")

    def test_very_old_branch(self):
        self.assertEqual(check((7, 4, 33))["verdict"], "VULNERABLE")
        self.assertEqual(check((7, 2, 34))["verdict"], "VULNERABLE")

    def test_future_branch_unknown(self):
        self.assertEqual(check((8, 6, 0))["verdict"], "UNKNOWN")

    def test_check_text_from_php_v(self):
        r = check_text("PHP 8.5.12 (cli) (built: Oct 21 2026 14:02:11) (NTS)")
        self.assertEqual(r["verdict"], "PATCHED")
        self.assertEqual(r["version"], "8.5.12")


if __name__ == "__main__":
    unittest.main()
