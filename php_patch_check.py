#!/usr/bin/env python3
"""PHP patch checker - is this PHP version patched against PHP2Shell?

Usage:
    python php_patch_check.py                  # checks the local `php -v`
    python php_patch_check.py 8.4.26 8.3.36    # checks the versions you give
    php -v | python php_patch_check.py --stdin # checks piped `php -v` output
    python php_patch_check.py --file hosts.txt # one version per line, labels ok
    python php_patch_check.py 8.2.20 --json

PHP2Shell is the pair of critical PHP core vulnerabilities CVE-2026-109618
(RCE via out-of-memory corruption) and CVE-2026-109619 (RCE via stale global
state), both CVSS v4.0 9.2, both allowing unauthenticated remote code
execution in PHP installations that serve web requests (PHP-FPM, Apache
mod_php, php-cgi, FrankenPHP, LiteSpeed). CISA added both to its Known
Exploited Vulnerabilities catalog on 2026-10-26.

PHP fixed both on 2026-10-21 in:
    8.5.12, 8.4.27, 8.3.36, 8.2.35

There is no numbered php.net release fixing them for 8.1 or older (7.4, 8.0
and 8.1 got minimal source backports only; 7.3 and older got nothing), so
this tool reports those branches as unpatched and tells you to upgrade or
confirm a vendor backport.

Distro caveat: distributions that backport security fixes often keep the
old upstream version number. A package can report, say, 8.3.30 and still
carry the fix. For distro packages, check the package changelog for the
CVE IDs instead of trusting the number alone:

    apt changelog php8.3-fpm | grep -E 'CVE-2026-10961(8|9)'

Exit codes: 0 = everything checked is patched, 1 = at least one version is
unpatched, 2 = nothing could be checked / a version could not be judged.

Only the Python standard library is required. Python 3.8+.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import date

CVES = ("CVE-2026-109618", "CVE-2026-109619")
RELEASE_DATE = date(2026, 10, 21)

# branch -> first fixed version on that branch
FIXED = {
    "8.5": (8, 5, 12),
    "8.4": (8, 4, 27),
    "8.3": (8, 3, 36),
    "8.2": (8, 2, 35),
}

# branches with minimal source backports only, no numbered release
BACKPORT_ONLY = {"8.1", "8.0", "7.4"}

VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
BUILD_DATE_RE = re.compile(
    r"built:\s*([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{4})", re.IGNORECASE
)
MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


def parse_version(text):
    """Extract the first X.Y.Z version tuple from a string, or None."""
    m = VERSION_RE.search(text)
    if not m:
        return None
    return tuple(int(g) for g in m.groups())


def parse_build_date(text):
    """Extract a `(built: Mon D YYYY ...)` date from php -v output, or None."""
    m = BUILD_DATE_RE.search(text)
    if not m:
        return None
    month = MONTHS.get(m.group(1).lower()[:3])
    if month is None:
        return None
    try:
        return date(int(m.group(3)), month, int(m.group(2)))
    except ValueError:
        return None


def check(version, build_date=None):
    """Judge one version tuple. Returns a dict with the verdict."""
    branch = f"{version[0]}.{version[1]}"
    result = {"version": ".".join(str(p) for p in version), "branch": branch}

    if branch in FIXED:
        fixed = FIXED[branch]
        result["fixed_version"] = ".".join(str(p) for p in fixed)
        if version >= fixed:
            result["verdict"] = "PATCHED"
            result["detail"] = (
                f"at or above the fixed release {result['fixed_version']} "
                f"for the {branch} branch."
            )
        elif build_date is not None and build_date >= RELEASE_DATE:
            result["verdict"] = "CHECK"
            result["detail"] = (
                f"number is below the fixed release {result['fixed_version']}, "
                f"but the build date ({build_date.isoformat()}) is on or after "
                f"the fix date ({RELEASE_DATE.isoformat()}). This may be a "
                "distro backport - confirm the CVE IDs in the package changelog "
                "before trusting it."
            )
        else:
            result["verdict"] = "VULNERABLE"
            result["detail"] = (
                f"below the fixed release {result['fixed_version']} for the "
                f"{branch} branch. Update PHP, then restart every PHP worker "
                "(FPM pools, Apache, queue workers) - the update alone does "
                "not replace running code."
            )
        if branch == "8.2":
            result["detail"] += (
                " Note: PHP 8.2 reaches end of life on 2026-12-31, so plan "
                "the move to 8.3 or newer."
            )
        return result

    if branch in BACKPORT_ONLY or version < (8, 2, 0):
        result["fixed_version"] = None
        result["verdict"] = "VULNERABLE"
        if branch in BACKPORT_ONLY:
            result["detail"] = (
                f"the {branch} branch is end of life and got no numbered "
                "php.net release for these CVEs (minimal source backports "
                "only). It counts as unpatched unless your distro or LTS "
                "vendor backported the fix - check the package changelog for "
                "the CVE IDs. The real fix is upgrading to PHP 8.3 or newer."
            )
        else:
            result["detail"] = (
                f"the {branch} branch is end of life and received nothing "
                "for these CVEs. Upgrade to PHP 8.3 or newer."
            )
        return result

    result["fixed_version"] = None
    result["verdict"] = "UNKNOWN"
    result["detail"] = (
        f"branch {branch} is newer than the branches covered by the "
        "2026-10-21 security release, so this tool cannot judge it. Check "
        "the branch's own release notes for CVE-2026-109618 / CVE-2026-109619."
    )
    return result


def check_text(text, label=None):
    """Judge the first version found in a blob of text (e.g. php -v output)."""
    version = parse_version(text)
    if version is None:
        return None
    result = check(version, parse_build_date(text))
    result["input"] = label if label is not None else text.strip()
    return result


def local_php_version():
    """Run `php -v` on this machine and return its first line, or None."""
    php = shutil.which("php")
    if php is None:
        return None
    try:
        out = subprocess.run(
            [php, "-v"], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.splitlines()[0] if out.stdout else None


def print_report(results):
    for r in results:
        print(f"{r['input']}")
        print(f"  PHP {r['version']} (branch {r['branch']}): {r['verdict']}")
        print(f"  {r['detail']}")
        print()
    patched = sum(1 for r in results if r["verdict"] == "PATCHED")
    print(
        f"Checked {len(results)} version(s): {patched} patched, "
        f"{len(results) - patched} not confirmed patched."
    )
    print(f"Scope: {CVES[0]} and {CVES[1]} (PHP2Shell), fixed 2026-10-21.")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Check whether PHP versions are patched against PHP2Shell "
            "(CVE-2026-109618 / CVE-2026-109619)."
        )
    )
    parser.add_argument(
        "versions", nargs="*",
        help="Version strings or php -v lines to check. With no arguments, "
             "the local `php -v` is checked.",
    )
    parser.add_argument(
        "--file", metavar="PATH",
        help="Read versions from a file, one per line; text before the "
             "version on a line is kept as its label.",
    )
    parser.add_argument(
        "--stdin", action="store_true",
        help="Read php -v output (or one version per line) from stdin.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output machine-readable JSON instead of text",
    )
    args = parser.parse_args()

    inputs = []  # (text, label)
    for v in args.versions:
        inputs.append((v, v))
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.strip():
                        inputs.append((line, line.strip()))
        except OSError as e:
            print(f"Error reading {args.file}: {e}", file=sys.stderr)
            sys.exit(2)
    if args.stdin:
        for line in sys.stdin:
            if line.strip():
                inputs.append((line, line.strip()))
    if not inputs:
        local = local_php_version()
        if local is None:
            print(
                "Error: no versions given and no local `php` binary found. "
                "Pass a version, --file, or --stdin.",
                file=sys.stderr,
            )
            sys.exit(2)
        inputs.append((local, local))

    results = []
    for text, label in inputs:
        r = check_text(text, label)
        if r is not None:
            results.append(r)

    if not results:
        print("Error: no PHP version (X.Y.Z) found in the input.", file=sys.stderr)
        sys.exit(2)

    if args.json:
        print(json.dumps({"cves": list(CVES), "results": results}, indent=2))
    else:
        print_report(results)

    if any(r["verdict"] == "VULNERABLE" for r in results):
        sys.exit(1)
    if any(r["verdict"] in ("CHECK", "UNKNOWN") for r in results):
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
