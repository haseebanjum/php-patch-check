# PHP Patch Check

A tiny, dependency-free Python tool that tells you whether a PHP version is patched against **PHP2Shell** — CVE-2026-109618 and CVE-2026-109619, the two critical PHP core vulnerabilities (CVSS v4.0 9.2 each) that allow unauthenticated remote code execution on PHP installations serving web requests. CISA added both to its Known Exploited Vulnerabilities catalog on 26 October 2026.

Updating WordPress or a plugin does not fix this. The fix is in PHP itself, and only an update is a complete fix.

## The fixed versions

PHP released the fixes on 21 October 2026:

| Branch | Fixed in | Notes |
|---|---|---|
| 8.5 | **8.5.12** | |
| 8.4 | **8.4.27** | |
| 8.3 | **8.3.36** | |
| 8.2 | **8.2.35** | Branch reaches end of life 31 December 2026 — plan the move to 8.3+ |
| 8.1, 8.0, 7.4 | *no release* | End of life; minimal source backports only, so treat as unpatched unless your vendor backported it |
| 7.3 and older | *nothing* | Upgrade |

## Usage

```bash
# check the PHP on this machine (runs php -v for you)
python php_patch_check.py

# check versions you name
python php_patch_check.py 8.4.26 8.3.36

# check a server's php -v output
php -v | python php_patch_check.py --stdin

# check a whole fleet: one version per line, labels allowed
python php_patch_check.py --file sample_versions.txt

# machine-readable output
python php_patch_check.py 8.2.20 --json
```

Verdicts: `PATCHED`, `VULNERABLE`, `CHECK` (version number is below the fixed release but the build date is on/after the fix date — possibly a distro backport), and `UNKNOWN` (a branch newer than the ones this release covered).

Exit codes, so it can gate a script or CI job: `0` = everything patched, `1` = at least one version unpatched, `2` = a version needs a manual check or nothing could be checked.

Example:

```bash
$ python php_patch_check.py --file sample_versions.txt
web1: PHP 8.4.26 (cli) (built: Oct  7 2026 10:11:12) (NTS)
  PHP 8.4.26 (branch 8.4): VULNERABLE
  below the fixed release 8.4.27 for the 8.4 branch. Update PHP, then restart every PHP worker (FPM pools, Apache, queue workers) - the update alone does not replace running code.
...
Checked 4 version(s): 1 patched, 3 not confirmed patched.
```

## Two traps this tool is built around

1. **A green "you are on a supported branch" check is not a patch check.** Only the full version number matters: 8.4.26 is on a supported branch and is still vulnerable.
2. **Distro backports can keep an old-looking number.** Debian, Ubuntu, CloudLinux and similar vendors often ship the fix inside a package whose upstream version stays below the fixed release. If your version reads low, check the package changelog for the CVE IDs before concluding either way:

   ```bash
   apt changelog php8.3-fpm | grep -E 'CVE-2026-10961(8|9)'
   ```

   The `CHECK` verdict exists for exactly this case.

After updating, **restart every PHP worker** (FPM pools, Apache, FrankenPHP, queue workers). Installing the fixed build does not replace the code already running in memory.

## Scope

This tool judges versions against the two PHP2Shell CVEs only. It does not cover the separate session-handling issue CVE-2026-115560, which the 21 October releases do not fix. Always check the current php.net security advisories for anything newer.

## Tests

```bash
python -m unittest -v
```

## Requirements

Python 3.8+. No third-party packages.
