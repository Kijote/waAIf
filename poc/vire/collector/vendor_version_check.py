"""Opt-in native package-version comparison on a trusted host.

Debian uses dpkg --compare-versions. Alpine uses apk version -t.
This does not inspect containers or authenticate package inventory.
"""
import argparse
import json
import re
import subprocess

def compare(distro, installed, fixed, *, runner=subprocess.run):
    if distro not in ("debian", "alpine"):
        raise ValueError("Only Debian and Alpine supported")
    if not all(isinstance(v, str) and 0 < len(v) <= 256 and not any(c in v for c in "\r\n\x00") for v in (installed, fixed)):
        raise ValueError("Invalid package version")
    if distro == "debian":
        cmd = ["dpkg", "--compare-versions", installed, "ge", fixed]
        try:
            proc = runner(cmd, capture_output=True, text=True, timeout=10, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {"status": "needs_verification", "reason": "dpkg unavailable or timed out"}
        if proc.returncode == 0:
            return {"status": "at_or_above_fixed_version", "comparison": "ge", "tool": "dpkg"}
        if proc.returncode == 1 and not proc.stderr.strip():
            return {"status": "below_fixed_version", "comparison": "lt", "tool": "dpkg"}
        return {"status": "needs_verification", "reason": "dpkg comparison failed"}
    cmd = ["apk", "version", "-t", installed, fixed]
    try:
        proc = runner(cmd, capture_output=True, text=True, timeout=10, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"status": "needs_verification", "reason": "apk unavailable or timed out"}
    if proc.returncode != 0:
        return {"status": "needs_verification", "reason": "apk comparison failed"}
    symbol = proc.stdout.strip()
    if symbol in (">", "="):
        return {"status": "at_or_above_fixed_version", "comparison": symbol, "tool": "apk"}
    if symbol == "<":
        return {"status": "below_fixed_version", "comparison": symbol, "tool": "apk"}
    return {"status": "needs_verification", "reason": "Unexpected apk comparison output"}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--distro", choices=["debian", "alpine"], required=True)
    p.add_argument("--installed", required=True)
    p.add_argument("--fixed", required=True)
    a = p.parse_args()
    result = compare(a.distro, a.installed, a.fixed)
    print(json.dumps({"mode": "native_vendor_version_comparison", "distro": a.distro,
                      "installed_version": a.installed, "fixed_version": a.fixed, **result}, indent=2))
    if result["status"] == "needs_verification":
        raise SystemExit(1)

if __name__ == "__main__":
    main()
