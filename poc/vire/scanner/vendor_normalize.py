"""Offline adapters for official Debian Security Tracker and Alpine SecDB snapshots.

Extracts advisory facts only. No fixed/affected decision is made without distro
version ordering and a verified installed-package inventory.
"""
import argparse
import hashlib
import json
from pathlib import Path

def normalize_debian(data, release, cve_ids):
    if not isinstance(data, dict):
        raise ValueError("Debian tracker must be a JSON object")
    entries = []
    for source_package, advisories in data.items():
        if not isinstance(advisories, dict):
            continue
        for cve in cve_ids:
            item = advisories.get(cve)
            if not isinstance(item, dict):
                continue
            releases = item.get("releases", {})
            release_data = releases.get(release) if isinstance(releases, dict) else None
            if not isinstance(release_data, dict):
                continue
            entries.append({
                "distro": "debian", "distro_release": release, "source_package": source_package,
                "vulnerability_id": cve, "vendor_status": release_data.get("status"),
                "fixed_version": release_data.get("fixed_version"),
                "urgency": release_data.get("urgency"),
                "advisory_url": "https://security-tracker.debian.org/tracker/" + cve,
                "applicability": "needs_verification",
            })
    return entries

def normalize_alpine(data, release, repository, cve_ids):
    if not isinstance(data, dict) or not isinstance(data.get("packages"), list):
        raise ValueError("Alpine SecDB must have a packages array")
    entries = []
    for package in data["packages"]:
        if not isinstance(package, dict) or not isinstance(package.get("pkg"), dict):
            continue
        source = package["pkg"].get("name")
        if not isinstance(source, str) or not source:
            continue
        for fixed in package["pkg"].get("secfixes", {}).items():
            version, ids = fixed
            if not isinstance(version, str) or not isinstance(ids, list):
                continue
            for cve in ids:
                if cve not in cve_ids:
                    continue
                entries.append({
                    "distro": "alpine", "distro_release": release, "repository": repository,
                    "source_package": source, "vulnerability_id": cve,
                    "fixed_version": version,
                    "advisory_url": "https://secdb.alpinelinux.org/",
                    "applicability": "needs_verification",
                })
    return entries

def normalize(raw, distro, release, cve_ids, repository=None):
    if distro == "debian":
        entries = normalize_debian(raw, release, cve_ids)
    elif distro == "alpine":
        if repository not in ("main", "community"):
            raise ValueError("Alpine repository required")
        entries = normalize_alpine(raw, release, repository, cve_ids)
    else:
        raise ValueError("Unsupported distro; Ubuntu adapter pending")
    return {"source": "vendor_feed_facts", "distro": distro, "distro_release": release,
            "entries": entries, "limitations": ["Not an installed-package vulnerability verdict",
            "No distro-native version comparison", "Snapshot authenticity and freshness require external validation"]}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--feed", required=True)
    p.add_argument("--metadata", required=True)
    p.add_argument("--distro", required=True, choices=["debian", "alpine"])
    p.add_argument("--release", required=True)
    p.add_argument("--repository", choices=["main", "community"])
    p.add_argument("--cve", action="append", required=True)
    a = p.parse_args()
    feed = Path(a.feed)
    if feed.stat().st_size > 120 * 1024 * 1024:
        raise SystemExit("Feed exceeds limit")
    raw_bytes = feed.read_bytes()
    meta = json.loads(Path(a.metadata).read_text())
    if hashlib.sha256(raw_bytes).hexdigest() != meta.get("sha256"):
        raise SystemExit("Feed SHA-256 does not match metadata")
    result = normalize(json.loads(raw_bytes), a.distro, a.release, set(a.cve), a.repository)
    result["retrieved_at"] = meta.get("retrieved_at")
    result["source_url"] = meta.get("source_url")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
