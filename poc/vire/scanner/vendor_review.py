"""Offline conservative review of OSV candidates against normalized vendor evidence.

This module does not parse raw vendor feeds or implement distro version ordering.
A fixed status is only accepted when evidence is explicitly tied to an installed
package release; absence of evidence never means not affected.
"""
import argparse
import json
from pathlib import Path

DISTROS = {"debian", "ubuntu", "alpine"}
STATES = {"fixed", "affected", "not_affected", "unknown"}

def review(osv, inventory, advisories):
    if osv.get("mode") != "offline_osv_candidates":
        raise ValueError("Expected normalized OSV candidate report")
    if advisories.get("source") != "normalized_vendor_advisories":
        raise ValueError("Expected normalized vendor evidence")
    if not isinstance(inventory.get("packages"), list) or not isinstance(advisories.get("entries"), list):
        raise ValueError("Invalid inventory or vendor entries")
    packages = inventory["packages"]
    entries = advisories["entries"]
    output = []
    for finding in osv.get("findings", []):
        vuln = finding.get("id")
        purl = finding.get("package", {}).get("purl")
        version = finding.get("version")
        matching = [p for p in packages if p.get("purl") == purl and p.get("version") == version]
        if len(matching) != 1:
            output.append({"id": vuln, "package": purl, "status": "needs_verification",
                           "reason": "Installed package identity missing or ambiguous"})
            continue
        package = matching[0]
        distro = package.get("distro")
        release = package.get("distro_release")
        installed = package.get("installed_version")
        name = package.get("source_package")
        if distro not in DISTROS or not all(isinstance(x, str) and x for x in (release, installed, name)):
            output.append({"id": vuln, "package": purl, "status": "needs_verification",
                           "reason": "Distribution release or installed package provenance missing"})
            continue
        evidence = [e for e in entries if e.get("distro") == distro and e.get("distro_release") == release
                    and e.get("source_package") == name and e.get("vulnerability_id") == vuln
                    and e.get("installed_version") == installed and e.get("state") in STATES
                    and isinstance(e.get("advisory_url"), str) and e["advisory_url"].startswith("https://")]
        if len(evidence) != 1:
            status, reason = "needs_verification", "No unique vendor advisory for exact installed release"
        else:
            state = evidence[0]["state"]
            status = {"fixed": "vendor_fixed", "not_affected": "vendor_not_affected",
                      "affected": "vendor_affected", "unknown": "needs_verification"}[state]
            reason = "Vendor evidence for exact installed package release"
        output.append({"id": vuln, "package": purl, "status": status, "reason": reason,
                       "vendor_evidence": evidence[0]["advisory_url"] if len(evidence) == 1 else None})
    return {"mode": "offline_vendor_review", "findings": output,
            "limitations": ["Normalized vendor data provenance must be independently verified",
                            "No raw vendor feed parser or distro version comparison",
                            "No automated remediation"]}

def main():
    p = argparse.ArgumentParser()
    for name in ("osv", "inventory", "advisories"):
        p.add_argument("--" + name, required=True)
    a = p.parse_args()
    sources = []
    for path in (a.osv, a.inventory, a.advisories):
        file = Path(path)
        if file.stat().st_size > 20 * 1024 * 1024:
            raise SystemExit("Input too large")
        sources.append(json.loads(file.read_text()))
    print(json.dumps(review(*sources), indent=2))

if __name__ == "__main__":
    main()
