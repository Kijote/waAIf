"""Offline analysis of a previously fetched OSV batch response.

Only reports potential matches. It does not establish distribution-specific
applicability or recommend automated remediation.
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

def analyze(cache, max_age_hours=168, now=None):
    if cache.get("source") != "osv_querybatch":
        raise ValueError("Unrecognized cache source")
    queries, results = cache.get("queries"), cache.get("results")
    if not isinstance(queries, list) or not isinstance(results, list) or len(queries) != len(results):
        raise ValueError("Query/result alignment invalid")
    retrieved = datetime.fromisoformat(cache["retrieved_at"].replace("Z", "+00:00"))
    if retrieved.tzinfo is None:
        raise ValueError("Timestamp must include timezone")
    now = now or datetime.now(timezone.utc)
    age_hours = (now - retrieved).total_seconds() / 3600
    fresh = 0 <= age_hours <= max_age_hours
    findings = []
    for query, result in zip(queries, results):
        if not isinstance(query, dict) or not isinstance(result, dict):
            raise ValueError("Invalid OSV entry")
        vulns = result.get("vulns", [])
        if not isinstance(vulns, list):
            raise ValueError("Invalid vulnerability list")
        for vuln in vulns:
            if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str):
                continue
            findings.append({"id": vuln["id"], "package": query.get("package", {}),
                             "version": query.get("version"), "status": "potentially_affected",
                             "requires_vendor_backport_review": True})
    return {"mode": "offline_osv_candidates", "cache_fresh": fresh, "cache_age_hours": round(age_hours, 2),
            "retrieved_at": cache["retrieved_at"], "findings": findings,
            "limitations": ["OSV results are not confirmed applicability", "Vendor advisories and distro backports not yet evaluated", "No automatic remediation"]}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cache", required=True)
    p.add_argument("--max-age-hours", type=float, default=168)
    args = p.parse_args()
    path = Path(args.cache)
    if path.stat().st_size > 20 * 1024 * 1024:
        raise SystemExit("Cache exceeds size limit")
    print(json.dumps(analyze(json.loads(path.read_text()), args.max_age_hours), indent=2))

if __name__ == "__main__":
    main()
