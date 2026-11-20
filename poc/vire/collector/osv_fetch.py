"""Opt-in host-side OSV batch fetch with a bounded, reusable local cache.

Network is never required by the VIRE analyzer. OSV results are candidates, not
verified vulnerability applicability for distribution packages.
"""
import argparse
import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API = "https://api.osv.dev/v1/querybatch"
PURL = re.compile(r"^pkg:[A-Za-z][A-Za-z0-9.+-]*/[^\s]{1,512}$")
MAX_REQUESTS = 100
MAX_RESPONSE = 5 * 1024 * 1024

def build_queries(sbom):
    components = sbom.get("components")
    if not isinstance(components, list):
        raise ValueError("SBOM components must be a list")
    seen = set()
    queries = []
    for component in components:
        if not isinstance(component, dict):
            continue
        purl, version = component.get("purl"), component.get("version")
        if not isinstance(purl, str) or not PURL.fullmatch(purl):
            continue
        if not isinstance(version, str) or not version or len(version) > 128:
            continue
        if (purl, version) in seen:
            continue
        seen.add((purl, version))
        queries.append({"package": {"purl": purl}, "version": version})
    if len(queries) > MAX_REQUESTS:
        raise ValueError("Too many packages; split into batches of 100")
    return queries

def fetch(sbom, *, opener=urllib.request.urlopen):
    queries = build_queries(sbom)
    if not queries:
        return {"schema_version": "0.1.0", "source": "osv_querybatch", "retrieved_at": datetime.now(timezone.utc).isoformat(),
                "queries": [], "results": [], "limitations": ["No valid versioned PURLs in input"]}
    payload = json.dumps({"queries": queries}, separators=(",", ":")).encode()
    request = urllib.request.Request(API, data=payload, headers={"Content-Type": "application/json", "User-Agent": "waAIf-VIRE-PoC/0.1"}, method="POST")
    with opener(request, timeout=30) as response:
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("OSV response too large")
    data = json.loads(raw)
    results = data.get("results")
    if not isinstance(results, list) or len(results) != len(queries):
        raise ValueError("Invalid OSV batch response")
    return {"schema_version": "0.1.0", "source": "osv_querybatch", "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "queries": queries, "results": results,
            "limitations": ["OSV results are vulnerability candidates", "Distribution backports and vendor advisories not resolved"]}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sbom", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()
    source = Path(args.sbom)
    if source.stat().st_size > 20 * 1024 * 1024:
        raise SystemExit("SBOM exceeds size limit")
    report = fetch(json.loads(source.read_text()))
    output = Path(args.output)
    if output.is_symlink():
        raise SystemExit("Refusing symlink output")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".osv-", dir=output.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, output)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print(f"Cached {len(report['queries'])} OSV queries to {output}")

if __name__ == "__main__":
    main()
