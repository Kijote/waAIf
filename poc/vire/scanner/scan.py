"""Offline, read-only VIRE PoC using explicit advisory fixtures.

This scanner does not inspect the running nginx container or fetch live CVEs.
It evaluates an explicitly provided inventory against a test advisory dataset.
"""
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

def version_tuple(value):
    if not re.fullmatch(r"\\d+(?:\\.\\d+){1,3}", value):
        return None
    return tuple(int(x) for x in value.split("."))

def assess(asset, advisory):
    evidence = []
    if asset.get("product") != advisory.get("product"):
        return "not_affected", ["Product does not match"]
    if asset.get("vendor_fix_status") == "fixed":
        if asset.get("vendor_advisory_reference"):
            return "not_affected", ["Inventory declares a vendor-confirmed fix", asset["vendor_advisory_reference"]]
        return "needs_verification", ["Fixed status lacks a vendor advisory reference"]
    version = version_tuple(asset.get("upstream_version", ""))
    minimum = version_tuple(advisory.get("affected_from", ""))
    maximum = version_tuple(advisory.get("affected_before", ""))
    if version is None or minimum is None or maximum is None:
        return "needs_verification", ["Missing or unparseable version data"]
    if not (minimum <= version < maximum):
        return "not_affected", ["Upstream version outside fixture's affected range"]
    feature = advisory.get("requires_feature")
    if feature:
        state = asset.get("features", {}).get(feature)
        if state is False:
            return "not_affected", [f"Required feature {feature} explicitly disabled in fixture"]
        if state is not True:
            return "needs_verification", [f"Feature {feature} status unknown"]
    return "affected", ["Fixture version and feature conditions match; confirm with authoritative vendor advisory"]

def main():
    inventory = json.loads(Path(os.environ.get("INVENTORY_PATH", "/fixtures/nginx-sample.json")).read_text())
    advisories = json.loads(Path(os.environ.get("ADVISORIES_PATH", "/fixtures/advisories.json")).read_text())
    results = []
    for advisory in advisories["advisories"]:
        status, evidence = assess(inventory, advisory)
        results.append({"id": advisory["id"], "status": status, "evidence": evidence, "source_url": advisory["source_url"]})
    report = {
        "schema_version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "offline_fixture",
        "asset": inventory.get("asset_id"),
        "results": results,
        "warning": "Fixture-based demonstration only; not a live vulnerability scan or verified vendor advisory."
    }
    target = Path(os.environ.get("OUTPUT_PATH", "/reports/report.json"))
    target.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
