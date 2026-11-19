"""Reconcile declarative Compose inventory with independently supplied runtime facts.

Does not access Docker Engine or execute commands. Image tags alone cannot prove identity.
"""
import json
import sys
from pathlib import Path

def reconcile(declared, runtime):
    services = {}
    for compose in declared.get("compose_files", []):
        for service in compose.get("services", []):
            services[(Path(compose["path"]).name, service["service"])] = service
    observations = {(entry["compose_file"], entry["service"]): entry for entry in runtime.get("services", [])}
    results = []
    for key, service in sorted(services.items()):
        running = observations.get(key)
        evidence = []
        if running is None:
            status = "needs_verification"
            evidence.append("No runtime observation for declared service")
        elif not running.get("running", False):
            status = "drift_detected"
            evidence.append("Runtime collector reports service is not running")
        elif service.get("image") and running.get("declared_image") and service["image"] != running["declared_image"]:
            status = "drift_detected"
            evidence.append("Runtime image reference differs from declared image")
        elif not running.get("image_digest") or not running.get("expected_image_digest"):
            status = "needs_verification"
            evidence.append("Immutable runtime and expected image digests are required")
        elif running["image_digest"] != running["expected_image_digest"]:
            status = "drift_detected"
            evidence.append("Runtime image digest differs from expected digest")
        else:
            status = "matched"
            evidence.append("Runtime and expected immutable image digests match")
        results.append({"compose_file": key[0], "service": key[1], "status": status, "evidence": evidence})
    for key in sorted(set(observations) - set(services)):
        results.append({"compose_file": key[0], "service": key[1], "status": "drift_detected", "evidence": ["Runtime service not present in declared Compose inventory"]})
    return {"schema_version": "0.1.0", "mode": "offline_reconciliation", "results": results,
            "limitations": ["Runtime observations are supplied externally and not authenticated by this PoC", "Expected digests must be collected independently from trusted deployment evidence"]}

if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python reconcile.py DECLARED_JSON RUNTIME_JSON")
    declared = json.loads(Path(sys.argv[1]).read_text())
    runtime = json.loads(Path(sys.argv[2]).read_text())
    print(json.dumps(reconcile(declared, runtime), indent=2))
