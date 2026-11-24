"""Offline Ed25519 verification for signed SBOM-to-image bindings.

Trust anchor is an explicitly configured PEM public key, never embedded in an SBOM.
"""
import argparse
import base64
import binascii
import hashlib
import json
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_SBOM_BYTES = 20 * 1024 * 1024
MAX_ATTESTATION_BYTES = 64 * 1024
MAX_KEY_BYTES = 16 * 1024

def canonical_bytes(statement):
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def verify(sbom_bytes, envelope, trusted_public_key_pem, runtime):
    try:
        if len(sbom_bytes) > MAX_SBOM_BYTES:
            raise ValueError("SBOM too large")
        if envelope.get("schema_version") != "0.1.0" or envelope.get("algorithm") != "Ed25519":
            raise ValueError("Unsupported attestation envelope")
        statement = envelope["statement"]
        if not isinstance(statement, dict) or set(statement) != {"sbom_sha256", "image_digest", "project", "service"}:
            raise ValueError("Invalid statement fields")
        digest = statement["image_digest"]
        sbom_hash = statement["sbom_sha256"]
        if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            raise ValueError("Invalid image digest")
        if not isinstance(sbom_hash, str) or not DIGEST_RE.fullmatch(sbom_hash):
            raise ValueError("Invalid SBOM hash")
        if not all(isinstance(statement[k], str) and statement[k] for k in ("project", "service")):
            raise ValueError("Invalid deployment identity")
        if sbom_hash != "sha256:" + hashlib.sha256(sbom_bytes).hexdigest():
            raise ValueError("SBOM bytes differ from signed hash")
        key = serialization.load_pem_public_key(trusted_public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Trusted key must be Ed25519")
        signature = base64.b64decode(envelope["signature"], validate=True)
        key.verify(signature, canonical_bytes(statement))
        services = [s for s in runtime.get("services", []) if s.get("project") == statement["project"] and s.get("service") == statement["service"]]
        if len(services) != 1:
            return {"status": "needs_verification", "signature_verified": True, "reason": "Missing or ambiguous runtime service"}
        observed = {r.rsplit("@", 1)[-1] for r in services[0].get("repo_digests", []) if isinstance(r, str) and "@" in r}
        if not observed:
            return {"status": "needs_verification", "signature_verified": True, "reason": "Runtime registry digest unavailable"}
        if digest not in observed:
            return {"status": "drift_detected", "signature_verified": True, "reason": "Signed image digest does not match runtime"}
        return {"status": "matched", "signature_verified": True, "reason": "Signed SBOM hash and image digest match runtime observation",
                "limitations": ["Signer trust and key lifecycle are operator-managed", "Runtime observation is not authenticated", "SBOM completeness and vulnerability status are not established"]}
    except (ValueError, KeyError, TypeError, InvalidSignature, binascii.Error) as exc:
        return {"status": "needs_verification", "signature_verified": False, "reason": "Invalid or untrusted attestation"}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sbom", required=True)
    p.add_argument("--attestation", required=True)
    p.add_argument("--trusted-key", required=True)
    p.add_argument("--runtime", required=True)
    args = p.parse_args()
    paths = [Path(args.sbom), Path(args.attestation), Path(args.trusted_key)]
    for path, limit in zip(paths, (MAX_SBOM_BYTES, MAX_ATTESTATION_BYTES, MAX_KEY_BYTES)):
        if path.stat().st_size > limit:
            raise SystemExit("Input exceeds size limit")
    result = verify(paths[0].read_bytes(), json.loads(paths[1].read_text()), paths[2].read_bytes(), json.loads(Path(args.runtime).read_text()))
    print(json.dumps({"mode": "signed_sbom_binding", **result}, indent=2))
    if not result["signature_verified"]:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
