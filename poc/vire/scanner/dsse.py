"""Offline DSSE PAE signature verification for a constrained in-toto statement.

This is NOT Sigstore keyless verification: no Fulcio, Rekor, certificate or OIDC checks.
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

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://wa aif.invalid/vire/sbom-binding/v1".replace(" ", "")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

def pae(payload_type, payload):
    t = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(payload)).encode() + b" " + payload

def verify(sbom_bytes, envelope, trusted_public_key_pem, runtime):
    try:
        if len(sbom_bytes) > 20 * 1024 * 1024:
            raise ValueError("Oversized SBOM")
        if envelope.get("payloadType") != PAYLOAD_TYPE:
            raise ValueError("Unexpected payload type")
        payload = base64.b64decode(envelope["payload"], validate=True)
        if len(payload) > 65536:
            raise ValueError("Oversized statement")
        signatures = envelope["signatures"]
        if not isinstance(signatures, list) or len(signatures) != 1:
            raise ValueError("Exactly one signature required")
        signature = base64.b64decode(signatures[0]["sig"], validate=True)
        key = serialization.load_pem_public_key(trusted_public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Ed25519 trust anchor required")
        key.verify(signature, pae(PAYLOAD_TYPE, payload))
        statement = json.loads(payload)
        if statement.get("_type") != STATEMENT_TYPE or statement.get("predicateType") != PREDICATE_TYPE:
            raise ValueError("Unsupported in-toto statement")
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or len(subjects) != 1:
            raise ValueError("Exactly one image subject required")
        subject = subjects[0]
        digest = subject["digest"]["sha256"]
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ValueError("Invalid image digest")
        predicate = statement["predicate"]
        if not isinstance(predicate, dict) or set(predicate) != {"sbomSha256", "project", "service"}:
            raise ValueError("Invalid binding predicate")
        sbom_hash = predicate["sbomSha256"]
        if not isinstance(sbom_hash, str) or not SHA256.fullmatch(sbom_hash):
            raise ValueError("Invalid SBOM hash")
        if hashlib.sha256(sbom_bytes).hexdigest() != sbom_hash:
            raise ValueError("SBOM does not match signed hash")
        project, service = predicate["project"], predicate["service"]
        if not all(isinstance(v, str) and v for v in (project, service)):
            raise ValueError("Missing deployment identity")
        observed_services = [s for s in runtime.get("services", []) if s.get("project") == project and s.get("service") == service]
        if len(observed_services) != 1:
            return {"status": "needs_verification", "signature_verified": True, "reason": "Missing or ambiguous runtime service"}
        observed = {ref.rsplit("@", 1)[-1] for ref in observed_services[0].get("repo_digests", []) if isinstance(ref, str) and "@" in ref}
        if not observed:
            return {"status": "needs_verification", "signature_verified": True, "reason": "Missing runtime digest evidence"}
        if "sha256:" + digest not in observed:
            return {"status": "drift_detected", "signature_verified": True, "reason": "Signed subject digest differs from runtime"}
        return {"status": "matched", "signature_verified": True, "reason": "Trusted DSSE signature, SBOM hash and runtime digest are consistent",
                "limitations": ["No Sigstore keyless identity, Fulcio or Rekor verification", "Runtime collector provenance remains unverified", "SBOM completeness is not established"]}
    except (ValueError, KeyError, TypeError, InvalidSignature, binascii.Error, UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        return {"status": "needs_verification", "signature_verified": False, "reason": "Invalid or untrusted DSSE attestation"}

def main():
    parser = argparse.ArgumentParser()
    for name in ("sbom", "envelope", "trusted-key", "runtime"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    files = [Path(args.sbom), Path(args.envelope), Path(args.trusted_key), Path(args.runtime)]
    for path, max_bytes in zip(files, (20 * 1024 * 1024, 128 * 1024, 16 * 1024, 20 * 1024 * 1024)):
        if path.stat().st_size > max_bytes:
            raise SystemExit("Input too large")
    result = verify(files[0].read_bytes(), json.loads(files[1].read_text()), files[2].read_bytes(), json.loads(files[3].read_text()))
    print(json.dumps({"mode": "dsse_sbom_binding", **result}, indent=2))
    if not result["signature_verified"]:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
