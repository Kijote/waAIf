import base64
import hashlib
import json
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dsse import PAYLOAD_TYPE, PREDICATE_TYPE, STATEMENT_TYPE, pae, verify

DIGEST = "a" * 64

class DsseTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.sbom = b'{"bomFormat":"CycloneDX","components":[]}'
        self.statement = {"_type": STATEMENT_TYPE, "predicateType": PREDICATE_TYPE,
            "subject": [{"name": "example/nginx", "digest": {"sha256": DIGEST}}],
            "predicate": {"sbomSha256": hashlib.sha256(self.sbom).hexdigest(),
                          "project": "demo", "service": "web"}}
        self.runtime = {"services": [{"project": "demo", "service": "web",
                                     "repo_digests": ["nginx@sha256:" + DIGEST]}]}

    def envelope(self, key=None):
        payload = json.dumps(self.statement, sort_keys=True).encode()
        signature = (key or self.key).sign(pae(PAYLOAD_TYPE, payload))
        return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(),
                "signatures": [{"sig": base64.b64encode(signature).decode()}]}

    def test_verified_binding(self):
        self.assertEqual(verify(self.sbom, self.envelope(), self.public, self.runtime)["status"], "matched")

    def test_tampered_sbom(self):
        self.assertFalse(verify(self.sbom + b"x", self.envelope(), self.public, self.runtime)["signature_verified"])

    def test_untrusted_signer(self):
        self.assertFalse(verify(self.sbom, self.envelope(Ed25519PrivateKey.generate()), self.public, self.runtime)["signature_verified"])

    def test_runtime_drift(self):
        self.runtime["services"][0]["repo_digests"] = ["nginx@sha256:" + "b" * 64]
        self.assertEqual(verify(self.sbom, self.envelope(), self.public, self.runtime)["status"], "drift_detected")

    def test_missing_runtime(self):
        self.assertEqual(verify(self.sbom, self.envelope(), self.public, {"services": []})["status"], "needs_verification")

    def test_wrong_payload_type(self):
        envelope = self.envelope()
        envelope["payloadType"] = "application/json"
        self.assertFalse(verify(self.sbom, envelope, self.public, self.runtime)["signature_verified"])

    def test_reject_multiple_signatures(self):
        envelope = self.envelope()
        envelope["signatures"].append(envelope["signatures"][0])
        self.assertFalse(verify(self.sbom, envelope, self.public, self.runtime)["signature_verified"])

if __name__ == "__main__":
    unittest.main()
