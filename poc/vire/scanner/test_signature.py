import base64
import hashlib
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signature import canonical_bytes, verify

DIGEST = "sha256:" + "a" * 64

class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.sbom = b'{"bomFormat":"CycloneDX","components":[]}'
        self.statement = {"sbom_sha256": "sha256:" + hashlib.sha256(self.sbom).hexdigest(),
                          "image_digest": DIGEST, "project": "demo", "service": "web"}
        self.runtime = {"services": [{"project": "demo", "service": "web", "repo_digests": ["nginx@" + DIGEST]}]}

    def envelope(self, key=None):
        key = key or self.key
        return {"schema_version": "0.1.0", "algorithm": "Ed25519",
                "statement": self.statement.copy(),
                "signature": base64.b64encode(key.sign(canonical_bytes(self.statement))).decode()}

    def test_valid_signature_and_runtime(self):
        result = verify(self.sbom, self.envelope(), self.public, self.runtime)
        self.assertEqual(result["status"], "matched")
        self.assertTrue(result["signature_verified"])

    def test_tampered_sbom(self):
        self.assertFalse(verify(self.sbom + b" ", self.envelope(), self.public, self.runtime)["signature_verified"])

    def test_wrong_signer(self):
        self.assertFalse(verify(self.sbom, self.envelope(Ed25519PrivateKey.generate()), self.public, self.runtime)["signature_verified"])

    def test_tampered_statement(self):
        envelope = self.envelope()
        envelope["statement"]["service"] = "other"
        self.assertFalse(verify(self.sbom, envelope, self.public, self.runtime)["signature_verified"])

    def test_runtime_drift(self):
        self.runtime["services"][0]["repo_digests"] = ["nginx@sha256:" + "b" * 64]
        self.assertEqual(verify(self.sbom, self.envelope(), self.public, self.runtime)["status"], "drift_detected")

    def test_missing_runtime_evidence(self):
        self.assertEqual(verify(self.sbom, self.envelope(), self.public, {"services": []})["status"], "needs_verification")

    def test_invalid_signature_encoding(self):
        envelope = self.envelope()
        envelope["signature"] = "invalid!!!"
        self.assertFalse(verify(self.sbom, envelope, self.public, self.runtime)["signature_verified"])

if __name__ == "__main__":
    unittest.main()
