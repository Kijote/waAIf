import unittest
from attest import check

DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
SBOM = {"mode": "sbom_inventory", "components": [{"name": "nginx", "version": "1"}]}
RUNTIME = {"services": [{"service": "web", "project": "demo", "repo_digests": ["nginx@" + DIGEST]}]}
BINDING = {"service": "web", "project": "demo", "image_digest": DIGEST}

class BindingTests(unittest.TestCase):
    def test_matching_digest_does_not_authenticate_sbom(self):
        result = check(SBOM, RUNTIME, BINDING)
        self.assertEqual(result["status"], "needs_verification")
        self.assertTrue(result["digest_consistent"])

    def test_mismatched_digest(self):
        self.assertEqual(check(SBOM, RUNTIME, {**BINDING, "image_digest": OTHER})["status"], "drift_detected")

    def test_missing_digest(self):
        self.assertEqual(check(SBOM, RUNTIME, {**BINDING, "image_digest": ""})["status"], "needs_verification")

    def test_ambiguous_service(self):
        self.assertEqual(check(SBOM, {"services": RUNTIME["services"] * 2}, BINDING)["status"], "needs_verification")

    def test_missing_runtime_digest(self):
        self.assertEqual(check(SBOM, {"services": [{**RUNTIME["services"][0], "repo_digests": []}]}, BINDING)["status"], "needs_verification")

if __name__ == "__main__":
    unittest.main()
