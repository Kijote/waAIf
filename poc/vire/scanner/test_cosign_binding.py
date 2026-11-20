import base64
import unittest
from cosign_binding import assess

D = "sha256:" + "a" * 64
SBOM = {"bomFormat": "CycloneDX", "components": [{"name": "nginx"}]}
RUNTIME = {"services": [{"project": "demo", "service": "web", "repo_digests": ["nginx@" + D]}]}

def entry(subject=D, predicate=SBOM):
    statement = {"_type": "https://in-toto.io/Statement/v1",
                 "predicateType": "https://cyclonedx.org/bom",
                 "subject": [{"name": "nginx", "digest": {"sha256": subject[7:]}}],
                 "predicate": predicate}
    import json
    return {"payload": base64.b64encode(json.dumps(statement).encode()).decode()}

class CosignBindingTests(unittest.TestCase):
    def test_matching_evidence(self):
        self.assertEqual(assess(SBOM, [entry()], RUNTIME, "demo", "web", D)["status"], "matched")

    def test_tampered_sbom(self):
        self.assertEqual(assess({"components": []}, [entry()], RUNTIME, "demo", "web", D)["status"], "needs_verification")

    def test_wrong_attested_subject(self):
        self.assertEqual(assess(SBOM, [entry("sha256:" + "b" * 64)], RUNTIME, "demo", "web", D)["status"], "needs_verification")

    def test_runtime_drift(self):
        other = {"services": [{**RUNTIME["services"][0], "repo_digests": ["nginx@sha256:" + "b" * 64]}]}
        self.assertEqual(assess(SBOM, [entry()], other, "demo", "web", D)["status"], "drift_detected")

    def test_ambiguous_runtime(self):
        self.assertEqual(assess(SBOM, [entry()], {"services": RUNTIME["services"] * 2}, "demo", "web", D)["status"], "needs_verification")

    def test_empty_cosign_output(self):
        self.assertEqual(assess(SBOM, [], RUNTIME, "demo", "web", D)["status"], "needs_verification")

    def test_invalid_payload(self):
        self.assertEqual(assess(SBOM, [{"payload": "not-base64"}], RUNTIME, "demo", "web", D)["status"], "needs_verification")

if __name__ == "__main__":
    unittest.main()
