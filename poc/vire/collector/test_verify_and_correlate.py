import base64
import hashlib
import json
import subprocess
import unittest
from unittest.mock import Mock
from verify_and_correlate import run

DIGEST = "a" * 64
IMAGE = "registry.example.org/app@sha256:" + DIGEST
SBOM = {"bomFormat": "CycloneDX", "components": [{"name": "nginx"}]}
RUNTIME = {"services": [{"project": "demo", "service": "web", "repo_digests": ["app@sha256:" + DIGEST]}]}

def response(subject=DIGEST, predicate=SBOM):
    statement = {"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://cyclonedx.org/bom",
                 "subject": [{"name": "app", "digest": {"sha256": subject}}], "predicate": predicate}
    encoded = base64.b64encode(json.dumps(statement).encode()).decode()
    return Mock(stdout=json.dumps({"payload": encoded}) + "\n")

class TrustedFlowTests(unittest.TestCase):
    def execute(self, runner, sbom=SBOM, runtime=RUNTIME):
        return run(IMAGE, "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main",
                   "https://token.actions.githubusercontent.com", sbom, runtime, "demo", "web", runner=runner)

    def test_success(self):
        runner = Mock(return_value=response())
        result = self.execute(runner)
        self.assertEqual(result["status"], "matched")
        self.assertTrue(result["cosign_verified"])
        args = runner.call_args.args[0]
        self.assertEqual(args[0:2], ["cosign", "verify-attestation"])
        self.assertIn("--certificate-identity", args)
        self.assertIn("--certificate-oidc-issuer", args)

    def test_cosign_failure(self):
        runner = Mock(side_effect=subprocess.CalledProcessError(1, "cosign"))
        self.assertEqual(self.execute(runner)["status"], "needs_verification")

    def test_cosign_timeout(self):
        runner = Mock(side_effect=subprocess.TimeoutExpired("cosign", 120))
        self.assertFalse(self.execute(runner)["cosign_verified"])

    def test_no_attestation(self):
        self.assertEqual(self.execute(Mock(return_value=Mock(stdout="")))["status"], "needs_verification")

    def test_tampered_sbom(self):
        self.assertEqual(self.execute(Mock(return_value=response()), sbom={"bomFormat": "CycloneDX"})["status"], "needs_verification")

    def test_runtime_drift(self):
        runtime = {"services": [{**RUNTIME["services"][0], "repo_digests": ["app@sha256:" + "b" * 64]}]}
        self.assertEqual(self.execute(Mock(return_value=response()), runtime=runtime)["status"], "drift_detected")

    def test_reject_mutable_tag(self):
        with self.assertRaises(ValueError):
            run("app:latest", "identity", "issuer", SBOM, RUNTIME, "demo", "web", runner=Mock())

    def test_reject_missing_identity(self):
        with self.assertRaises(ValueError):
            run(IMAGE, "", "issuer", SBOM, RUNTIME, "demo", "web", runner=Mock())

if __name__ == "__main__":
    unittest.main()
