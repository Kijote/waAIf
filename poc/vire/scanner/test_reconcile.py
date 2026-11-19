import unittest
from reconcile import reconcile

DECLARED = {"compose_files": [{"path": "compose.yaml", "services": [{"service": "nginx", "image": "nginx:1.27-alpine"}]}]}

def runtime(**kwargs):
    entry = {"compose_file": "compose.yaml", "service": "nginx", "running": True, "declared_image": "nginx:1.27-alpine"}
    entry.update(kwargs)
    return {"services": [entry]}

class ReconciliationTests(unittest.TestCase):
    def status(self, observation):
        return reconcile(DECLARED, observation)["results"][0]["status"]

    def test_matching_digests(self):
        self.assertEqual(self.status(runtime(image_digest="sha256:abc", expected_image_digest="sha256:abc")), "matched")

    def test_different_digests(self):
        self.assertEqual(self.status(runtime(image_digest="sha256:abc", expected_image_digest="sha256:def")), "drift_detected")

    def test_matching_tags_are_not_enough(self):
        self.assertEqual(self.status(runtime()), "needs_verification")

    def test_missing_runtime(self):
        self.assertEqual(self.status({"services": []}), "needs_verification")

    def test_stopped_container(self):
        self.assertEqual(self.status(runtime(running=False)), "drift_detected")

    def test_changed_image_reference(self):
        self.assertEqual(self.status(runtime(declared_image="nginx:latest")), "drift_detected")

    def test_unexpected_runtime_service(self):
        result = reconcile({"compose_files": []}, runtime())
        self.assertEqual(result["results"][0]["status"], "drift_detected")

if __name__ == "__main__":
    unittest.main()
