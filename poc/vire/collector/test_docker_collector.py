import json
import unittest
from unittest.mock import patch, Mock
from docker_collector import collect

class CollectorTests(unittest.TestCase):
    @patch("docker_collector.docker_json")
    @patch("docker_collector.subprocess.run")
    def test_sanitized_runtime_inventory(self, run, inspect):
        run.return_value = Mock(stdout="container1\n")
        inspect.side_effect = [
            [{"Id": "container1", "Image": "sha256:123", "State": {"Running": True},
              "Config": {"Image": "nginx:1.27-alpine", "Env": ["PASSWORD=secret"],
                         "Labels": {"com.docker.compose.service": "web",
                                    "com.docker.compose.project": "demo",
                                    "com.docker.compose.project.config_files": "/srv/demo/compose.yaml"}}}],
            [{"RepoDigests": ["nginx@sha256:abc"]}]
        ]
        result = collect()
        self.assertEqual(result["services"][0]["service"], "web")
        self.assertNotIn("secret", json.dumps(result))
        self.assertEqual(result["services"][0]["repo_digests"], ["nginx@sha256:abc"])
        self.assertNotIn("expected_image_digest", result["services"][0])

    @patch("docker_collector.subprocess.run")
    def test_empty_inventory(self, run):
        run.return_value = Mock(stdout="")
        self.assertEqual(collect()["services"], [])

if __name__ == "__main__":
    unittest.main()
