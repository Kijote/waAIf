import tempfile
import unittest
from pathlib import Path
from inventory import collect, dockerfile_images

class InventoryTests(unittest.TestCase):
    def test_dockerfile_and_compose(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text("ARG VERSION=1.27-alpine\nFROM nginx:$VERSION AS server\n")
            (root / "compose.yaml").write_text("services:\n  web:\n    image: nginx:1.27-alpine\n    ports:\n      - '8080:80'\n")
            report = collect(root)
            self.assertEqual(report["dockerfiles"][0]["base_images"][0]["reference"], "nginx:1.27-alpine")
            self.assertEqual(report["compose_files"][0]["services"][0]["service"], "web")
            self.assertEqual(report["errors"], [])

    def test_unresolved_arg_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Dockerfile"
            path.write_text("FROM nginx:$UNSET\n")
            self.assertFalse(dockerfile_images(path)[0]["fully_resolved"])

    def test_invalid_compose_reports_error(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "compose.yaml").write_text("services: [invalid]")
            self.assertEqual(len(collect(directory)["errors"]), 1)

if __name__ == "__main__":
    unittest.main()
