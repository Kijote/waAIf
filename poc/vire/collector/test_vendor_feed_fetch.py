import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from vendor_feed_fetch import retrieve, save, url_for

class Response:
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, n): return b'{"packages":[]}'

class VendorFeedTests(unittest.TestCase):
    def test_debian_url(self):
        self.assertEqual(url_for("debian"), "https://security-tracker.debian.org/tracker/data/json")

    def test_alpine_url(self):
        self.assertEqual(url_for("alpine", release="v3.22", repository="main"),
                         "https://secdb.alpinelinux.org/v3.22/main.json")

    def test_reject_invalid_release(self):
        with self.assertRaises(ValueError):
            url_for("alpine", release="../../etc", repository="main")

    def test_reject_invalid_repository(self):
        with self.assertRaises(ValueError):
            url_for("alpine", release="v3.22", repository="testing")

    def test_ubuntu_not_yet_supported(self):
        with self.assertRaises(ValueError):
            url_for("ubuntu")

    def test_retrieve_bounded(self):
        self.assertEqual(retrieve(url_for("debian"), opener=Mock(return_value=Response())), b'{"packages":[]}')

    def test_sha256_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "feed.json"
            meta = save(path, b"sample", url_for("debian"))
            self.assertEqual(meta["sha256"], hashlib.sha256(b"sample").hexdigest())
            self.assertFalse(meta["verified_vendor_status"])
            self.assertTrue(Path(str(path) + ".metadata.json").exists())

if __name__ == "__main__":
    unittest.main()
