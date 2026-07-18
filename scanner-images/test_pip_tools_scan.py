from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("pip_tools_scan.py")
SPEC = importlib.util.spec_from_file_location("pip_tools_scan", SCRIPT)
scanner = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(scanner)


class FakeResponse:
    def __init__(self, payload: dict):
        self.data = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit: int) -> bytes:
        return self.data[:limit]


class PipToolsScanTest(unittest.TestCase):
    def write_requirements(self, contents: str) -> Path:
        directory = Path(tempfile.mkdtemp())
        path = directory / "requirements.in"
        path.write_text(contents, encoding="utf-8")
        self.addCleanup(shutil.rmtree, directory)
        return path

    def test_scans_direct_exact_pins(self):
        path = self.write_requirements("requests[socks]==2.31.0\nFlask==3.1.2 # direct\n")
        payloads = {
            "requests": {"info": {"name": "requests", "version": "2.32.4"}},
            "Flask": {"info": {"name": "flask", "version": "3.1.2"}},
        }

        def open_request(request, timeout):
            self.assertEqual(timeout, scanner.REQUEST_TIMEOUT_SECONDS)
            name = request.full_url.split("/")[-2]
            return FakeResponse(payloads[name])

        with mock.patch.object(scanner.urllib.request, "urlopen", side_effect=open_request):
            self.assertEqual(
                scanner.scan(path),
                [{"name": "requests", "current": "2.31.0", "latest_version": "2.32.4"}],
            )

    def test_rejects_unpinned_or_external_inputs(self):
        for requirement in ("requests>=2\n", "-r other.txt\n", "requests @ https://example.invalid/a.whl\n"):
            with self.subTest(requirement=requirement):
                with self.assertRaises(scanner.ScanError):
                    scanner.parse_pins(self.write_requirements(requirement))

    def test_rejects_duplicate_normalized_names(self):
        path = self.write_requirements("demo_pkg==1.0\ndemo-pkg==1.0\n")
        with self.assertRaises(scanner.ScanError):
            scanner.parse_pins(path)

    def test_rejects_mismatched_registry_name(self):
        path = self.write_requirements("requests==2.31.0\n")
        response = FakeResponse({"info": {"name": "different", "version": "9.0.0"}})
        with mock.patch.object(scanner.urllib.request, "urlopen", return_value=response):
            with self.assertRaises(scanner.ScanError):
                scanner.scan(path)


if __name__ == "__main__":
    unittest.main()
