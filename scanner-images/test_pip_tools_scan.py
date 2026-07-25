from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("pip_tools_scan.py")
SPEC = importlib.util.spec_from_file_location("pip_tools_scan", SCRIPT)
scanner = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(scanner)


class FakeResponse:
    def __init__(self, payload: dict | bytes):
        self.data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit: int) -> bytes:
        return self.data[:limit]


class PipToolsScanTest(unittest.TestCase):
    def write_requirements(self, contents: str, name: str = "requirements.in") -> Path:
        directory = Path(tempfile.mkdtemp())
        path = directory / name
        path.write_text(contents, encoding="utf-8")
        self.addCleanup(shutil.rmtree, directory)
        return path

    def test_scans_exact_pins_with_extras_markers_comments_and_normalized_names(self):
        path = self.write_requirements(
            'requests[socks]==2.31.0; python_version >= "3.10" # direct\nFlask==3.1.2 # current\n'
        )
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
                scanner.scan_report(path),
                {
                    "candidates": [
                        {"name": "requests", "current": "2.31.0", "latest_version": "2.32.4"}
                    ],
                    "diagnostics": [],
                },
            )

    def test_unsupported_records_are_diagnostics_and_preserve_valid_pins(self):
        path = self.write_requirements(
            "valid_pkg==1.0\n"
            "range>=2\n"
            "-r other.txt\n"
            "-c constraints.txt\n"
            "-e ./local\n"
            "external @ https://example.invalid/a.whl\n"
            "hashed==1 --hash=sha256:abc\n"
            "invalid==not_a_version\n"
            "not a requirement ???\n",
            "requirements.txt",
        )
        pins, diagnostics = scanner.parse_pins(path)
        self.assertEqual([(pin.name, pin.version) for pin in pins], [("valid_pkg", "1.0")])
        self.assertEqual(
            [item["code"] for item in diagnostics],
            [
                "exact_pin_required",
                "include_unsupported",
                "constraint_unsupported",
                "editable_unsupported",
                "url_unsupported",
                "hash_unsupported",
                "malformed_requirement",
                "malformed_requirement",
            ],
        )

    def test_duplicate_normalized_names_are_all_ambiguous(self):
        path = self.write_requirements("demo_pkg==1.0\ndemo-pkg==2.0\nvalid==1.0\n")
        pins, diagnostics = scanner.parse_pins(path)
        self.assertEqual([(pin.name, pin.version) for pin in pins], [("valid", "1.0")])
        self.assertEqual([item["code"] for item in diagnostics], ["duplicate_pin", "duplicate_pin"])

    def test_scanner_image_packages_are_not_candidates(self):
        path = self.write_requirements("# no project pins; pip and pip-tools are installed only in the image\n")
        with mock.patch.object(scanner.urllib.request, "urlopen") as open_request:
            self.assertEqual(scanner.scan_report(path), {"candidates": [], "diagnostics": []})
        open_request.assert_not_called()

    def test_rejects_mismatched_registry_name(self):
        path = self.write_requirements("requests==2.31.0\n")
        response = FakeResponse({"info": {"name": "different", "version": "9.0.0"}})
        with mock.patch.object(scanner.urllib.request, "urlopen", return_value=response):
            with self.assertRaises(scanner.ScanError):
                scanner.scan(path)

    def test_accepts_common_registry_metadata_larger_than_one_mibibyte(self):
        path = self.write_requirements("matplotlib==3.8.0\n")
        response = FakeResponse(
            {
                "info": {"name": "matplotlib", "version": "3.11.1"},
                "releases": {"padding": "x" * ((1 << 20) + 1)},
            }
        )
        with mock.patch.object(scanner.urllib.request, "urlopen", return_value=response):
            self.assertEqual(
                scanner.scan(path),
                [
                    {
                        "name": "matplotlib",
                        "current": "3.8.0",
                        "latest_version": "3.11.1",
                    }
                ],
            )

    def test_bounds_registry_failures(self):
        path = self.write_requirements("requests==2.31.0\n")
        failures = [
            urllib.error.URLError("timed out"),
            FakeResponse(b"not-json"),
            FakeResponse(b"x" * (scanner.MAX_METADATA_BYTES + 1)),
            FakeResponse({"info": {"name": "requests"}}),
        ]
        for response in failures:
            with self.subTest(response=type(response).__name__):
                patch = mock.patch.object(scanner.urllib.request, "urlopen", side_effect=response) if isinstance(response, Exception) else mock.patch.object(scanner.urllib.request, "urlopen", return_value=response)
                with patch, self.assertRaises(scanner.ScanError):
                    scanner.scan(path)

    def test_oversized_record_is_diagnostic(self):
        path = self.write_requirements("x" * (scanner.MAX_RECORD_BYTES + 1) + "\nvalid==1.0\n")
        pins, diagnostics = scanner.parse_pins(path)
        self.assertEqual([pin.name for pin in pins], ["valid"])
        self.assertEqual(diagnostics[0]["code"], "record_too_long")


if __name__ == "__main__":
    unittest.main()
