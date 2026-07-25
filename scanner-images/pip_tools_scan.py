#!/usr/bin/env python3
"""Read reviewed exact requirement pins and query bounded PyPI JSON metadata."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import NamedTuple

from pip._vendor.packaging.requirements import InvalidRequirement, Requirement
from pip._vendor.packaging.version import InvalidVersion, Version


VERSION = "1.1.1"
MAX_REQUIREMENTS_BYTES = 1 << 20
# Popular projects with long release histories (for example matplotlib) can
# legitimately exceed 1 MiB because PyPI's project endpoint includes every
# release. Keep the response bounded while allowing common project metadata.
MAX_METADATA_BYTES = 16 << 20
MAX_PACKAGES = 256
MAX_DIAGNOSTICS = 256
MAX_RECORD_BYTES = 4096
MAX_MARKER_BYTES = 1024
REQUEST_TIMEOUT_SECONDS = 20

_NORMALIZE_NAME = re.compile(r"[-_.]+")
_INLINE_COMMENT = re.compile(r"\s+#")


class ScanError(Exception):
    """A safe, actionable scanner failure."""


class Pin(NamedTuple):
    name: str
    version: str
    line: int


def normalized_name(value: str) -> str:
    return _NORMALIZE_NAME.sub("-", value).lower()


def diagnostic(path: Path, line: int, code: str, message: str) -> dict[str, object]:
    return {"file": path.name, "line": line, "code": code, "message": message}


def _record_diagnostic(
    diagnostics: list[dict[str, object]], path: Path, line: int, code: str, message: str
) -> None:
    if len(diagnostics) < MAX_DIAGNOSTICS:
        diagnostics.append(diagnostic(path, line, code, message))


def _parse_record(path: Path, line_number: int, raw: str) -> tuple[Pin | None, dict[str, object] | None]:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None, None
    if len(raw.encode("utf-8")) > MAX_RECORD_BYTES:
        return None, diagnostic(path, line_number, "record_too_long", f"record exceeds {MAX_RECORD_BYTES} bytes")
    if line.endswith("\\"):
        return None, diagnostic(path, line_number, "continued_record_unsupported", "continued requirements are not followed")
    comment = _INLINE_COMMENT.search(line)
    if comment is not None:
        line = line[: comment.start()].rstrip()
    lowered = line.lower()
    if lowered.startswith(("-r", "--requirement")):
        return None, diagnostic(path, line_number, "include_unsupported", "nested requirement files are not followed")
    if lowered.startswith(("-c", "--constraint")):
        return None, diagnostic(path, line_number, "constraint_unsupported", "nested constraint files are not followed")
    if lowered.startswith(("-e", "--editable")):
        return None, diagnostic(path, line_number, "editable_unsupported", "editable installs are not scanned")
    if "--hash" in lowered:
        return None, diagnostic(path, line_number, "hash_unsupported", "hashed requirement records are not scanned")
    if "://" in line or lowered.startswith(("git+", "hg+", "svn+", "bzr+")):
        return None, diagnostic(path, line_number, "url_unsupported", "direct URL requirements are not scanned")

    try:
        requirement = Requirement(line)
    except InvalidRequirement:
        return None, diagnostic(path, line_number, "malformed_requirement", "requirement record is malformed")
    if requirement.url is not None:
        return None, diagnostic(path, line_number, "url_unsupported", "direct URL requirements are not scanned")
    if requirement.marker is not None and len(str(requirement.marker).encode("utf-8")) > MAX_MARKER_BYTES:
        return None, diagnostic(path, line_number, "marker_too_long", f"environment marker exceeds {MAX_MARKER_BYTES} bytes")
    specifiers = list(requirement.specifier)
    if len(specifiers) != 1 or specifiers[0].operator != "==" or specifiers[0].version.endswith(".*"):
        return None, diagnostic(path, line_number, "exact_pin_required", "expected one exact pin like package==1.2.3")
    try:
        Version(specifiers[0].version)
    except InvalidVersion:
        return None, diagnostic(path, line_number, "invalid_pinned_version", "exact pin has an invalid version")
    return Pin(requirement.name, specifiers[0].version, line_number), None


def parse_pins(path: Path) -> tuple[list[Pin], list[dict[str, object]]]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ScanError(f"cannot read {path.name}: {exc.strerror or 'read failed'}") from exc
    if len(data) > MAX_REQUIREMENTS_BYTES:
        raise ScanError(f"{path.name} exceeds {MAX_REQUIREMENTS_BYTES} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScanError(f"{path.name} must be UTF-8") from exc

    pins: list[Pin] = []
    diagnostics: list[dict[str, object]] = []
    by_name: dict[str, list[Pin]] = {}
    for line_number, raw in enumerate(text.splitlines(), start=1):
        pin, issue = _parse_record(path, line_number, raw)
        if issue is not None:
            if len(diagnostics) < MAX_DIAGNOSTICS:
                diagnostics.append(issue)
            continue
        if pin is None:
            continue
        key = normalized_name(pin.name)
        by_name.setdefault(key, []).append(pin)
        if len(by_name) > MAX_PACKAGES:
            raise ScanError(f"{path.name} exceeds {MAX_PACKAGES} distinct exact pins")

    for records in by_name.values():
        if len(records) == 1:
            pins.append(records[0])
            continue
        for pin in records:
            _record_diagnostic(
                diagnostics,
                path,
                pin.line,
                "duplicate_pin",
                f"ambiguous duplicate pin for {normalized_name(pin.name)}",
            )
    pins.sort(key=lambda pin: normalized_name(pin.name))
    diagnostics.sort(key=lambda item: (int(item["line"]), str(item["code"])))
    return pins, diagnostics


def latest_version(name: str) -> str:
    encoded_name = urllib.parse.quote(name, safe="")
    request = urllib.request.Request(
        f"https://pypi.org/pypi/{encoded_name}/json",
        headers={"Accept": "application/json", "User-Agent": f"vuelta-pip-tools-scan/{VERSION}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            data = response.read(MAX_METADATA_BYTES + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise ScanError(f"PyPI metadata request failed for {name}") from exc
    if len(data) > MAX_METADATA_BYTES:
        raise ScanError(f"PyPI metadata response exceeds {MAX_METADATA_BYTES} bytes for {name}")
    try:
        payload = json.loads(data)
        info = payload["info"]
        returned_name = info["name"]
        version = info["version"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ScanError(f"PyPI metadata is malformed for {name}") from exc
    if not isinstance(returned_name, str) or normalized_name(returned_name) != normalized_name(name):
        raise ScanError(f"PyPI metadata name does not match {name}")
    if not isinstance(version, str) or not version:
        raise ScanError(f"PyPI metadata has no latest release for {name}")
    return version


def scan_report(path: Path) -> dict[str, object]:
    pins, diagnostics = parse_pins(path)
    candidates: list[dict[str, str]] = []
    for pin in pins:
        target = latest_version(pin.name)
        try:
            current_version = Version(pin.version)
            target_version = Version(target)
        except InvalidVersion as exc:
            raise ScanError(f"PyPI returned an invalid version for {pin.name}") from exc
        if target_version > current_version:
            candidates.append(
                {"name": normalized_name(pin.name), "current": pin.version, "latest_version": target}
            )
    candidates.sort(key=lambda candidate: normalized_name(candidate["name"]))
    return {"candidates": candidates, "diagnostics": diagnostics}


def scan(path: Path) -> list[dict[str, str]]:
    return scan_report(path)["candidates"]  # type: ignore[return-value]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requirements", default="requirements.in")
    parser.add_argument("--report", action="store_true", help="emit candidates and structured diagnostics")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)
    if args.version:
        print(VERSION)
        return 0
    try:
        report = scan_report(Path(args.requirements))
    except ScanError as exc:
        print(f"requirements metadata scan failed: {exc}", file=sys.stderr)
        return 2
    json.dump(report if args.report else report["candidates"], sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
