#!/usr/bin/env python3
"""Read exact requirements.in pins and query bounded PyPI JSON metadata."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from pip._vendor.packaging.version import InvalidVersion, Version


VERSION = "1.0.0"
MAX_REQUIREMENTS_BYTES = 1 << 20
MAX_METADATA_BYTES = 1 << 20
MAX_PACKAGES = 256
REQUEST_TIMEOUT_SECONDS = 20

_PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[A-Za-z0-9._-]+(?:,[A-Za-z0-9._-]+)*\])?"
    r"\s*==\s*(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)"
    r"(?:\s+#.*)?$"
)
_NORMALIZE_NAME = re.compile(r"[-_.]+")


class ScanError(Exception):
    """A safe, actionable scanner failure."""


def normalized_name(value: str) -> str:
    return _NORMALIZE_NAME.sub("-", value).lower()


def parse_pins(path: Path) -> list[tuple[str, str]]:
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

    pins: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            raise ScanError(f"{path.name}:{line_number}: continued requirements are unsupported")
        match = _PIN.fullmatch(line)
        if match is None:
            raise ScanError(
                f"{path.name}:{line_number}: expected a direct exact pin like package==1.2.3"
            )
        name = match.group("name")
        key = normalized_name(name)
        if key in seen:
            raise ScanError(f"{path.name}:{line_number}: duplicate pin for {name}")
        seen.add(key)
        pins.append((name, match.group("version")))
        if len(pins) > MAX_PACKAGES:
            raise ScanError(f"{path.name} exceeds {MAX_PACKAGES} direct pins")
    return pins


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
        raise ScanError(f"PyPI metadata has no latest version for {name}")
    return version


def scan(path: Path) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    for name, current in parse_pins(path):
        target = latest_version(name)
        try:
            current_version = Version(current)
            target_version = Version(target)
        except InvalidVersion as exc:
            raise ScanError(f"PyPI returned an invalid version for {name}") from exc
        if target_version > current_version:
            candidates.append(
                {"name": name, "current": current, "latest_version": target}
            )
    candidates.sort(key=lambda candidate: normalized_name(candidate["name"]))
    return candidates


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requirements", default="requirements.in")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)
    if args.version:
        print(VERSION)
        return 0
    try:
        candidates = scan(Path(args.requirements))
    except ScanError as exc:
        print(f"pip-tools scan failed: {exc}", file=sys.stderr)
        return 2
    json.dump(candidates, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
