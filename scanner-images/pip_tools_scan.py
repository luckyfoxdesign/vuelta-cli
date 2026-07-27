#!/usr/bin/env python3
"""Read a bounded requirements graph and query bounded PyPI JSON metadata."""

from __future__ import annotations

import argparse
import json
import posixpath
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import NamedTuple

from pip._vendor.packaging.requirements import InvalidRequirement, Requirement
from pip._vendor.packaging.version import InvalidVersion, Version


VERSION = "1.3.0"
MAX_REQUIREMENTS_BYTES = 1 << 20
MAX_GRAPH_BYTES = 8 << 20
MAX_GRAPH_FILES = 32
MAX_GRAPH_DEPTH = 8
MAX_GRAPH_RECORDS = 32_768
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
_HASH_OPTION = re.compile(r"(?:^|\s)--hash(?:=|\s+)[^\s]+")
_VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+")


class ScanError(Exception):
    """A safe, actionable scanner failure."""


class InputUnavailable(ScanError):
    """One referenced graph input is unavailable."""


class Pin(NamedTuple):
    name: str
    version: str
    file: str
    line: int


class Constraint(NamedTuple):
    requirement: Requirement
    file: str
    line: int


def normalized_name(value: str) -> str:
    return _NORMALIZE_NAME.sub("-", value).lower()


def diagnostic(
    file: str,
    line: int,
    code: str,
    message: str,
    disposition: str = "invalid",
) -> dict[str, object]:
    return {
        "file": file,
        "line": line,
        "code": code,
        "severity": "info",
        "disposition": disposition,
        "message": message,
    }


def _record_diagnostic(
    diagnostics: list[dict[str, object]],
    file: str,
    line: int,
    code: str,
    message: str,
    disposition: str = "invalid",
) -> None:
    if len(diagnostics) < MAX_DIAGNOSTICS:
        diagnostics.append(diagnostic(file, line, code, message, disposition))


def _strip_inline_comment(value: str) -> str:
    match = _INLINE_COMMENT.search(value)
    return value[: match.start()].rstrip() if match is not None else value


def _logical_records(text: str):
    pending = ""
    start_line = 0
    for line_number, raw in enumerate(text.splitlines(), start=1):
        if not pending:
            start_line = line_number
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            if len(pending.encode("utf-8")) > MAX_RECORD_BYTES:
                yield start_line, pending, True
                pending = ""
            continue
        record = pending + raw
        pending = ""
        yield start_line, record, len(record.encode("utf-8")) > MAX_RECORD_BYTES
    if pending:
        yield start_line, pending, len(pending.encode("utf-8")) > MAX_RECORD_BYTES


def _directive(value: str) -> tuple[str, str] | None:
    line = _strip_inline_comment(value.strip())
    forms = (
        ("--requirement=", "requirement"),
        ("--constraint=", "constraint"),
        ("--requirement ", "requirement"),
        ("--constraint ", "constraint"),
        ("-r ", "requirement"),
        ("-c ", "constraint"),
    )
    for prefix, role in forms:
        if line.startswith(prefix):
            return role, line[len(prefix) :].strip()
    if line.startswith("-r") and len(line) > 2:
        return "requirement", line[2:].strip()
    if line.startswith("-c") and len(line) > 2:
        return "constraint", line[2:].strip()
    return None


def _parse_record(
    file: str,
    line_number: int,
    raw: str,
    role: str,
) -> tuple[Pin | Constraint | None, dict[str, object] | None]:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None, None
    if len(raw.encode("utf-8")) > MAX_RECORD_BYTES:
        return None, diagnostic(
            file,
            line_number,
            "record_too_long",
            f"record exceeds {MAX_RECORD_BYTES} bytes",
        )
    line = _strip_inline_comment(line)
    lowered = line.lower()
    if lowered.startswith(("-e", "--editable")):
        return None, diagnostic(
            file,
            line_number,
            "editable_unsupported",
            "editable installs are not scanned",
            "unsupported",
        )
    if "://" in line or lowered.startswith(_VCS_PREFIXES):
        return None, diagnostic(
            file,
            line_number,
            "url_unsupported",
            "direct URL and VCS requirements are not scanned",
            "unsupported",
        )
    if line.startswith("-"):
        return None, diagnostic(
            file,
            line_number,
            "option_unsupported",
            "requirements option is not scanned",
            "unsupported",
        )

    line = _HASH_OPTION.sub(" ", line).strip()
    try:
        requirement = Requirement(line)
    except InvalidRequirement:
        return None, diagnostic(
            file, line_number, "malformed_requirement", "requirement record is malformed"
        )
    if requirement.url is not None:
        return None, diagnostic(
            file,
            line_number,
            "url_unsupported",
            "direct URL and VCS requirements are not scanned",
            "unsupported",
        )
    if requirement.marker is not None and len(str(requirement.marker).encode("utf-8")) > MAX_MARKER_BYTES:
        return None, diagnostic(
            file,
            line_number,
            "marker_too_long",
            f"environment marker exceeds {MAX_MARKER_BYTES} bytes",
        )
    if role == "constraint":
        if not str(requirement.specifier):
            return None, diagnostic(
                file,
                line_number,
                "constraint_specifier_required",
                "constraint record must declare a version specifier",
            )
        return Constraint(requirement, file, line_number), None

    specifiers = list(requirement.specifier)
    if len(specifiers) != 1 or specifiers[0].operator != "==" or specifiers[0].version.endswith(".*"):
        return None, diagnostic(
            file,
            line_number,
            "exact_pin_required",
            "expected one exact pin like package==1.2.3",
            "unsupported",
        )
    try:
        Version(specifiers[0].version)
    except InvalidVersion:
        return None, diagnostic(
            file,
            line_number,
            "invalid_pinned_version",
            "exact pin has an invalid version",
        )
    return Pin(requirement.name, specifiers[0].version, file, line_number), None


def _safe_reference(parent: str, target: str) -> str | None:
    if (
        not target
        or target.startswith("/")
        or "\\" in target
        or any(character in target for character in "\"'")
        or any(character.isspace() for character in target)
        or "://" in target
        or target.lower().startswith(_VCS_PREFIXES)
    ):
        return None
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(parent), target))
    if resolved in (".", "..") or resolved.startswith("../") or PurePosixPath(resolved).is_absolute():
        return None
    return resolved


class _GraphParser:
    def __init__(self, selected: Path):
        try:
            self.root = selected.parent.resolve(strict=True)
            resolved = selected.resolve(strict=True)
        except OSError as exc:
            raise ScanError("cannot resolve selected requirements input") from exc
        try:
            self.selected = resolved.relative_to(self.root).as_posix()
        except ValueError as exc:
            raise ScanError("selected requirements input escapes its project root") from exc
        self.seen: dict[str, str] = {}
        self.active: set[str] = set()
        self.total_bytes = 0
        self.records = 0
        self.pins: list[Pin] = []
        self.constraints: list[Constraint] = []
        self.diagnostics: list[dict[str, object]] = []

    def read(self, relative: str) -> str:
        if len(self.seen) >= MAX_GRAPH_FILES:
            raise ScanError(f"requirements graph exceeds {MAX_GRAPH_FILES} files")
        candidate = self.root.joinpath(*PurePosixPath(relative).parts)
        probe = self.root
        for part in PurePosixPath(relative).parts:
            probe = probe / part
            if probe.is_symlink():
                raise ScanError("requirements graph traverses a symbolic link")
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(self.root)
            if not resolved.is_file():
                raise ScanError("requirements graph selected a non-regular file")
            data = resolved.read_bytes()
        except ValueError as exc:
            raise ScanError("requirements graph escapes the selected project") from exc
        except FileNotFoundError as exc:
            raise InputUnavailable(f"cannot read {relative}") from exc
        except OSError as exc:
            raise ScanError(f"cannot read {relative}") from exc
        if len(data) > MAX_REQUIREMENTS_BYTES:
            raise ScanError(f"{relative} exceeds {MAX_REQUIREMENTS_BYTES} bytes")
        self.total_bytes += len(data)
        if self.total_bytes > MAX_GRAPH_BYTES:
            raise ScanError(f"requirements graph exceeds {MAX_GRAPH_BYTES} aggregate bytes")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ScanError(f"{relative} must be UTF-8") from exc

    def visit(self, relative: str, role: str, depth: int) -> None:
        if depth > MAX_GRAPH_DEPTH:
            raise ScanError(f"requirements graph exceeds depth {MAX_GRAPH_DEPTH}")
        text = self.read(relative)
        self.seen[relative] = role
        self.active.add(relative)
        for line_number, raw, oversized in _logical_records(text):
            self.records += 1
            if self.records > MAX_GRAPH_RECORDS:
                raise ScanError(f"requirements graph exceeds {MAX_GRAPH_RECORDS} records")
            if oversized:
                _record_diagnostic(
                    self.diagnostics,
                    relative,
                    line_number,
                    "record_too_long",
                    f"record exceeds {MAX_RECORD_BYTES} bytes",
                )
                continue
            directive = _directive(raw)
            if directive is not None:
                next_role, target = directive
                if role == "constraint":
                    next_role = "constraint"
                resolved = _safe_reference(relative, target)
                if resolved is None:
                    _record_diagnostic(
                        self.diagnostics,
                        relative,
                        line_number,
                        "include_invalid",
                        "include target must be one safe project-relative path",
                    )
                    continue
                if resolved in self.active:
                    _record_diagnostic(
                        self.diagnostics,
                        relative,
                        line_number,
                        "include_cycle",
                        "requirements include cycle was ignored",
                    )
                    continue
                if resolved in self.seen:
                    _record_diagnostic(
                        self.diagnostics,
                        relative,
                        line_number,
                        "duplicate_include",
                        "duplicate requirements include was ignored",
                    )
                    continue
                try:
                    self.visit(resolved, next_role, depth + 1)
                except InputUnavailable:
                    _record_diagnostic(
                        self.diagnostics,
                        relative,
                        line_number,
                        "include_unavailable",
                        "referenced requirements input is unavailable",
                        "unsupported",
                    )
                continue
            parsed, issue = _parse_record(relative, line_number, raw, role)
            if issue is not None:
                if len(self.diagnostics) < MAX_DIAGNOSTICS:
                    self.diagnostics.append(issue)
                continue
            if isinstance(parsed, Pin):
                self.pins.append(parsed)
            elif isinstance(parsed, Constraint):
                self.constraints.append(parsed)
                _record_diagnostic(
                    self.diagnostics,
                    parsed.file,
                    parsed.line,
                    "constraint_applied",
                    f"constraint recorded for {normalized_name(parsed.requirement.name)}",
                    "constrained",
                )
        self.active.remove(relative)


def _parse_graph_records(
    path: Path,
) -> tuple[list[Pin], list[dict[str, object]], dict[str, list[Constraint]]]:
    parser = _GraphParser(path)
    parser.visit(parser.selected, "requirement", 0)

    constraints: dict[str, list[Constraint]] = {}
    for constraint in parser.constraints:
        constraints.setdefault(normalized_name(constraint.requirement.name), []).append(constraint)

    by_name: dict[str, list[Pin]] = {}
    for pin in parser.pins:
        by_name.setdefault(normalized_name(pin.name), []).append(pin)
        if len(by_name) > MAX_PACKAGES:
            raise ScanError(f"requirements graph exceeds {MAX_PACKAGES} distinct exact pins")

    pins: list[Pin] = []
    for name in sorted(by_name):
        records = by_name[name]
        versions = {pin.version for pin in records}
        if len(versions) > 1:
            for pin in records:
                _record_diagnostic(
                    parser.diagnostics,
                    pin.file,
                    pin.line,
                    "conflicting_pin",
                    f"incompatible exact pins for {name}",
                )
            continue
        pin = records[0]
        for duplicate in records[1:]:
            _record_diagnostic(
                parser.diagnostics,
                duplicate.file,
                duplicate.line,
                "duplicate_pin",
                f"duplicate exact pin for {name} was ignored",
            )
        try:
            current = Version(pin.version)
        except InvalidVersion:
            continue
        incompatible = [
            item
            for item in constraints.get(name, [])
            if current not in item.requirement.specifier
        ]
        if incompatible:
            _record_diagnostic(
                parser.diagnostics,
                pin.file,
                pin.line,
                "pin_conflicts_with_constraint",
                f"exact pin conflicts with a constraint for {name}",
            )
            continue
        pins.append(pin)

    parser.diagnostics.sort(
        key=lambda item: (
            str(item["file"]),
            int(item["line"]),
            str(item["code"]),
        )
    )
    return pins, parser.diagnostics, constraints


def parse_pins(path: Path) -> tuple[list[Pin], list[dict[str, object]]]:
    pins, diagnostics, _constraints = _parse_graph_records(path)
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
        raise ScanError(f"PyPI metadata request failed for {normalized_name(name)}") from exc
    if len(data) > MAX_METADATA_BYTES:
        raise ScanError(f"PyPI metadata response exceeds {MAX_METADATA_BYTES} bytes for {normalized_name(name)}")
    try:
        payload = json.loads(data)
        info = payload["info"]
        returned_name = info["name"]
        version = info["version"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ScanError(f"PyPI metadata is malformed for {normalized_name(name)}") from exc
    if not isinstance(returned_name, str) or normalized_name(returned_name) != normalized_name(name):
        raise ScanError(f"PyPI metadata name does not match {normalized_name(name)}")
    if not isinstance(version, str) or not version:
        raise ScanError(f"PyPI metadata has no latest release for {normalized_name(name)}")
    return version


def scan_report(path: Path) -> dict[str, object]:
    pins, diagnostics, constraints = _parse_graph_records(path)
    candidates: list[dict[str, object]] = []
    for pin in pins:
        try:
            target = latest_version(pin.name)
            current_version = Version(pin.version)
            target_version = Version(target)
        except (InvalidVersion, ScanError):
            _record_diagnostic(
                diagnostics,
                pin.file,
                pin.line,
                "metadata_unavailable",
                f"registry metadata is unavailable for {normalized_name(pin.name)}",
                "unsupported",
            )
            continue
        blocked = [
            item
            for item in constraints.get(normalized_name(pin.name), [])
            if target_version not in item.requirement.specifier
        ]
        if blocked:
            _record_diagnostic(
                diagnostics,
                pin.file,
                pin.line,
                "constraint_blocks_latest",
                f"latest release is excluded by a constraint for {normalized_name(pin.name)}",
                "constrained",
            )
            continue
        if target_version > current_version:
            candidates.append(
                {
                    "name": normalized_name(pin.name),
                    "current": pin.version,
                    "latest_version": target,
                    "file": pin.file,
                    "line": pin.line,
                    "disposition": (
                        "constrained"
                        if constraints.get(normalized_name(pin.name))
                        else "scanned"
                    ),
                }
            )
    candidates.sort(
        key=lambda candidate: (
            normalized_name(str(candidate["name"])),
            str(candidate["file"]),
            int(candidate["line"]),
        )
    )
    diagnostics.sort(
        key=lambda item: (
            str(item["file"]),
            int(item["line"]),
            str(item["code"]),
        )
    )
    return {"candidates": candidates, "diagnostics": diagnostics}


def scan(path: Path) -> list[dict[str, object]]:
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
