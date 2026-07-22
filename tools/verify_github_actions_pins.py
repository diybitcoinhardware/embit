#!/usr/bin/env python3
"""Verify third-party GitHub Actions are pinned to full commit SHAs."""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<value>.+?)\s*$")
FIRST_PARTY_OWNERS = {"actions", "github"}


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    value: str
    reason: str


def strip_inline_comment(value: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#":
            return value[:index].rstrip()
    return value.strip()


def normalize_scalar(value: str) -> str:
    value = strip_inline_comment(value)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def is_out_of_scope(value: str) -> bool:
    if value.startswith("./") or value.startswith("../") or value.startswith("/"):
        return True
    if value.startswith("docker://"):
        return True
    owner = value.split("/", 1)[0].lower()
    return owner in FIRST_PARTY_OWNERS


def check_uses_value(value: str) -> str | None:
    if is_out_of_scope(value):
        return None
    if "@" not in value:
        return "missing ref"
    _action, ref = value.rsplit("@", 1)
    if not ref:
        return "missing ref"
    if not FULL_SHA_RE.fullmatch(ref):
        return "ref is not a full 40-character commit SHA"
    return None


def scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    with path.open("r", encoding="utf-8") as workflow:
        for line_number, line in enumerate(workflow, start=1):
            match = USES_RE.match(line)
            if not match:
                continue
            value = normalize_scalar(match.group("value"))
            if not value or value in {"|", ">"}:
                findings.append(
                    Finding(
                        path,
                        line_number,
                        value or "<empty>",
                        "missing action reference",
                    )
                )
                continue
            reason = check_uses_value(value)
            if reason is not None:
                findings.append(Finding(path, line_number, value, reason))
    return findings


def workflow_files(root: Path) -> list[Path]:
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.exists():
        return []
    return sorted(
        path
        for pattern in ("*.yml", "*.yaml")
        for path in workflows_dir.glob(pattern)
        if path.is_file()
    )


def scan_repository(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in workflow_files(root):
        findings.extend(scan_file(path))
    return findings


def write_workflow(root: Path, name: str, uses_values: list[str]) -> None:
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    steps = "\n".join(f"      - uses: {value}" for value in uses_values)
    (workflow_dir / name).write_text(
        "\n".join(
            [
                "name: fixture",
                "on: pull_request",
                "jobs:",
                "  check:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                steps,
                "",
            ]
        ),
        encoding="utf-8",
    )


def run_self_test() -> int:
    failing_values = [
        "thirdparty/action@v1",
        "thirdparty/action@main",
        "thirdparty/action@release/v1",
        "thirdparty/action@1234567",
        "thirdparty/action",
        "thirdparty/action@${{ inputs.ref }}",
        "thirdparty/action/path@v1",
    ]
    passing_values = [
        "thirdparty/action@0123456789abcdef0123456789abcdef01234567",
        "thirdparty/action/path@0123456789abcdef0123456789abcdef01234567",
        "actions/checkout@v4",
        "github/codeql-action/init@v3",
        "./.github/actions/local-action",
        "docker://python:3.13-slim",
    ]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_workflow(root, "failing.yml", failing_values)
        write_workflow(root, "passing.yaml", passing_values)
        findings = scan_repository(root)

    found_values = {finding.value for finding in findings}
    missing_failures = sorted(set(failing_values) - found_values)
    unexpected_failures = sorted(found_values - set(failing_values))
    if missing_failures or unexpected_failures:
        if missing_failures:
            print("Self-test missed expected failures:", file=sys.stderr)
            for value in missing_failures:
                print(f"  {value}", file=sys.stderr)
        if unexpected_failures:
            print("Self-test produced unexpected failures:", file=sys.stderr)
            for value in unexpected_failures:
                print(f"  {value}", file=sys.stderr)
        return 1
    print("GitHub Actions pin verifier self-test passed")
    return 0


def print_findings(findings: list[Finding]) -> None:
    print(
        "Third-party GitHub Actions must be pinned to full commit SHAs.",
        file=sys.stderr,
    )
    for finding in findings:
        print(
            f"{finding.path}:{finding.line}: {finding.value} ({finding.reason})",
            file=sys.stderr,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run fixture-based verifier tests before scanning the repository",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root to scan",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        result = run_self_test()
        if result != 0:
            return result

    findings = scan_repository(args.root)
    if findings:
        print_findings(findings)
        return 1
    print("GitHub Actions third-party pin policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
