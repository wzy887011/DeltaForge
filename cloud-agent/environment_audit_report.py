#!/usr/bin/env python3
"""Summarize read-only Android environment audit evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path


SYSCALL_RE = re.compile(r"(?:^|\s)(?P<timestamp>\d+\.\d+)\s+(?P<name>[A-Za-z0-9_]+)\(")
QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
FILE_SYSCALLS = {
    "access",
    "faccessat",
    "faccessat2",
    "open",
    "openat",
    "readlink",
    "readlinkat",
    "stat",
    "stat64",
    "statfs",
    "statx",
    "lstat",
    "newfstatat",
}
NETWORK_SYSCALLS = {
    "accept",
    "accept4",
    "bind",
    "connect",
    "getpeername",
    "getsockname",
    "getsockopt",
    "recvfrom",
    "recvmmsg",
    "sendmmsg",
    "sendto",
    "setsockopt",
    "socket",
}
KERNEL_SYSCALLS = {"uname", "sysinfo", "prctl"}


def _unquote(value: str) -> str:
    return value.replace(r"\"", '"').replace(r"\\", "\\")


def _record(
    counts: Counter[str],
    grouped: dict[tuple[str, str, str, str], dict[str, object]],
    category: str,
    source: str,
    value: str,
    operation: str,
    timestamp: str = "",
) -> None:
    counts[category] += 1
    key = (category, source, value, operation)
    item = grouped.setdefault(
        key,
        {
            "category": category,
            "source": source,
            "value": value,
            "operation": operation,
            "count": 0,
            "first_timestamp": timestamp or None,
            "last_timestamp": timestamp or None,
        },
    )
    item["count"] = int(item["count"]) + 1
    if timestamp:
        if not item["first_timestamp"]:
            item["first_timestamp"] = timestamp
        item["last_timestamp"] = timestamp


def _parse_strace(
    path: Path,
    counts: Counter[str],
    grouped: dict[tuple[str, str, str, str], dict[str, object]],
) -> None:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = SYSCALL_RE.search(line)
        if not match:
            continue
        timestamp = match.group("timestamp")
        name = match.group("name")
        quoted = [_unquote(value) for value in QUOTED_RE.findall(line)]
        if name in FILE_SYSCALLS:
            path_value = next((value for value in quoted if value.startswith("/")), "")
            _record(counts, grouped, "filesystem", path.name, path_value or name, name, timestamp)
        elif name == "ioctl":
            request = re.search(r"ioctl\([^,]+,\s*([^,\)]+)", line)
            value = request.group(1).strip() if request else "ioctl"
            _record(counts, grouped, "ioctl", path.name, value, name, timestamp)
        elif name in NETWORK_SYSCALLS:
            value = quoted[0] if quoted else name
            _record(counts, grouped, "network", path.name, value, name, timestamp)
        elif name in KERNEL_SYSCALLS:
            _record(counts, grouped, "kernel", path.name, name, name, timestamp)


def _parse_static(
    path: Path,
    counts: Counter[str],
    grouped: dict[tuple[str, str, str, str], dict[str, object]],
) -> None:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        module, kind, value = parts
        category = {
            "path": "filesystem",
            "property": "property",
            "token": "static_token",
        }.get(kind, "static_token")
        _record(counts, grouped, category, module, value, f"static:{kind}")


def build_report(directory: str | Path) -> dict[str, object]:
    root = Path(directory)
    counts: Counter[str] = Counter()
    grouped: dict[tuple[str, str, str, str], dict[str, object]] = {}
    inputs: list[str] = []

    for path in sorted(root.glob("strace*")):
        if path.is_file():
            inputs.append(path.name)
            _parse_strace(path, counts, grouped)
    static_path = root / "static_candidates.tsv"
    if static_path.is_file():
        inputs.append(static_path.name)
        _parse_static(static_path, counts, grouped)

    signals = sorted(
        grouped.values(),
        key=lambda item: (
            str(item["category"]),
            str(item["value"]),
            str(item["source"]),
            str(item["operation"]),
        ),
    )
    return {
        "schema": 1,
        "source_directory": str(root),
        "inputs": inputs,
        "summary": dict(sorted(counts.items())),
        "signals": signals,
    }


def _print_text(report: dict[str, object]) -> None:
    print("Environment access audit summary")
    summary = report["summary"]
    if isinstance(summary, dict):
        for category, count in summary.items():
            print(f"  {category}: {count}")
    print(f"  unique_signals: {len(report['signals'])}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", help="audit evidence directory")
    parser.add_argument("--json", dest="json_path", help="write JSON report")
    args = parser.parse_args(argv)
    report = build_report(args.directory)
    if args.json_path:
        output = Path(args.json_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        work = output.with_name(output.name + ".work")
        work.write_text(
            json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        work.replace(output)
    _print_text(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
