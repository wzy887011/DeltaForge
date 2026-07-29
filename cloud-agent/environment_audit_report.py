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
FACET_RULES = {
    "anti_cheat": re.compile(
        r"libtersafe|tss_(?:ano|tmp)|ano_tmp|ace_shell|dg-patch|gamesecurity",
        re.IGNORECASE,
    ),
    "telemetry": re.compile(
        r"tdatamaster|(?:^|[^a-z])tdm(?:[^a-z]|$)|qimei|turing|hawk|crashsight|beacon",
        re.IGNORECASE,
    ),
    "identity": re.compile(
        r"serial|imei|oaid|vaid|android_id|settings_ssaid|build\.fingerprint|"
        r"mac_addr|wlan\d*/address|device_id|cpuid|meid",
        re.IGNORECASE,
    ),
    "root_instrumentation": re.compile(
        r"magisk|kernelsu|xposed|frida|libforgehook|/data/adb|(?:^|/)su(?:$|/)|s9su",
        re.IGNORECASE,
    ),
    "virtualization": re.compile(
        r"qemu|goldfish|ranchu|virtio|vbox|lxc|container|overlay|mountinfo|"
        r"rockchip|rk3588|/proc/(?:self|\d+)/(?:maps|mounts|mountinfo)",
        re.IGNORECASE,
    ),
    "hardware_security": re.compile(
        r"kgsl|adreno|mali|keymint|keymaster|strongbox|gatekeeper|"
        r"(?:^|[^a-z])tee(?:[^a-z]|$)|soc0|device.?tree|selinux|ro\.hardware",
        re.IGNORECASE,
    ),
}


def classify_facets(value: str) -> list[str]:
    return sorted(name for name, pattern in FACET_RULES.items() if pattern.search(value))


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


def _parse_inventory(path: Path) -> list[dict[str, object]]:
    inventory: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("\t", 5)
        if len(parts) != 6:
            continue
        module, size, sha256, build_id, version_text, file_path = parts
        try:
            byte_count = int(size)
        except ValueError:
            continue
        versions = sorted(set(re.findall(r"\d+\.\d+\.\d+\.\d+", version_text)))
        inventory.append(
            {
                "module": module,
                "bytes": byte_count,
                "sha256": sha256,
                "build_id": build_id or None,
                "versions": versions,
                "path": file_path,
            }
        )
    return sorted(inventory, key=lambda item: (str(item["module"]), str(item["path"])))


def build_report(directory: str | Path) -> dict[str, object]:
    root = Path(directory)
    counts: Counter[str] = Counter()
    grouped: dict[tuple[str, str, str, str], dict[str, object]] = {}
    inputs: list[str] = []
    inventory: list[dict[str, object]] = []

    for path in sorted(root.glob("strace*")):
        if path.is_file():
            inputs.append(path.name)
            _parse_strace(path, counts, grouped)
    static_path = root / "static_candidates.tsv"
    if static_path.is_file():
        inputs.append(static_path.name)
        _parse_static(static_path, counts, grouped)
    inventory_path = root / "native_inventory.tsv"
    if inventory_path.is_file():
        inputs.append(inventory_path.name)
        inventory = _parse_inventory(inventory_path)

    signals = sorted(
        grouped.values(),
        key=lambda item: (
            str(item["category"]),
            str(item["value"]),
            str(item["source"]),
            str(item["operation"]),
        ),
    )
    facet_counts: Counter[str] = Counter()
    for item in signals:
        haystack = f"{item['source']} {item['value']} {item['operation']}"
        facets = classify_facets(haystack)
        item["facets"] = facets
        for facet in facets:
            facet_counts[facet] += int(item["count"])
    return {
        "schema": 2,
        "source_directory": str(root),
        "inputs": inputs,
        "summary": dict(sorted(counts.items())),
        "facet_summary": dict(sorted(facet_counts.items())),
        "native_inventory": inventory,
        "signals": signals,
    }


def _print_text(report: dict[str, object]) -> None:
    print("Environment access audit summary")
    summary = report["summary"]
    if isinstance(summary, dict):
        for category, count in summary.items():
            print(f"  {category}: {count}")
    facets = report["facet_summary"]
    if isinstance(facets, dict):
        print("Detection surfaces")
        for facet, count in facets.items():
            print(f"  {facet}: {count}")
    print(f"  native_inventory: {len(report['native_inventory'])}")
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
