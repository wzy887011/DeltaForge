#!/usr/bin/env python3
"""Build complete, source-backed Android environment inventories and diffs."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from typing import Iterable


CONFIG_GLOBS = (
    "manifest.tsv",
    "candidates.tsv",
    "errors.tsv",
    "file_hashes.tsv",
    "commands/boot_kernel/*.stdout.txt",
    "commands/identity_projection/*.stdout.txt",
    "commands/init_services/*.stdout.txt",
    "commands/namespace_projection/*.stdout.txt",
    "commands/network_projection/*.stdout.txt",
    "commands/packages_artifacts/*.stdout.txt",
    "commands/root_framework/*.stdout.txt",
    "supplemental/*.stdout.txt",
    "processes/system_server/cmdline.txt",
    "processes/system_server/environ.txt",
    "processes/system_server/mountinfo.txt",
    "processes/system_server/namespaces.txt",
    "processes/system_server/selinux_context.txt",
    "processes/system_server/status.txt",
    "processes/zygote/cmdline.txt",
    "processes/zygote/environ.txt",
    "processes/zygote/mountinfo.txt",
    "processes/zygote/namespaces.txt",
    "processes/zygote/selinux_context.txt",
    "processes/zygote/status.txt",
    "processes/zygote64/cmdline.txt",
    "processes/zygote64/environ.txt",
    "processes/zygote64/mountinfo.txt",
    "processes/zygote64/namespaces.txt",
    "processes/zygote64/selinux_context.txt",
    "processes/zygote64/status.txt",
)

EXCLUDED_CONFIGURATION_FILES = {
    "commands/packages_artifacts/target_package.stdout.txt",
    "commands/packages_artifacts/target_paths.stdout.txt",
}

PROPERTY_RE = re.compile(r"^\[([^]]+)\]: \[(.*)\]$")
PACKAGE_RE = re.compile(r"^package:(.*?)=([A-Za-z0-9._]+)(?:\s+uid:(\d+))?$")
BINDER_RE = re.compile(r"^\s*\d+\s+([^:]+):\s*(.*)$")


def evidence_root(path: Path) -> Path:
    path = Path(path).resolve()
    if (path / "manifest.tsv").is_file():
        return path
    children = [child for child in path.iterdir() if (child / "manifest.tsv").is_file()]
    if len(children) != 1:
        raise ValueError(f"expected one evidence root below {path}, found {len(children)}")
    return children[0]


def configuration_paths(root: Path) -> list[Path]:
    paths: set[Path] = set()
    for pattern in CONFIG_GLOBS:
        paths.update(path for path in root.glob(pattern) if path.is_file())
    return sorted(
        (
            path
            for path in paths
            if path.relative_to(root).as_posix() not in EXCLUDED_CONFIGURATION_FILES
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def text_record(root: Path, path: Path) -> dict:
    raw = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "text": raw.decode("utf-8-sig", errors="replace"),
    }


def parse_properties(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        match = PROPERTY_RE.match(line)
        if match:
            result[match.group(1)] = match.group(2)
    return dict(sorted(result.items()))


def parse_kernel_config(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
            continue
        if line.startswith("# CONFIG_") and line.endswith(" is not set"):
            result[line[2 : -len(" is not set")]] = "not set"
    return dict(sorted(result.items()))


def parse_init_services(properties: dict[str, str]) -> dict[str, str]:
    return {
        key.removeprefix("init.svc."): value
        for key, value in properties.items()
        if key.startswith("init.svc.")
    }


def parse_processes(text: str) -> dict[str, int]:
    signatures: Counter[str] = Counter()
    for line in text.splitlines():
        fields = line.split("\t", 5)
        if len(fields) != 6 or not fields[0].isdigit():
            continue
        _, _, _, name, executable, command = fields
        signatures[f"{name}|{executable}|{command.strip()}"] += 1
    return dict(sorted(signatures.items()))


def parse_mountinfo(records: Iterable[dict]) -> dict[str, str]:
    result = {}
    for record in records:
        source_path = record["path"]
        for number, line in enumerate(record["text"].splitlines(), 1):
            if " - " not in line:
                continue
            left, right = line.split(" - ", 1)
            left_fields = left.split()
            right_fields = right.split()
            if len(left_fields) < 6 or len(right_fields) < 2:
                continue
            mount_point = left_fields[4]
            fs_type = right_fields[0]
            device = right_fields[1]
            key = f"{source_path}:{number}:{mount_point}|{fs_type}|{device}"
            result[key] = line
    return dict(sorted(result.items()))


def parse_packages(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        match = PACKAGE_RE.match(line.strip())
        if not match:
            continue
        apk_path, package_name, uid = match.groups()
        result[package_name] = f"path={apk_path};uid={uid or ''}"
    return dict(sorted(result.items()))


def parse_binder_services(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        match = BINDER_RE.match(line)
        if match:
            result[match.group(1).strip()] = match.group(2).strip()
    return dict(sorted(result.items()))


def nonempty_lines(text: str) -> dict[str, int]:
    counts = Counter(line.strip() for line in text.splitlines() if line.strip())
    return dict(sorted(counts.items()))


def parse_key_values(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key:
            result[key] = value
    return dict(sorted(result.items()))


def get_text(records_by_path: dict[str, dict], relative: str) -> str:
    record = records_by_path.get(relative)
    return record["text"] if record else ""


def first_text(records_by_path: dict[str, dict], *relatives: str) -> str:
    for relative in relatives:
        text = get_text(records_by_path, relative)
        if text and "Failure calling service" not in text:
            return text
    return ""


def build_inventory(root: Path, label: str) -> dict:
    root = evidence_root(root)
    records = [text_record(root, path) for path in configuration_paths(root)]
    records_by_path = {record["path"]: record for record in records}

    properties = parse_properties(
        get_text(records_by_path, "commands/identity_projection/getprop.stdout.txt")
    )
    kernel_config = parse_kernel_config(
        get_text(records_by_path, "commands/boot_kernel/kernel_config.stdout.txt")
    )
    mount_records = [
        record
        for record in records
        if "mountinfo" in Path(record["path"]).name
        or record["path"].endswith("root_mounts.stdout.txt")
    ]

    normalized = {
        "properties": properties,
        "kernel_config": kernel_config,
        "init_services": parse_init_services(properties),
        "processes": parse_processes(
            get_text(records_by_path, "commands/root_framework/proc_walk.stdout.txt")
        ),
        "mounts": parse_mountinfo(mount_records),
        "packages": {},
        "third_party_packages": {},
        "binder_services": parse_binder_services(
            get_text(records_by_path, "commands/init_services/binder_services.stdout.txt")
        ),
        "hal_inventory": nonempty_lines(
            get_text(records_by_path, "commands/init_services/hal_inventory.stdout.txt")
        ),
        "network_addresses": nonempty_lines(
            get_text(records_by_path, "commands/network_projection/address.stdout.txt")
        ),
        "network_routes": nonempty_lines(
            get_text(records_by_path, "commands/network_projection/routes.stdout.txt")
        ),
        "network_rules": nonempty_lines(
            get_text(records_by_path, "commands/network_projection/rules.stdout.txt")
        ),
        "network_sockets": nonempty_lines(
            get_text(records_by_path, "commands/network_projection/sockets.stdout.txt")
        ),
        "settings_global": parse_key_values(
            first_text(
                records_by_path,
                "commands/identity_projection/settings_global.stdout.txt",
                "supplemental/settings_global.stdout.txt",
            )
        ),
        "settings_secure": parse_key_values(
            first_text(
                records_by_path,
                "commands/identity_projection/settings_secure.stdout.txt",
                "supplemental/settings_secure.stdout.txt",
            )
        ),
        "settings_system": parse_key_values(
            first_text(
                records_by_path,
                "commands/identity_projection/settings_system.stdout.txt",
                "supplemental/settings_system.stdout.txt",
            )
        ),
        "device_config": parse_key_values(
            first_text(
                records_by_path,
                "commands/identity_projection/device_config.stdout.txt",
                "supplemental/device_config.stdout.txt",
            )
        ),
        "features": nonempty_lines(
            first_text(
                records_by_path,
                "commands/packages_artifacts/features.stdout.txt",
                "supplemental/features.stdout.txt",
            )
        ),
        "shared_libraries": nonempty_lines(
            first_text(
                records_by_path,
                "commands/packages_artifacts/libraries.stdout.txt",
                "supplemental/libraries.stdout.txt",
            )
        ),
        "overlays": nonempty_lines(
            first_text(
                records_by_path,
                "commands/packages_artifacts/overlays.stdout.txt",
                "supplemental/overlays.stdout.txt",
            )
        ),
    }

    package_text = get_text(
        records_by_path, "commands/packages_artifacts/packages_all.stdout.txt"
    )
    third_party_text = get_text(
        records_by_path,
        "commands/packages_artifacts/packages_third_party.stdout.txt",
    )
    normalized["packages"] = parse_packages(package_text) or parse_packages(
        get_text(records_by_path, "supplemental/packages_all.stdout.txt")
    )
    normalized["third_party_packages"] = parse_packages(
        third_party_text
    ) or parse_packages(
        get_text(records_by_path, "supplemental/packages_third_party.stdout.txt")
    )

    return {
        "schema": 1,
        "label": label,
        "evidence_root": str(root),
        "source_file_count": len(records),
        "source_bytes": sum(record["bytes"] for record in records),
        "normalized": normalized,
        "sources": records,
    }


def mapping_diff(left: dict, right: dict) -> list[dict]:
    result = []
    for key in sorted(set(left) | set(right)):
        left_value = left.get(key)
        right_value = right.get(key)
        if left_value != right_value:
            result.append(
                {
                    "key": key,
                    "cloud_phone": left_value,
                    "cloud_real_phone": right_value,
                }
            )
    return result


def build_diff(cloud_phone: dict, cloud_real_phone: dict) -> dict:
    domains = {}
    left_domains = cloud_phone["normalized"]
    right_domains = cloud_real_phone["normalized"]
    for domain in sorted(set(left_domains) | set(right_domains)):
        left = left_domains.get(domain, {})
        right = right_domains.get(domain, {})
        domains[domain] = {
            "cloud_phone_count": len(left),
            "cloud_real_phone_count": len(right),
            "difference_count": len(mapping_diff(left, right)),
            "differences": mapping_diff(left, right),
        }
    return {"schema": 1, "domains": domains}


def markdown_cell(value: object) -> str:
    if value is None:
        return "<absent>"
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_diff_markdown(diff: dict) -> str:
    lines = [
        "# Complete Android Environment Configuration Diff",
        "",
        "Every normalized difference is listed below. The companion JSON files and",
        "`*-config-all.txt` bundles retain the complete source text, byte counts, and",
        "SHA-256 for every collected configuration file.",
        "",
        "## Domain Summary",
        "",
        "| Domain | Cloud phone | Cloud real phone | Differences |",
        "|---|---:|---:|---:|",
    ]
    for domain, payload in diff["domains"].items():
        lines.append(
            f"| `{domain}` | {payload['cloud_phone_count']} | "
            f"{payload['cloud_real_phone_count']} | {payload['difference_count']} |"
        )

    for domain, payload in diff["domains"].items():
        lines.extend(
            [
                "",
                f"## {domain}",
                "",
                "| Key | Cloud phone | Cloud real phone |",
                "|---|---|---|",
            ]
        )
        if not payload["differences"]:
            lines.append("| `<none>` |  |  |")
            continue
        for item in payload["differences"]:
            lines.append(
                "| `{}` | `{}` | `{}` |".format(
                    markdown_cell(item["key"]),
                    markdown_cell(item["cloud_phone"]),
                    markdown_cell(item["cloud_real_phone"]),
                )
            )
    return "\n".join(lines) + "\n"


def write_raw_bundle(inventory: dict, path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for record in inventory["sources"]:
            stream.write(f"===== {record['path']} =====\n")
            stream.write(
                f"bytes={record['bytes']} sha256={record['sha256']}\n\n"
            )
            stream.write(record["text"])
            if not record["text"].endswith("\n"):
                stream.write("\n")
            stream.write("\n")


def write_outputs(
    cloud_phone: dict, cloud_real_phone: dict, output_dir: Path
) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    diff = build_diff(cloud_phone, cloud_real_phone)
    outputs = {
        "cloud_phone_json": output_dir / "cloud-phone-config.json",
        "cloud_real_phone_json": output_dir / "cloud-real-phone-config.json",
        "diff_json": output_dir / "environment-config-diff.json",
        "diff_markdown": output_dir / "environment-config-diff.md",
        "cloud_phone_text": output_dir / "cloud-phone-config-all.txt",
        "cloud_real_phone_text": output_dir / "cloud-real-phone-config-all.txt",
    }
    outputs["cloud_phone_json"].write_text(
        json.dumps(cloud_phone, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    outputs["cloud_real_phone_json"].write_text(
        json.dumps(cloud_real_phone, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    outputs["diff_json"].write_text(
        json.dumps(diff, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    outputs["diff_markdown"].write_text(
        render_diff_markdown(diff), encoding="utf-8"
    )
    write_raw_bundle(cloud_phone, outputs["cloud_phone_text"])
    write_raw_bundle(cloud_real_phone, outputs["cloud_real_phone_text"])
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build complete Android environment configuration inventories"
    )
    parser.add_argument("--cloud-phone", required=True, type=Path)
    parser.add_argument("--cloud-real-phone", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    cloud_phone = build_inventory(args.cloud_phone, "cloud_phone")
    cloud_real_phone = build_inventory(args.cloud_real_phone, "cloud_real_phone")
    outputs = write_outputs(cloud_phone, cloud_real_phone, args.output_dir)
    for name, path in outputs.items():
        print(f"{name.upper()}={path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
