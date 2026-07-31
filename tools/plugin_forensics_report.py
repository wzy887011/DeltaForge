#!/usr/bin/env python3
"""Correlate DeltaForge cloud-device plugin forensics evidence."""

from __future__ import annotations

import argparse
from collections import defaultdict
from contextlib import contextmanager
import csv
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile
from typing import Iterator


SCHEMA = 1
MAX_TEXT_BYTES = 8 * 1024 * 1024

FACET_PATTERNS = {
    "root_framework": re.compile(
        r"magisk|kernelsu|\bksud?\b|apatch|\bapd\b|shamiko|root[_ -]?module|s9su|"
        r"bpfdomain|com\.android\.provider\.root",
        re.I,
    ),
    "privileged_control_plane": re.compile(
        r"platform[_ -]?control[_ -]?plane|bpfdomain|rkp_cert_processor|"
        r"traced_kprobes|mount_script_socket|"
        r"/data/misc/profiles/(?:exec|root)|provider\.root|dexguard|localSock",
        re.I,
    ),
    "selinux_policy_patch": re.compile(
        r"poweropt-service|asp_sepolicy|live[_ -]?sepolicy|selinux.*(?:patch|load)|"
        r"/sys/fs/selinux/load",
        re.I,
    ),
    "remote_admin": re.compile(
        r"console_agent|dropbear(?:_service)?|authorized_keys|\bcrond?\b", re.I
    ),
    "zygote_injection": re.compile(
        r"zygisk|riru|lsposed|xposed|zygote.*(?:inject|module)|(?:inject|module).*zygote",
        re.I,
    ),
    "property_spoofing": re.compile(
        r"resetprop|system\.prop|prop(?:erty)?[_ -]?(?:spoof|mask|override)|"
        r"(?:spoof|mask).*prop|ro\.(?:product|build|boot|hardware|soc)(?:\.|\b)",
        re.I,
    ),
    "namespace_overlay": re.compile(
        r"mountinfo|overlay|lxc|bind[_ -]?mount|magic[_ -]?mount|mirror|namespace|nsenter",
        re.I,
    ),
    "kernel_hook": re.compile(
        r"susfs|(?<!traced_)kprobe|ftrace|inline[_ -]?hook|/sys/module|"
        r"proc/modules|kernel[_ -]?module",
        re.I,
    ),
    "hardware_projection": re.compile(
        r"kgsl|adreno|mali|sm8150|rk3588|device.?tree|keymint|keymaster|"
        r"gatekeeper|strongbox|secureclock|soc0",
        re.I,
    ),
    "network_projection": re.compile(
        r"mihomo|clash|sing-box|v2ray|tun2socks|redsocks|iptables|nft|"
        r"\btun\b|proxy|private_dns",
        re.I,
    ),
    "target_security_module": re.compile(
        r"tersafe|tdatamaster|qimei|turing|hawk|crashsight", re.I
    ),
    "application_hook": re.compile(
        r"frida|(?:^|[^a-z])hook(?:[^a-z]|$)|libforge|"
        r"memfd:|\(deleted\)|rwxp",
        re.I,
    ),
}

GENERIC_PATH_TOKENS = {
    "data",
    "adb",
    "modules",
    "modules_update",
    "system",
    "vendor",
    "product",
    "system_ext",
    "bin",
    "lib",
    "lib64",
    "zygisk",
    "arm64-v8a.so",
    "arm64-v8a",
    "arm64",
    "armeabi-v7a",
    "base.apk",
    "base",
}


def classify_facets(text: str) -> list[str]:
    return sorted(name for name, pattern in FACET_PATTERNS.items() if pattern.search(text))


def source_family(relative: str) -> str:
    normalized = relative.replace("\\", "/")
    if normalized == "candidates.tsv":
        return "candidate_inventory"
    if normalized.startswith("modules/"):
        return "module_metadata"
    if normalized.startswith("processes/target/"):
        return "target_process"
    if normalized.startswith("processes/"):
        return "platform_process"
    if normalized.startswith("commands/"):
        parts = normalized.split("/")
        return parts[1] if len(parts) > 2 else "commands"
    if normalized == "manifest.tsv":
        return "manifest"
    return "other"


def candidate_source_family(source: str) -> str:
    mapping = {
        "root_modules": "root_module_inventory",
        "filesystem_scan": "filesystem_inventory",
        "process_target": "target_process",
        "process_zygote": "platform_process",
        "process_zygote64": "platform_process",
        "process_system_server": "platform_process",
    }
    return mapping.get(source, source or "candidate_inventory")


def read_tsv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        return [dict(row) for row in csv.DictReader(stream, delimiter="\t")]


def read_manifest(path: Path) -> dict[str, str]:
    rows = read_tsv(path)
    return {
        row.get("key", ""): row.get("value", "")
        for row in rows
        if row.get("key")
    }


def iter_text_lines(root: Path) -> Iterator[tuple[str, int, str]]:
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        if not path.is_file() or path.name == "file_hashes.tsv":
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > MAX_TEXT_BYTES:
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:4096]:
            continue
        text = raw.decode("utf-8", errors="replace")
        relative = path.relative_to(root).as_posix()
        for number, line in enumerate(text.splitlines(), 1):
            yield relative, number, line


def candidate_tokens(path: str) -> list[str]:
    pure = PurePosixPath(path)
    tokens = []
    basename = pure.name.lower()
    stem = Path(pure.name).stem.lower()
    for token in (basename, stem):
        if len(token) >= 4 and token not in GENERIC_PATH_TOKENS and token not in tokens:
            tokens.append(token)

    parts = [part.lower() for part in pure.parts]
    try:
        module_index = parts.index("modules")
    except ValueError:
        module_index = -1
    if module_index >= 0 and module_index + 1 < len(parts):
        module_id = parts[module_index + 1]
        if len(module_id) >= 4 and module_id not in GENERIC_PATH_TOKENS:
            tokens.append(module_id)

    if basename in GENERIC_PATH_TOKENS and "data" in parts and "app" in parts:
        for part in parts:
            match = re.match(r"((?:[a-z][a-z0-9_]*\.)+[a-z][a-z0-9_]*)-", part)
            if match and match.group(1) not in tokens:
                tokens.append(match.group(1))
    return tokens


def matches_candidate(line: str, path: str, tokens: list[str]) -> bool:
    lower = line.lower()
    if path.lower() in lower:
        return True
    basename = PurePosixPath(path).name.lower()
    if len(basename) >= 4 and basename in lower:
        return True
    for token in tokens:
        if token not in lower:
            continue
        if token.startswith("com.") and lower.count(",") >= 2:
            continue
        return True
    return False


def environment_contradictions(lines: list[tuple[str, int, str]]) -> list[dict]:
    hits: dict[str, list[dict]] = defaultdict(list)

    def add(name: str, source: str, number: int, line: str) -> None:
        if len(hits[name]) < 8:
            hits[name].append({"source": source, "line": number, "text": line[:500]})

    for source, number, line in lines:
        normalized = source.replace("\\", "/")
        lower = line.lower()

        property_source = normalized in {
            "commands/identity_projection/getprop.stdout.txt",
            "commands/init_services/init_properties.stdout.txt",
            "commands/root_framework/resetprop_view.stdout.txt",
        }
        hardware_source = normalized in {
            "commands/boot_kernel/device_tree.stdout.txt",
            "commands/identity_projection/hardware_nodes.stdout.txt",
            "commands/identity_projection/cpuinfo.stdout.txt",
            "commands/identity_projection/surfaceflinger.stdout.txt",
        }
        if property_source:
            if re.search(r"\[(?:ro\.)?(?:boot\.hardware|hardware|soc\.(?:model|manufacturer)|board\.platform)\].*\[(?:qcom|qualcomm|sm8\d+)", lower):
                add("qualcomm", source, number, line)
            if re.search(r"\[(?:ro\.)?(?:boot\.hardware|hardware|soc\.(?:model|manufacturer)|board\.platform|hardware\.egl)\].*\[(?:rockchip|rk3588|mali)", lower):
                add("rockchip", source, number, line)
            if "verifiedbootstate" in lower and "[green]" in lower:
                add("verified_green", source, number, line)
            if "ro.boot.selinux" in lower and "[enforcing]" in lower:
                add("selinux_enforcing", source, number, line)

        if hardware_source:
            if re.search(r"qcom|qualcomm|sm8\d+|adreno", lower):
                add("qualcomm", source, number, line)
            if re.search(r"rockchip|rk3588|mali|rknpu", lower):
                add("rockchip", source, number, line)

        if normalized.endswith("mountinfo.txt") and re.search(
            r"overlay|lxc|antdock|container|virtio|\b9p\b|/dev/mapper/vg-vm_", lower
        ):
            add("container", source, number, line)

        root_source = normalized in {
            "commands/root_framework/proc_walk.stdout.txt",
            "commands/root_framework/framework_versions.stdout.txt",
            "commands/root_framework/adb_inventory.stdout.txt",
            "commands/root_framework/platform_control_plane.stdout.txt",
            "commands/root_framework/platform_control_processes.stdout.txt",
            "commands/root_framework/root_provider.stdout.txt",
            "candidates.tsv",
        }
        if root_source and re.search(
            r"(?:^|/)su(?:\s|$)|resetprop|bpfdomain|provider\.root|"
            r"rkp_cert_processor|traced_kprobes|magisk|kernelsu|apatch|/data/adb/modules",
            lower,
        ):
            add("root", source, number, line)

        if normalized == "commands/boot_kernel/selinux.stdout.txt":
            if lower.strip() == "enforcing":
                add("selinux_enforcing", source, number, line)
            elif lower.strip() in {"disabled", "permissive"}:
                add("selinux_disabled", source, number, line)
        if normalized == "commands/boot_kernel/cmdline.stdout.txt":
            if "androidboot.selinux=disabled" in lower:
                add("selinux_disabled", source, number, line)
            elif "androidboot.selinux=enforcing" in lower:
                add("selinux_enforcing", source, number, line)

    contradictions = []
    definitions = (
        (
            "hardware_vendor_mismatch",
            "Qualcomm/Adreno and Rockchip/Mali evidence coexist",
            ("qualcomm", "rockchip"),
        ),
        (
            "container_topology_visible",
            "Virtualized or container storage topology is visible in mount evidence",
            ("container",),
        ),
        (
            "verified_boot_root_mismatch",
            "Verified-boot green claims coexist with visible root framework evidence",
            ("verified_green", "root"),
        ),
        (
            "selinux_state_mismatch",
            "Runtime enforcing evidence coexists with a disabled SELinux boot claim",
            ("selinux_enforcing", "selinux_disabled"),
        ),
    )
    for key, description, required in definitions:
        if all(hits[name] for name in required):
            evidence = []
            for name in required:
                evidence.extend(hits[name][:3])
            contradictions.append(
                {"id": key, "description": description, "evidence": evidence}
            )
    return contradictions


def build_report(root: Path) -> dict:
    root = Path(root).resolve()
    manifest = read_manifest(root / "manifest.tsv")
    rows = read_tsv(root / "candidates.tsv")
    all_lines = list(iter_text_lines(root))

    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        path = row.get("path", "").strip()
        if path:
            grouped[path].append(row)

    candidates = []
    for path in sorted(grouped):
        candidate_rows = grouped[path]
        indicators = sorted(
            {
                item.strip()
                for row in candidate_rows
                for item in row.get("indicators", "").split(",")
                if item.strip()
            }
        )
        families = {
            candidate_source_family(row.get("source", "")) for row in candidate_rows
        }
        evidence = []
        tokens = candidate_tokens(path)
        for source, number, line in all_lines:
            if source == "candidates.tsv":
                continue
            if matches_candidate(line, path, tokens):
                family = source_family(source)
                families.add(family)
                if len(evidence) < 80:
                    evidence.append(
                        {
                            "source": source,
                            "line": number,
                            "family": family,
                            "text": line[:500],
                        }
                    )

        first = candidate_rows[0]
        basename = PurePosixPath(path).name.lower()
        direct_evidence = []
        for item in evidence:
            lower = item["text"].lower()
            if path.lower() in lower or (
                basename not in GENERIC_PATH_TOKENS and basename in lower
            ):
                direct_evidence.append(item["text"])
        combined = " ".join([path, " ".join(indicators)] + direct_evidence)
        facets = classify_facets(combined)
        score = min(75, 15 * len(families))
        if first.get("sha256"):
            score += 5
        if first.get("build_id"):
            score += 5
        if "target_process" in families:
            score += 10
        if "module_metadata" in families:
            score += 5
        if not facets:
            score = min(score, 20)
        score = min(score, 100)

        candidates.append(
            {
                "path": path,
                "type": first.get("type", ""),
                "size": first.get("size", ""),
                "uid": first.get("uid", ""),
                "gid": first.get("gid", ""),
                "mode": first.get("mode", ""),
                "sha256": first.get("sha256", ""),
                "build_id": first.get("build_id", ""),
                "indicators": indicators,
                "facets": facets,
                "score": score,
                "confidence": "high" if score >= 70 else "medium" if score >= 40 else "low",
                "source_families": sorted(families),
                "evidence": sorted(
                    evidence,
                    key=lambda item: (item["source"], item["line"], item["text"]),
                ),
            }
        )

    candidates.sort(key=lambda item: (-item["score"], item["path"]))
    errors = read_tsv(root / "errors.tsv")
    contradictions = environment_contradictions(all_lines)
    facets = defaultdict(int)
    for candidate in candidates:
        for facet in candidate["facets"]:
            facets[facet] += 1

    return {
        "schema": SCHEMA,
        "manifest": dict(sorted(manifest.items())),
        "summary": {
            "candidate_count": len(candidates),
            "high_confidence_count": sum(
                candidate["confidence"] == "high" for candidate in candidates
            ),
            "error_count": len(errors),
            "evidence_line_count": len(all_lines),
            "facet_counts": dict(sorted(facets.items())),
        },
        "contradictions": contradictions,
        "candidates": candidates,
        "collection_errors": errors,
    }


def markdown_escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# Cloud Device Plugin Forensics",
        "",
        f"- Package: `{markdown_escape(report['manifest'].get('package', 'unknown'))}`",
        f"- Candidates: {summary['candidate_count']}",
        f"- High confidence: {summary['high_confidence_count']}",
        f"- Collection errors: {summary['error_count']}",
        "",
        "## Environment Contradictions",
        "",
    ]
    if report["contradictions"]:
        for item in report["contradictions"]:
            lines.append(f"- **{item['id']}**: {item['description']}")
    else:
        lines.append("- None observed in the supplied evidence window.")

    lines.extend(
        [
            "",
            "## Candidate Components",
            "",
            "| Score | Confidence | Facets | Path | SHA-256 |",
            "|---:|---|---|---|---|",
        ]
    )
    for candidate in report["candidates"]:
        lines.append(
            "| {score} | {confidence} | {facets} | `{path}` | `{digest}` |".format(
                score=candidate["score"],
                confidence=candidate["confidence"],
                facets=markdown_escape(", ".join(candidate["facets"])),
                path=markdown_escape(candidate["path"]),
                digest=markdown_escape(candidate["sha256"]),
            )
        )
        lines.append("")
        lines.append(f"Evidence for `{markdown_escape(candidate['path'])}`:")
        for evidence in candidate["evidence"][:12]:
            lines.append(
                f"- `{evidence['source']}:{evidence['line']}` "
                f"[{evidence['family']}] {markdown_escape(evidence['text'])}"
            )

    if report["collection_errors"]:
        lines.extend(["", "## Collection Errors", ""])
        for error in report["collection_errors"]:
            lines.append(
                "- `{layer}/{name}` rc={rc}: {stderr}".format(
                    layer=markdown_escape(error.get("layer", "")),
                    name=markdown_escape(error.get("name", "")),
                    rc=markdown_escape(error.get("rc", "")),
                    stderr=markdown_escape(error.get("stderr", "")),
                )
            )
    lines.append("")
    return "\n".join(lines)


def write_reports(report: dict, output_dir: Path) -> tuple[Path, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "plugin-forensics-report.json"
    markdown_path = output_dir / "plugin-forensics-report.md"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def validate_tar_members(members: list[tarfile.TarInfo]) -> None:
    for member in members:
        name = PurePosixPath(member.name)
        if name.is_absolute() or ".." in name.parts:
            raise ValueError(f"unsafe archive member: {member.name}")
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            raise ValueError(f"unsupported archive member: {member.name}")
        if not (member.isdir() or member.isfile()):
            raise ValueError(f"unsupported archive member type: {member.name}")


@contextmanager
def evidence_root(source: Path) -> Iterator[Path]:
    source = Path(source)
    if source.is_dir():
        yield source.resolve()
        return
    if not source.is_file():
        raise FileNotFoundError(source)

    with tempfile.TemporaryDirectory(prefix="deltaforge-plugin-audit-") as tmp:
        destination = Path(tmp)
        with tarfile.open(source, "r:*") as archive:
            members = archive.getmembers()
            validate_tar_members(members)
            archive.extractall(destination, members=members)

        if (destination / "manifest.tsv").is_file():
            root = destination
        else:
            candidates = sorted(
                path.parent for path in destination.rglob("manifest.tsv") if path.is_file()
            )
            if len(candidates) != 1:
                raise ValueError("archive must contain exactly one evidence root")
            root = candidates[0]
        yield root.resolve()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a source-backed report from a plugin forensics archive"
    )
    parser.add_argument("evidence", type=Path, help="evidence directory or .tar.gz")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("plugin-forensics-report"),
        help="report output directory",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with evidence_root(args.evidence) as root:
        report = build_report(root)
    json_path, markdown_path = write_reports(report, args.output_dir)
    print(f"JSON={json_path.resolve()}")
    print(f"MARKDOWN={markdown_path.resolve()}")
    print(f"CANDIDATES={report['summary']['candidate_count']}")
    print(f"HIGH_CONFIDENCE={report['summary']['high_confidence_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
