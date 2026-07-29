# Cloud Device Plugin Forensics Design

## Goal

Build a read-only, whole-device evidence collector that identifies the components responsible for presenting the current cloud device as a physical Android phone. The resulting archive must support offline attribution and reverse engineering without changing the observed runtime state.

The default target package is `com.tencent.tmgp.dfm`, with a command-line override for other packages.

## Architecture

The feature has two independent components:

1. `cloud-agent/plugin_forensics_collect.sh` runs as root on Android and creates a timestamped evidence directory plus a compressed archive.
2. `tools/plugin_forensics_report.py` runs on the workstation against an extracted directory or archive and produces deterministic JSON and Markdown reports.

The collector records raw facts. The reporter classifies and scores evidence. Neither component automatically installs, disables, patches, or copies candidate plugins into DeltaForge.

## Evidence Layers

The collector covers the complete path from boot to application observation:

1. Boot and kernel: command line, kernel version/config, modules, Device Tree, boot properties, verified boot, SELinux state and policy hash.
2. Root frameworks: Magisk, KernelSU, APatch, module manifests, service scripts, Zygisk/Riru payloads, SUSFS indicators, and root management processes.
3. Init and services: init properties, service state, relevant RC definitions, process tree, Binder services, HAL inventory, and vendor daemons.
4. Identity projection: product/build/boot/vendor properties, serial and Android identifiers where readable, `/proc` and sysfs identity nodes, GPU, CPU, thermal, sensor, display, codec, and hardware-security facts.
5. Namespace projection: root and target-process mount information, mount namespace identifiers, overlay/bind mounts, hidden paths, and root-path visibility.
6. Runtime injection: target, zygote, and system_server maps; deleted mappings; memfd mappings; executable anonymous regions; loaded libraries; file descriptors; tracer state; and injected framework names.
7. Packages and artifacts: package inventory, suspicious manager/module packages, candidate scripts/APKs/SOs/binaries, metadata, ownership, mode, SHA-256, and ELF Build ID when tooling is available.
8. Network projection: interfaces, routes, rules, TUN devices, DNS properties, proxy settings, listening sockets, iptables/ip6tables/nft state, and proxy processes.

## Read-Only Boundary

The collector may create its own output directory and archive. It does not invoke `setprop`, `resetprop`, `mount`, `umount`, `kill`, `stop`, `start`, package-management mutations, firewall mutations, or writes to Android system/application state.

Commands that are missing or denied are recorded in `errors.tsv`; collection continues so one unavailable subsystem does not discard other evidence.

Sensitive values such as account tokens, application databases, keystores, clipboard data, and unrelated application private files are outside the collection scope.

## Output Contract

The device-side archive contains:

- `manifest.tsv`: collection time, package, PID, device identifiers, tool availability, and per-file hashes.
- `commands/`: raw command outputs grouped by evidence layer.
- `processes/`: target/zygote/system_server status, maps, mountinfo, namespaces, and descriptors.
- `modules/`: module manifests, file inventories, configuration text, and hashes.
- `candidates.tsv`: normalized candidate path, type, size, ownership, mode, hash, Build ID, and matched indicators.
- `errors.tsv`: failed evidence commands with return codes.

Default archive location:

```text
/sdcard/Download/deltaforge-plugin-audit-YYYYMMDD-HHMMSS.tar.gz
```

The reporter emits:

- `plugin-forensics-report.json`
- `plugin-forensics-report.md`

## Classification Model

Evidence is assigned to one or more facets:

- `root_framework`
- `zygote_injection`
- `property_spoofing`
- `namespace_overlay`
- `kernel_hook`
- `hardware_projection`
- `network_projection`
- `application_hook`

Scoring combines independent signals. A module manifest alone is weak; a manifest plus running process, target mapping, mount effect, and matching file hash is strong. Reports preserve every source line used by a score.

## Integration Decision

Candidate components are integrated only after static analysis establishes their behavior and dependencies. Reusable mechanisms are reimplemented behind DeltaForge's profile, transaction, rollback, and evidence gates. Version-bound binaries, broad data deletion, uncontrolled property randomization, and opaque network control are retained as analysis samples rather than runtime dependencies.

## Verification

Repository tests verify:

1. The collector contains required evidence sections and prohibited state-changing commands are absent.
2. Reporter output is deterministic for fixed fixtures.
3. Candidate scoring requires corroborating evidence and includes source references.
4. Archive traversal paths are rejected.
5. Missing optional device commands produce recorded errors instead of terminating collection.

Device acceptance requires one successful archive, a valid SHA-256, a reporter run without parse errors, and at least one source-backed conclusion for every detected candidate.
