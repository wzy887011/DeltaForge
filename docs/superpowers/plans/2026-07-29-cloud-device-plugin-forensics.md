# Cloud Device Plugin Forensics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a read-only Android root collector and deterministic workstation reporter that attribute the mechanisms used by the current cloud device to project a physical-device environment.

**Architecture:** A standalone Android shell collector writes raw evidence and a normalized candidate table into a timestamped archive. A standard-library Python reporter safely reads the archive, correlates independent evidence, and emits JSON and Markdown findings with source references.

**Tech Stack:** Android `/system/bin/sh`, Toybox, optional `readelf`, Python 3 standard library, `unittest`.

---

### Task 1: Contract Tests

**Files:**
- Create: `tests/test_plugin_forensics.py`

- [ ] **Step 1: Write failing collector contract tests**

Test that the collector declares all eight evidence layers, defaults to `com.tencent.tmgp.dfm`, records command failures, produces `candidates.tsv`, and excludes state-changing Android commands.

- [ ] **Step 2: Write failing reporter tests**

Create a temporary fixture containing module metadata, process maps, mount evidence, and candidate rows. Assert deterministic classification, corroboration scoring, source references, archive traversal rejection, and Markdown/JSON output.

- [ ] **Step 3: Run tests to verify failure**

```powershell
python -m unittest discover -s tests -p test_plugin_forensics.py -v
```

Expected: imports or paths fail because the collector and reporter do not exist.

### Task 2: Android Collector

**Files:**
- Create: `cloud-agent/plugin_forensics_collect.sh`

- [ ] **Step 1: Implement arguments and output contract**

Support `--package PACKAGE`, `--out DIRECTORY`, and `--help`. Require root, create a unique evidence directory, and initialize `manifest.tsv`, `candidates.tsv`, and `errors.tsv`.

- [ ] **Step 2: Implement resilient command capture**

Use a `capture NAME COMMAND...` helper that writes stdout/stderr separately and records nonzero return codes without aborting the scan.

- [ ] **Step 3: Collect whole-device evidence**

Collect boot/kernel, root frameworks, init/services, identity projection, namespace projection, runtime mappings, packages/artifacts, and network projection. Limit filesystem traversal to named platform/module directories and keyword-filtered candidates.

- [ ] **Step 4: Inventory candidate artifacts**

For each normalized candidate path, record type, size, uid/gid, mode, SHA-256, optional ELF Build ID, and matched indicator. Preserve module manifests and configuration text as evidence without copying opaque private application data.

- [ ] **Step 5: Package evidence**

Hash collected files, write the archive with `tar -czf`, print `ARCHIVE=...` and `SHA256=...`, and leave raw evidence available for inspection.

### Task 3: Offline Reporter

**Files:**
- Create: `tools/plugin_forensics_report.py`

- [ ] **Step 1: Implement safe input loading**

Accept an evidence directory or `.tar.gz`, reject absolute paths, parent traversal, links, devices, and extraction outside a temporary directory.

- [ ] **Step 2: Implement normalized evidence parsing**

Parse TSV rows defensively, retain source file and line references, and tolerate missing optional files.

- [ ] **Step 3: Implement facet classification and scoring**

Classify `root_framework`, `zygote_injection`, `property_spoofing`, `namespace_overlay`, `kernel_hook`, `hardware_projection`, `network_projection`, and `application_hook`. Score corroborating source families rather than repeated keyword occurrences.

- [ ] **Step 4: Implement reports**

Write stable, sorted `plugin-forensics-report.json` and `plugin-forensics-report.md` containing summary, candidates, evidence references, environment contradictions, and collection errors.

### Task 4: Verification and Delivery

**Files:**
- Modify: `tests/test_plugin_forensics.py`
- Create: `docs/PLUGIN_FORENSICS.md`

- [ ] **Step 1: Run focused tests**

```powershell
python -m unittest discover -s tests -p test_plugin_forensics.py -v
```

Expected: all plugin-forensics tests pass.

- [ ] **Step 2: Run the complete suite**

```powershell
python -m unittest discover -s tests -v
python -m py_compile tools/plugin_forensics_report.py
git diff --check
```

Expected: all tests, compilation, and whitespace checks pass.

- [ ] **Step 3: Document TIER UX execution**

Document repository pull, root execution, archive hash verification, upload location, and workstation report generation with exact commands.

- [ ] **Step 4: Commit and push**

```powershell
git add cloud-agent/plugin_forensics_collect.sh tools/plugin_forensics_report.py tests/test_plugin_forensics.py docs/PLUGIN_FORENSICS.md docs/superpowers/plans/2026-07-29-cloud-device-plugin-forensics.md
git commit -m "feat: add whole-device plugin forensics scan"
git push origin codex/v8.7-hardening
```
