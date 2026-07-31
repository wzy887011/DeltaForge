# Cloud Device Plugin Forensics

This workflow attributes the components that project the cloud device as a physical Android phone. Collection is read-only except for files created under the selected output directory.

## Run In TIER UX

Keep the target application running at the screen where its environment checks have completed. From the existing DeltaForge checkout:

```sh
cd ~/DeltaForge
git pull origin codex/v8.7-hardening
chmod 700 cloud-agent/plugin_forensics_collect.sh
su -c "sh $(pwd)/cloud-agent/plugin_forensics_collect.sh --package com.tencent.tmgp.dfm"
```

The final lines contain values similar to:

```text
EVIDENCE_DIR=/sdcard/Download/deltaforge-plugin-audit-20260729-180000
ARCHIVE=/sdcard/Download/deltaforge-plugin-audit-20260729-180000.tar.gz
SHA256=ARCHIVE_SHA256
```

The scan can take several minutes because it hashes candidate module files and collects service, HAL, display, sensor, mount, process-map, and network evidence.

## Upload Through The Repository

Replace `ARCHIVE` with the path printed by the collector:

```sh
cd ~/DeltaForge
mkdir -p diagnostics/plugin-audits
cp ARCHIVE diagnostics/plugin-audits/
git add -f diagnostics/plugin-audits/$(basename ARCHIVE)
git commit -m "diagnostics: add cloud device plugin audit"
git push cloud codex/v8.7-hardening
```

Use `origin` only on a device whose SSH identity has write access to
`wzy887011/DeltaForge`. The cloud-phone identity writes its evidence commit to
`wzy887011-cloud/DeltaForge` through the `cloud` remote.

Record the printed SHA-256 in the commit message or accompanying message. The archive excludes application databases, account tokens, keystores, and unrelated private application files.

## Build The Report

After pulling the archive on the workstation:

```powershell
cd "C:\Users\15144\Documents\New project\DeltaForge-v8.7-hardening.work"
git pull origin codex/v8.7-hardening
$archive = Get-ChildItem diagnostics\plugin-audits\deltaforge-plugin-audit-*.tar.gz |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
python tools\plugin_forensics_report.py $archive.FullName --output-dir diagnostics\plugin-report
```

Review these outputs:

- `diagnostics/plugin-report/plugin-forensics-report.md`
- `diagnostics/plugin-report/plugin-forensics-report.json`

High-confidence candidates have evidence from multiple source families, such as
a root-module inventory, a platform root control plane, a privileged provider,
a target-process mapping, and a namespace or property effect. The collector also
captures renamed root daemons, execution sockets, live SELinux policy loaders,
and init services even when `/data/adb/modules` is absent. The raw evidence
reference on every finding provides the exact file and line to inspect before
reverse engineering the candidate artifact.

## Optional Package Override

For a different target application:

```sh
su -c "sh $(pwd)/cloud-agent/plugin_forensics_collect.sh --package PACKAGE_NAME"
```

For an alternate output location:

```sh
su -c "sh $(pwd)/cloud-agent/plugin_forensics_collect.sh --package PACKAGE_NAME --out /data/local/tmp"
```
