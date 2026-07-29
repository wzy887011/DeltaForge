# Environment Access Audit

`cloud-agent/environment_audit.sh` is an external, read-only observer for an
already running Android application process. It does not inject a library and
does not change syscall return values.

## Evidence Sources

- `strace.*`: file, network, ioctl, kernel identity, and `prctl` syscalls from
  all threads present when collection starts;
- `static_candidates.tsv`: property names, paths, and hardware/security tokens
  found in application native libraries;
- `native_inventory.tsv`: hashes, sizes, Build IDs, and visible version strings
  for critical anti-cheat and telemetry libraries;
- `maps.before.txt` and `maps.after.txt`: process mappings around the window;
- `mountinfo.txt`, property and HAL snapshots, and `logcat.txt`;
- `report.json`: deterministic classification and de-duplication.

## Device Run

Install Termux `strace`, Python, and binutils when they are not already present:

```sh
pkg install strace python binutils
```

Start the unmodified application, wait until the target screen, then collect a
60-second window:

```sh
su -c '/data/local/tmp/environment_audit.sh 60'
```

The collector rejects a process containing `libforgehook.so` by default because
its filtered results would contaminate the baseline. A deliberately labeled
comparison run can be collected with `ALLOW_HOOKED=1`; do not mix it with the
unmodified baseline.

The command prints the evidence directory. Rebuild a report without collecting
again:

```sh
python /data/local/tmp/environment_audit_report.py AUDIT_DIR \
  --json AUDIT_DIR/report.json
```

## Interpretation

Dynamic evidence proves that a syscall occurred during the captured window.
Static candidates prove only that a relevant string exists in a library. They
do not prove that the string is executed or used as a decision input.

`strace` changes scheduling and exposes a ptrace relationship. Code with
anti-debug behavior may take a different path or terminate, so a clean trace is
not proof that no other checks exist. Property-area reads, Java framework calls,
Binder payloads, direct ARM64 syscalls outside the traced set, encrypted strings,
and service-side decisions require separate evidence sources.

Report schema 2 tags evidence into six review surfaces: `anti_cheat`,
`telemetry`, `identity`, `root_instrumentation`, `virtualization`, and
`hardware_security`. These tags identify where evidence belongs; they do not
assert that a particular string or access decided an outcome.

Use the report to fix crashes, missing platform capabilities, and inconsistent
system behavior. Keep raw evidence and image identifiers with every conclusion.
