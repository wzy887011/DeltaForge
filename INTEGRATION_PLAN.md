# DeltaForge v8.7 System, Kernel, Hardware, and Server Integration

## Current Baseline

The stable runtime baseline is commit `109519f`:

- the game reaches the login page without the green graphics-debug border;
- 58 TerSafe code entries and 40 BSS entries survive when applied in staged phases;
- the full `forge -l` path preserves the original PID for at least 120 seconds;
- injector scratch memory is unmapped after a non-NULL Bionic `dlopen` handle;
- inject mode skips Qimei chainloading and preserves the rollback copy.

This proves process-level compatibility. It does not prove that the host image,
kernel, hardware security services, or network origin match a physical SM-G9730.

## Phase A: System Image Integration

Owner: Android base image and vendor partition.

Required changes:

1. Boot with SELinux enforcing and a tested policy.
2. Remove Rockchip/AntDock properties, init services, HALs, binaries, and process names.
3. Remove public Root binaries and development daemons from the application-visible image.
4. Replace LXC/overlay mounts with an application namespace that has no host paths.
5. Align physical display mode, density, refresh modes, codecs, sensors, audio, camera,
   power profiles, thermal zones, and feature XML with one device profile.
6. Keep `system_identity_overlay.sh` only as a rollback-capable diagnostic layer.

Gate:

```sh
su -c '/data/local/tmp/system_integration_gate.sh'
```

Acceptance: zero `FAIL`; warnings must have a named owner and expiry.

## Phase B: Kernel and Hardware Integration

Owner: boot image, kernel, Device Tree, vendor modules, TEE firmware, and HAL services.

Required changes:

1. Use a kernel and Device Tree built for the selected hardware profile.
2. Provide real KGSL and `/dev/kgsl-3d0` behavior; static sysfs files are not sufficient.
3. Provide coherent `soc0`, cpufreq, devfreq, thermal, ION/dma-buf, sensor, and input trees.
4. Boot a real SELinux policy and preserve AVC behavior.
5. Integrate KeyMint/Keymaster, Gatekeeper, SecureClock, SharedSecret, and TEE-backed keys.
6. Validate kernel config provenance and remove vendor-host container dependencies.
7. Run ioctl and timing conformance tests against the selected vendor userspace.

Gate:

```sh
su -c '/data/local/tmp/kernel_hardware_gate.sh'
```

Acceptance: zero `BLOCKED_IMAGE`. A user-space Hook is not a substitute for a
missing driver, TEE, hardware-backed key, or policy behavior.

## Phase C: Service-Side Integration

Owner: self-hosted observation service, reverse proxy, DNS, and egress network.

Components:

- `server-probe/server.py`: records the actual peer and request metadata;
- `cloud-agent/server_probe_client.sh`: preserves response and curl timing evidence;
- internal IP intelligence pipeline: supplies ASN, prefix owner, and network class;
- TLS reverse proxy: terminates a controlled certificate and forwards trusted headers.

Start the local probe:

```sh
python server-probe/server.py --bind 0.0.0.0 --port 8787 \
  --log diagnostics/server-probe.jsonl
```

Query from the cloud device:

```sh
su -c '/data/local/tmp/server_probe_client.sh http://PROBE_HOST:8787/v1/observe'
```

Acceptance evidence:

- observed peer IP and DNS path are stable and expected;
- ASN/network classification comes from an explicit internal data source;
- proxy headers are trusted only behind a controlled reverse proxy;
- latency, route changes, connection failures, and TLS metadata are retained;
- unknown values remain `unknown` and do not pass the gate.

## Phase D: End-to-End Release Gate

Run in order:

1. Deploy with `cloud-agent/deploy.sh --no-hijack`.
2. Apply network configuration with `mihomo_control.sh apply`.
3. Launch with `forge -l` and retain PID/crash evidence.
4. Run `verify_identity.sh`, `system_integration_gate.sh`, and
   `kernel_hardware_gate.sh`.
5. Query the self-hosted server probe.
6. Archive all reports with `collect_device_state.sh`.

Release states:

- `PROCESS_READY`: process-level launch and compatibility checks pass.
- `SYSTEM_READY`: system gate has zero failures.
- `HARDWARE_READY`: kernel/hardware gate has zero blocked items.
- `SERVICE_OBSERVED`: service probe has complete, classified evidence.
- `INTEGRATED`: all four states are present for the same immutable image build.

The current cloud image is `PROCESS_READY`; the other states require evidence
from the image, kernel/hardware owners, and service-side environment.
