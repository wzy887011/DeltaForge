import json
import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNNER = os.path.join(ROOT, "runner")
sys.path.insert(0, RUNNER)

import forge_controller as controller
from bot_runner import BotRunner


class ConfigProtocolTests(unittest.TestCase):
    def test_active_version_declarations_are_87(self):
        expected = {
            "README.md": "# DeltaForge v8.7",
            "cloud-agent/deploy.sh": "Compiling v8.7",
            "cloud-agent/magisk/module.prop": "version=v8.7",
            "cloud-agent/native/forge.c": '#define FORGE_VERSION       "8.7"',
            "cloud-agent/native/forge_monitor.c": "forge_monitor v8.7 start",
            "runner/forge_controller.py": "forge_controller.py v8.7",
            "runner/setup_network.sh": "DeltaForge v8.7",
        }
        for relative, marker in expected.items():
            with self.subTest(path=relative):
                with open(os.path.join(ROOT, relative), encoding="utf-8") as stream:
                    self.assertIn(marker, stream.read())

    def test_opcode_auth_covers_wire_body(self):
        controller._session_key = bytes(range(16))
        original = controller.secrets.token_bytes
        controller.secrets.token_bytes = lambda n: b"12345678"
        try:
            body = b"\x03\n"
            header = controller.build_auth_header(body)
        finally:
            controller.secrets.token_bytes = original

        _, nonce_hex, mac_hex = header.strip().split(":")
        expected = controller.siphash24(
            controller._session_key, bytes.fromhex(nonce_hex) + body
        )
        self.assertEqual(int(mac_hex, 16), expected)

    def test_nested_runner_config_is_applied(self):
        bot = BotRunner()
        self.assertEqual(bot.cfg["game_package"], "com.tencent.tmgp.dfm")
        self.assertEqual(
            (bot.cfg["screen_width"], bot.cfg["screen_height"]),
            (1080, 2280),
        )

    def test_patch_table_is_guarded(self):
        path = os.path.join(RUNNER, "config", "tersafe_patches.json")
        with open(path, encoding="utf-8") as stream:
            table = json.load(stream)
        self.assertEqual(len(table["tersafe_patches"]), 58)
        self.assertEqual(len(table["tersafe_bss"]), 40)
        self.assertTrue(all("expected" in item for item in table["tersafe_patches"]))
        offsets = {item["offset"].lower() for item in table["tersafe_patches"]}
        self.assertTrue({"0x5137c0", "0x516640", "0x526ed0"}.isdisjoint(offsets))
        self.assertFalse(
            any("kKillChain" in item.get("comment", "") for item in table["tersafe_patches"])
        )
        self.assertEqual(
            table["build_id"],
            "d70d7926094ae39a46745c12ddcc1877641f82e8",
        )
        self.assertEqual(table["ue4_patches"], [])
        self.assertEqual(
            table["ue4_build_id"],
            "8187ddb9edbc9d5201201ffd7b008df3bfe533db",
        )

    def test_native_patch_paths_share_validation_gate(self):
        path = os.path.join(ROOT, "cloud-agent", "native", "forge.c")
        with open(path, encoding="utf-8") as stream:
            source = stream.read()
        self.assertIn("#define EXPECTED_TERSAFE_PATCH_COUNT 58", source)
        self.assertIn("#define EXPECTED_TERSAFE_BSS_COUNT   40", source)
        self.assertIn("#define PATCH_PHASE_SETTLE_SECONDS   30", source)
        self.assertIn("find_validated_patch", source)
        self.assertIn("preflight_code_table", source)
        self.assertIn("table rejected: accepted=%zu rejected=%zu total=%zu", source)
        self.assertIn("pkill -x forge_monitor", source)
        self.assertIn("preflight_bss_table", source)
        self.assertIn("PATCH_SCOPE_CODE_ONLY", source)
        self.assertIn("PATCH_SCOPE_BSS_ONLY", source)
        self.assertIn("diagnostic scope: code table skipped", source)
        self.assertIn("diagnostic scope: BSS table skipped", source)
        self.assertIn("staged patch: game stable, entering BSS phase", source)
        self.assertIn("if (patch_code && patch_bss)", source)
        self.assertIn("--code-only/--bss-only 只允许与 -m 一起使用", source)
        self.assertIn("validated patch transaction failed; hook injection cancelled", source)
        self.assertIn("#define WRITE_FAIL_ABORT_THRESHOLD 0", source)
        self.assertIn('verify_module_version(pid, "libUE4.so"', source)
        self.assertNotIn("? g_dyn_table.tersafe_patches : kTersafePatches", source)
        self.assertNotIn("ts2+kChk[ci].off", source)
        injector_path = os.path.join(ROOT, "cloud-agent", "native", "injector.c")
        with open(injector_path, encoding="utf-8") as stream:
            injector_source = stream.read()
        self.assertNotIn("kKillPatches", injector_source)
        self.assertNotIn("patch_kill_chain_while_paused", injector_source)
        self.assertNotIn('strstr(line, "libtdmqimei")', injector_source)
        self.assertIn("__NR_munmap", injector_source)
        self.assertIn("ptrace_setregs(pid, &saved);", injector_source)
        self.assertIn('handle ? "non-null handle" : "NULL"', injector_source)
        self.assertIn("if (done && handle)", injector_source)
        self.assertIn("if (!done || !handle)", injector_source)
        self.assertNotIn("(int64_t)handle < 0", injector_source)
        self.assertNotIn("(int64_t)handle > 0", injector_source)

        hook_path = os.path.join(ROOT, "cloud-agent", "native", "libforgehook.c")
        with open(hook_path, encoding="utf-8") as stream:
            hook_source = stream.read()
        disabled_start = hook_source.index(
            "/* v8.7: forge is the only owner of target-module writes."
        )
        disabled_start = hook_source.index("#if 0", disabled_start)
        disabled_end = hook_source.index("#endif", disabled_start)
        active_hook_source = (
            hook_source[:disabled_start] + hook_source[disabled_end + len("#endif") :]
        )
        for legacy_writer in (
            "patch_insn",
            "kKillChain",
            "resolve_patch_offset",
            "_adjust_code_thread",
        ):
            self.assertNotIn(legacy_writer, active_hook_source)
        self.assertIn("patch ownership=forge", active_hook_source)
        self.assertIn("_activate_hooks_thread", active_hook_source)
        self.assertIn("[chainload] inject mode; chainload skipped", active_hook_source)
        self.assertIn("[chainload] disk backup preserved", active_hook_source)
        self.assertNotIn(
            "syscall(SYS_unlinkat, AT_FDCWD, g_real_qimei_path", active_hook_source
        )
        self.assertNotIn("LD_PRELOAD=/data/local/tmp/libforgehook.so", source)
        self.assertIn("stale wrap.%s preload cleared", source)
        self.assertNotIn("bss sweep zeroed", source)
        self.assertNotIn("val >= 1u && val <= 0xFFu", source)

    def test_identity_overlay_has_full_rollback(self):
        path = os.path.join(ROOT, "cloud-agent", "system_identity_overlay.sh")
        with open(path, encoding="utf-8") as stream:
            source = stream.read()
        self.assertIn("restore_properties", source)
        self.assertIn("restore_display", source)
        self.assertIn("unmount_overlay", source)
        self.assertIn('mount --bind "$src" "$dst"', source)
        self.assertIn('/proc/sys/kernel/osrelease', source)
        self.assertIn('/sys/firmware/devicetree/base/compatible', source)
        self.assertIn('"apply-pid"', source)
        self.assertIn('"apply-local"', source)
        self.assertIn('"rollback-pid"', source)
        self.assertIn('"rollback-local"', source)
        self.assertIn('nsenter -t "$PID_ARG" -m', source)
        self.assertIn('mounts.pid.$PID_ARG.state', source)
        self.assertIn('selinux_enforce', source)
        self.assertIn('/sys/fs/selinux/enforce', source)
        self.assertIn('policy unchanged', source)
        self.assertEqual(source.count("BogoMIPS\t: 38.40"), 8)
        self.assertEqual(source.count("CPU variant\t: 0x0"), 4)
        self.assertEqual(source.count("CPU variant\t: 0x1"), 4)
        self.assertIn("androidboot.slot_suffix=_a", source)
        self.assertIn("rcu_nocbs=0-7", source)
        for partition in ("odm", "product", "system", "system_ext", "vendor"):
            self.assertIn(f"ro.product.{partition}.model|SM-G9730", source)

        hook_path = os.path.join(ROOT, "cloud-agent", "native", "libforgehook.c")
        with open(hook_path, encoding="utf-8") as stream:
            hook_source = stream.read()
        for partition in ("odm", "product", "system", "system_ext", "vendor"):
            self.assertIn(
                f'PROFILE_ENTRY("ro.product.{partition}.model","SM-G9730")',
                hook_source,
            )
        self.assertIn("int uname(struct utsname *buf)", hook_source)

        forge_path = os.path.join(ROOT, "cloud-agent", "native", "forge.c")
        with open(forge_path, encoding="utf-8") as stream:
            forge_source = stream.read()
        launch = forge_source[forge_source.index("static int do_launch(void) {") :]
        self.assertLess(
            launch.index("apply_identity_namespace(pid);"),
            launch.index("patch_game_process();"),
        )

        verify_path = os.path.join(ROOT, "cloud-agent", "verify_identity.sh")
        with open(verify_path, encoding="utf-8") as stream:
            verify_source = stream.read()
        for node in (
            "/proc/cpuinfo",
            "/proc/sys/kernel/osrelease",
            "/sys/firmware/devicetree/base/compatible",
            "/sys/fs/selinux/enforce",
        ):
            self.assertIn(f"ns_cat {node}", verify_source)
        self.assertIn("read-node overlay does not change policy", verify_source)

    def test_deploy_root_owns_tmp_transaction(self):
        path = os.path.join(ROOT, "cloud-agent", "deploy.sh")
        with open(path, encoding="utf-8") as stream:
            source = stream.read()
        root_start = source.index('cat > "$DEPLOY_SH"')
        pre_root = source[:root_start]
        root_script = source[root_start:]
        self.assertNotIn('mkdir -p "$BACKUP_DIR"', pre_root)
        self.assertNotIn('> "$TMP/forge_build.md5"', pre_root)
        self.assertIn('mkdir -p "$BACKUP_DIR"', root_script)
        self.assertIn('cp -p "$TMP/$f" "$BACKUP_DIR/$f.$TIMESTAMP"', root_script)
        self.assertIn('> $TMP/forge_build.md5', root_script)
        self.assertIn('> $TMP/forge.version', root_script)
        self.assertLess(source.index('if [ "$DRY_RUN" = "1" ]'), root_start)

    def test_mihomo_controller_preserves_direct_resource_routes(self):
        path = os.path.join(ROOT, "cloud-agent", "mihomo_control.sh")
        with open(path, encoding="utf-8") as stream:
            source = stream.read()
        self.assertIn("config.before", source)
        self.assertIn("PUFFER_DOMAIN=puffer.500638030-11-1.gcloudsvcs.com", source)
        self.assertIn('PUFFER_RULE="DOMAIN,$PUFFER_DOMAIN,DIRECT"', source)
        self.assertIn("ip route replace", source)
        self.assertIn("table \"$ROUTE_TABLE\"", source)
        self.assertIn('$2 == "via" && $5 == dev', source)
        self.assertIn("socket.getaddrinfo", source)
        self.assertIn('chmod 0600 "$CONFIG"', source)
        self.assertIn("rollback)", source)

        deploy_path = os.path.join(ROOT, "cloud-agent", "deploy.sh")
        with open(deploy_path, encoding="utf-8") as stream:
            deploy_source = stream.read()
        self.assertIn('cp "$SCRIPT_DIR/mihomo_control.sh"', deploy_source)
        self.assertIn("$TMP/mihomo_control.sh", deploy_source)
        self.assertIn("Qimei rollback copy rebuilt from active original", deploy_source)
        self.assertIn("Qimei rollback copy missing while hijack is active", deploy_source)
        self.assertIn('[ "$QIMEI_MD5" != "$HOOK_MD5" ]', deploy_source)

        check_path = os.path.join(ROOT, "cloud-agent", "check.sh")
        with open(check_path, encoding="utf-8") as stream:
            check_source = stream.read()
        self.assertIn("hijack active (主库等于 Hook)", check_source)
        self.assertIn("inject mode / original active (主库不等于 Hook)", check_source)

    def test_deploy_disables_android_graphics_diagnostics(self):
        deploy_path = os.path.join(ROOT, "cloud-agent", "deploy.sh")
        with open(deploy_path, encoding="utf-8") as stream:
            deploy_source = stream.read()
        verify_path = os.path.join(ROOT, "cloud-agent", "verify_identity.sh")
        with open(verify_path, encoding="utf-8") as stream:
            verify_source = stream.read()

        for prop in (
            "debug.hwui.show_layers_updates",
            "debug.hwui.show_dirty_regions",
            "debug.hwui.show_overdraw",
            "debug.hwui.profile",
            "debug.sf.showupdates",
        ):
            self.assertIn(f"setprop {prop} false", deploy_source)
            self.assertIn(prop, verify_source)

    def test_integration_gates_are_deployed_and_fail_closed(self):
        system_path = os.path.join(ROOT, "cloud-agent", "system_integration_gate.sh")
        kernel_path = os.path.join(ROOT, "cloud-agent", "kernel_hardware_gate.sh")
        client_path = os.path.join(ROOT, "cloud-agent", "server_probe_client.sh")
        deploy_path = os.path.join(ROOT, "cloud-agent", "deploy.sh")

        with open(system_path, encoding="utf-8") as stream:
            system_source = stream.read()
        with open(kernel_path, encoding="utf-8") as stream:
            kernel_source = stream.read()
        with open(client_path, encoding="utf-8") as stream:
            client_source = stream.read()
        with open(deploy_path, encoding="utf-8") as stream:
            deploy_source = stream.read()

        self.assertIn("SELinux behavior=", system_source)
        self.assertIn("container mount topology visible in game namespace", system_source)
        self.assertIn("external root observer sees hook pathname", system_source)
        self.assertIn("[BLOCKED_IMAGE]", kernel_source)
        self.assertIn("/sys/class/kgsl/kgsl-3d0", kernel_source)
        self.assertIn("KeyMint/Keymaster HAL absent", kernel_source)
        self.assertIn("base image must boot SELinux enforcing", kernel_source)
        self.assertIn("--connect-timeout 10 --max-time 30", client_source)
        for script in (
            "system_integration_gate.sh",
            "kernel_hardware_gate.sh",
            "server_probe_client.sh",
        ):
            self.assertIn(f'cp "$SCRIPT_DIR/{script}"', deploy_source)
            self.assertIn(f"$TMP/{script}", deploy_source)

        collector_path = os.path.join(ROOT, "cloud-agent", "collect_device_state.sh")
        with open(collector_path, encoding="utf-8") as stream:
            collector_source = stream.read()
        self.assertIn('section "INTEGRATION GATES"', collector_source)
        self.assertIn('system_integration_gate kernel_hardware_gate', collector_source)
        self.assertIn("deltaforge_server_probe.json", collector_source)

    def test_server_probe_does_not_invent_network_classification(self):
        path = os.path.join(ROOT, "server-probe", "server.py")
        with open(path, encoding="utf-8") as stream:
            source = stream.read()
        self.assertIn('"asn": None', source)
        self.assertIn('"network_type": "unknown"', source)
        self.assertIn("proxy_headers_trusted", source)
        self.assertIn("--trust-proxy", source)

    def test_environment_audit_is_read_only_and_deployed(self):
        audit_path = os.path.join(ROOT, "cloud-agent", "environment_audit.sh")
        report_path = os.path.join(
            ROOT, "cloud-agent", "environment_audit_report.py"
        )
        deploy_path = os.path.join(ROOT, "cloud-agent", "deploy.sh")
        with open(audit_path, encoding="utf-8") as stream:
            audit_source = stream.read()
        with open(report_path, encoding="utf-8") as stream:
            report_source = stream.read()
        with open(deploy_path, encoding="utf-8") as stream:
            deploy_source = stream.read()

        self.assertIn("-e trace=%file,%network,ioctl,uname,sysinfo,prctl", audit_source)
        self.assertIn("static_candidates.tsv", audit_source)
        self.assertIn("native_inventory.tsv", audit_source)
        self.assertIn("libTDataMaster.so", audit_source)
        self.assertIn("GCLOUD_VERSION_TDM_", audit_source)
        self.assertIn("maps.before.txt", audit_source)
        self.assertIn("ALLOW_HOOKED", audit_source)
        self.assertIn("libforgehook.so is active", audit_source)
        self.assertNotIn("resetprop", audit_source)
        self.assertNotIn("setprop ", audit_source)
        self.assertIn("def build_report", report_source)
        self.assertIn('cp "$SCRIPT_DIR/environment_audit.sh"', deploy_source)
        self.assertIn('cp "$SCRIPT_DIR/environment_audit_report.py"', deploy_source)


if __name__ == "__main__":
    unittest.main()
