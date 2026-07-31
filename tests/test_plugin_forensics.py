import importlib.util
import io
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "cloud-agent" / "plugin_forensics_collect.sh"
REPORTER = ROOT / "tools" / "plugin_forensics_report.py"


def load_reporter():
    spec = importlib.util.spec_from_file_location("plugin_forensics_report", REPORTER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class PluginForensicsCollectorTests(unittest.TestCase):
    def test_collector_contract_is_read_only_and_complete(self):
        source = COLLECTOR.read_text(encoding="utf-8")
        for layer in (
            "boot_kernel",
            "root_framework",
            "init_services",
            "identity_projection",
            "namespace_projection",
            "runtime_injection",
            "packages_artifacts",
            "network_projection",
        ):
            self.assertIn(f"layer: {layer}", source)

        self.assertIn('TARGET_PACKAGE="com.tencent.tmgp.dfm"', source)
        self.assertIn("errors.tsv", source)
        self.assertIn("candidates.tsv", source)
        self.assertIn("tar -czf", source)
        self.assertIn("ARCHIVE=", source)
        self.assertIn("SHA256=", source)
        for deep_signal in (
            "proc_walk",
            "boot_scripts",
            "core_tool_hashes",
            "bpf_inventory",
            "resetprop_view",
            "environ.txt",
            "platform_control_plane",
            "platform_control_processes",
            "platform_control_sockets",
            "com.android.provider.root",
            "bpfdomain",
            "rkp_cert_processor",
            "traced_kprobes",
            "s9su",
            "script_guard",
            "createns2",
            "execns2",
            "remote_admin_bridges",
            "capture_shell_uid",
            "settings_global",
            "settings_secure",
            "settings_system",
            "device_config",
            "packages_artifacts features",
            "packages_artifacts libraries",
        ):
            self.assertIn(deep_signal, source)

        forbidden = re.compile(
            r"(?m)^\s*(?:setprop|resetprop|umount|kill|stop|start|"
            r"pm\s+(?:install|uninstall)|iptables\s+-|ip6tables\s+-|"
            r"nft\s+(?:add|delete|flush))\b"
        )
        self.assertIsNone(forbidden.search(source))


class PluginForensicsReporterTests(unittest.TestCase):
    def make_fixture(self, root: Path):
        (root / "commands" / "identity_projection").mkdir(parents=True)
        (root / "commands" / "namespace_projection").mkdir(parents=True)
        (root / "processes" / "target").mkdir(parents=True)
        (root / "modules" / "text").mkdir(parents=True)

        (root / "manifest.tsv").write_text(
            "key\tvalue\npackage\tcom.tencent.tmgp.dfm\nschema\t1\n",
            encoding="utf-8",
        )
        (root / "candidates.tsv").write_text(
            "path\ttype\tsize\tuid\tgid\tmode\tsha256\tbuild_id\tindicators\tsource\n"
            "/data/adb/modules/cloudmask/zygisk/arm64-v8a.so\tregular file\t4096\t0\t0\t755\t"
            + "a" * 64
            + "\tabc123\tzygisk,resetprop,spoof\troot_modules\n",
            encoding="utf-8",
        )
        (root / "modules" / "text" / "cloudmask.module.prop.txt").write_text(
            "id=cloudmask\nname=Cloud Mask\ndescription=property spoof and zygisk bridge\n",
            encoding="utf-8",
        )
        (root / "processes" / "target" / "maps.txt").write_text(
            "7a000000-7a010000 r-xp 0 00:00 0 /data/adb/modules/cloudmask/zygisk/arm64-v8a.so\n",
            encoding="utf-8",
        )
        (root / "commands" / "identity_projection" / "getprop.stdout.txt").write_text(
            "[ro.hardware]: [qcom]\n[ro.soc.model]: [SM8150]\n"
            "[ro.boot.hardware]: [rk3588]\n[ro.boot.verifiedbootstate]: [green]\n",
            encoding="utf-8",
        )
        (root / "commands" / "boot_kernel").mkdir(parents=True)
        (root / "commands" / "boot_kernel" / "kernel_config.stdout.txt").write_text(
            "# CONFIG_SECURITY_SELINUX_DISABLE is not set\n"
            "CONFIG_ARCH_ROCKCHIP=y\nCONFIG_OVERLAY_FS=y\n",
            encoding="utf-8",
        )
        (root / "commands" / "namespace_projection" / "root_mountinfo.stdout.txt").write_text(
            "42 31 0:38 / /system rw - overlay overlay rw,lowerdir=/lxc/rootfs\n",
            encoding="utf-8",
        )
        (root / "errors.tsv").write_text("layer\tname\trc\tstderr\n", encoding="utf-8")

    def test_report_correlates_sources_and_is_deterministic(self):
        reporter = load_reporter()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "audit"
            root.mkdir()
            self.make_fixture(root)

            first = reporter.build_report(root)
            second = reporter.build_report(root)
            self.assertEqual(first, second)
            self.assertEqual(first["schema"], 1)
            self.assertEqual(first["summary"]["candidate_count"], 1)

            candidate = first["candidates"][0]
            self.assertIn("zygote_injection", candidate["facets"])
            self.assertIn("property_spoofing", candidate["facets"])
            self.assertGreaterEqual(candidate["score"], 50)
            self.assertGreaterEqual(len(candidate["source_families"]), 3)
            self.assertTrue(candidate["evidence"])
            self.assertTrue(first["contradictions"])
            contradiction_ids = {item["id"] for item in first["contradictions"]}
            self.assertNotIn("selinux_state_mismatch", contradiction_ids)

            out = Path(tmp) / "out"
            reporter.write_reports(first, out)
            payload = json.loads(
                (out / "plugin-forensics-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(payload, first)
            markdown = (out / "plugin-forensics-report.md").read_text(encoding="utf-8")
            self.assertIn("Cloud Device Plugin Forensics", markdown)
            self.assertIn("cloudmask", markdown)

    def test_candidate_tokens_exclude_generic_architecture_components(self):
        reporter = load_reporter()
        tokens = reporter.candidate_tokens(
            "/data/app/random/com.example/lib/arm64/libTDataMaster.so"
        )
        self.assertNotIn("arm64", tokens)
        self.assertNotIn("data", tokens)
        self.assertNotIn("com.example", tokens)
        self.assertIn("libtdatamaster", tokens)

        module_tokens = reporter.candidate_tokens(
            "/data/adb/modules/cloudmask/zygisk/arm64-v8a.so"
        )
        self.assertIn("cloudmask", module_tokens)

        apk_tokens = reporter.candidate_tokens(
            "/data/app/~~random==/com.android.provider.root-random==/base.apk"
        )
        self.assertNotIn("base", apk_tokens)
        self.assertNotIn("base.apk", apk_tokens)
        self.assertIn("com.android.provider.root", apk_tokens)
        self.assertFalse(
            reporter.matches_candidate(
                "[com.android.provider.root,com.android.provider.proxy,com.example]",
                "/data/app/random/com.android.provider.root-random/base.apk",
                apk_tokens,
            )
        )

    def test_normal_vndk_library_remains_low_confidence(self):
        reporter = load_reporter()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "audit"
            (root / "processes" / "target").mkdir(parents=True)
            (root / "manifest.tsv").write_text(
                "key\tvalue\npackage\tcom.example\n", encoding="utf-8"
            )
            (root / "candidates.tsv").write_text(
                "path\ttype\tsize\tuid\tgid\tmode\tsha256\tbuild_id\tindicators\tsource\n"
                "/system/lib64/libvndksupport.so\tregular file\t100\t0\t0\t644\t"
                + "b" * 64
                + "\t\tloaded_mapping\tprocess_target\n",
                encoding="utf-8",
            )
            (root / "processes" / "target" / "maps.txt").write_text(
                "7000-8000 r-xp 0 00:00 0 /system/lib64/libvndksupport.so\n",
                encoding="utf-8",
            )
            report = reporter.build_report(root)
            candidate = report["candidates"][0]
            self.assertEqual(candidate["facets"], [])
            self.assertLessEqual(candidate["score"], 20)
            self.assertEqual(candidate["confidence"], "low")

    def test_platform_root_stack_is_classified_as_control_plane(self):
        reporter = load_reporter()
        facets = reporter.classify_facets(
            "/system/xbin/rkp_cert_processor platform_control_plane "
            "/data/misc/profiles/exec/sock"
        )
        self.assertIn("privileged_control_plane", facets)

        root_facets = reporter.classify_facets(
            "/system/xbin/bpfdomain com.android.provider.root"
        )
        self.assertIn("root_framework", root_facets)
        self.assertIn("privileged_control_plane", root_facets)

        policy_facets = reporter.classify_facets(
            "/system/bin/poweropt-service /system/etc/selinux/asp_sepolicy.conf"
        )
        self.assertIn("selinux_policy_patch", policy_facets)
        self.assertNotIn("hardware_projection", policy_facets)

        decoy_facets = reporter.classify_facets(
            "/system/xbin/traced_kprobes platform_control_plane"
        )
        self.assertIn("privileged_control_plane", decoy_facets)
        self.assertNotIn("kernel_hook", decoy_facets)

        initd_facets = reporter.classify_facets(
            "/system/bin/initd [ro.boottime.initd]: [4839547528102962]"
        )
        self.assertNotIn("property_spoofing", initd_facets)

        cloud_phone_facets = reporter.classify_facets(
            "/system/xbin/s9su /vendor/bin/createns2 ntimespace "
            "nc -L -p 5555 /vendor/bin/execns2"
        )
        self.assertIn("root_framework", cloud_phone_facets)
        self.assertIn("privileged_control_plane", cloud_phone_facets)
        self.assertIn("container_control_plane", cloud_phone_facets)
        self.assertIn("remote_admin", cloud_phone_facets)

        research_facets = reporter.classify_facets(
            "/data/local/tmp/frida-server-17.15.3 keyword_match"
        )
        self.assertIn("research_artifact", research_facets)
        self.assertIn("application_hook", research_facets)

    def test_mixed_consumer_and_cloud_identity_is_reported(self):
        reporter = load_reporter()
        lines = [
            ("commands/identity_projection/getprop.stdout.txt", 1,
             "[ro.build.fingerprint]: [samsung/device/device:12/build:user/release-keys]"),
            ("commands/identity_projection/getprop.stdout.txt", 2,
             "[ro.product.brand]: [OPPO]"),
            ("commands/identity_projection/getprop.stdout.txt", 3,
             "[ro.product.manufacturer]: [honor]"),
            ("commands/identity_projection/getprop.stdout.txt", 4,
             "[ro.system_ext.build.fingerprint]: [ntimespace/rk3588_docker/device:12/build:user/test-keys]"),
        ]
        ids = {item["id"] for item in reporter.environment_contradictions(lines)}
        self.assertIn("identity_profile_mismatch", ids)
        self.assertIn("native_cloud_identity_leak", ids)

    def test_archive_parent_traversal_is_rejected(self):
        reporter = load_reporter()
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "bad.tar.gz"
            with tarfile.open(archive, "w:gz") as stream:
                info = tarfile.TarInfo("../outside.txt")
                body = b"bad"
                info.size = len(body)
                stream.addfile(info, io.BytesIO(body))

            with self.assertRaises(ValueError):
                with reporter.evidence_root(archive):
                    pass


if __name__ == "__main__":
    unittest.main()
