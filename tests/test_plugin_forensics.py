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

            out = Path(tmp) / "out"
            reporter.write_reports(first, out)
            payload = json.loads(
                (out / "plugin-forensics-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(payload, first)
            markdown = (out / "plugin-forensics-report.md").read_text(encoding="utf-8")
            self.assertIn("Cloud Device Plugin Forensics", markdown)
            self.assertIn("cloudmask", markdown)

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
