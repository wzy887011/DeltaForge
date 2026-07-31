import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "environment_inventory_report.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("environment_inventory_report", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class EnvironmentInventoryTests(unittest.TestCase):
    def make_fixture(self, root: Path, hardware: str, service_state: str) -> None:
        files = {
            "manifest.tsv": "key\tvalue\nschema\t1\n",
            "commands/identity_projection/getprop.stdout.txt": (
                f"[ro.hardware]: [{hardware}]\n[init.svc.adbd]: [{service_state}]\n"
            ),
            "commands/boot_kernel/kernel_config.stdout.txt": (
                "CONFIG_ARM64=y\n# CONFIG_KPROBES is not set\n"
            ),
            "commands/root_framework/proc_walk.stdout.txt": (
                "10\t1\t0\tinit\t/system/bin/init\t/system/bin/init second_stage\n"
            ),
            "commands/namespace_projection/root_mountinfo.stdout.txt": (
                "1 0 8:1 / / rw - ext4 /dev/root rw\n"
            ),
            "commands/packages_artifacts/packages_all.stdout.txt": (
                "package:/system/app/Test/base.apk=com.example.test uid:1000\n"
            ),
            "commands/init_services/binder_services.stdout.txt": (
                "0 activity: [android.app.IActivityManager]\n"
            ),
            "supplemental/settings_global.stdout.txt": "adb_enabled=0\n",
            "supplemental/device_config.stdout.txt": "namespace/flag=true\n",
        }
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def test_complete_inventory_and_diff(self):
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            phone_root = Path(tmp) / "phone"
            real_root = Path(tmp) / "real"
            self.make_fixture(phone_root, "ntimespace", "running")
            self.make_fixture(real_root, "qcom", "stopped")

            phone = tool.build_inventory(phone_root, "cloud_phone")
            real = tool.build_inventory(real_root, "cloud_real_phone")
            self.assertEqual(phone["normalized"]["properties"]["ro.hardware"], "ntimespace")
            self.assertEqual(phone["normalized"]["kernel_config"]["CONFIG_KPROBES"], "not set")
            self.assertIn("adbd", phone["normalized"]["init_services"])
            self.assertIn("com.example.test", phone["normalized"]["packages"])
            self.assertEqual(phone["normalized"]["settings_global"]["adb_enabled"], "0")
            self.assertEqual(phone["normalized"]["device_config"]["namespace/flag"], "true")
            self.assertTrue(phone["normalized"]["mounts"])

            diff = tool.build_diff(phone, real)
            property_keys = {
                item["key"] for item in diff["domains"]["properties"]["differences"]
            }
            self.assertIn("ro.hardware", property_keys)
            self.assertIn("init.svc.adbd", property_keys)

            outputs = tool.write_outputs(phone, real, Path(tmp) / "out")
            self.assertTrue(outputs["cloud_phone_json"].is_file())
            self.assertTrue(outputs["cloud_real_phone_text"].is_file())
            self.assertIn(
                "commands/boot_kernel/kernel_config.stdout.txt",
                outputs["cloud_phone_text"].read_text(encoding="utf-8"),
            )

    def test_failed_binder_output_uses_supplement(self):
        tool = load_tool()
        records = {
            "commands/packages_artifacts/features.stdout.txt": {
                "text": "cmd: Failure calling service package: Failed transaction\n"
            },
            "supplemental/features.stdout.txt": {"text": "feature:android.hardware.camera\n"},
        }
        self.assertEqual(
            tool.first_text(
                records,
                "commands/packages_artifacts/features.stdout.txt",
                "supplemental/features.stdout.txt",
            ),
            "feature:android.hardware.camera\n",
        )

    def test_binder_service_ordinals_are_ignored(self):
        tool = load_tool()
        before = tool.parse_binder_services(
            "0 activity: [android.app.IActivityManager]\n"
            "1 package: [android.content.pm.IPackageManager]\n"
        )
        after = tool.parse_binder_services(
            "0 apexservice: [android.apex.IApexService]\n"
            "1 activity: [android.app.IActivityManager]\n"
            "2 package: [android.content.pm.IPackageManager]\n"
        )

        self.assertEqual(before["activity"], after["activity"])
        self.assertEqual(before["package"], after["package"])
        self.assertEqual(
            [item["key"] for item in tool.mapping_diff(before, after)],
            ["apexservice"],
        )


if __name__ == "__main__":
    unittest.main()
