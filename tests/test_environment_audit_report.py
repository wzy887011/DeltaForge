import json
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class EnvironmentAuditReportTests(unittest.TestCase):
    def test_strace_and_static_candidates_are_classified(self):
        from cloud_agent_import import load_environment_audit_report

        module = load_environment_audit_report(ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "strace.123"), "w", encoding="utf-8") as stream:
                stream.write(
                    '1722230000.100 openat(AT_FDCWD, "/proc/cpuinfo", O_RDONLY) = 3\n'
                )
                stream.write(
                    '1722230000.200 openat(AT_FDCWD, "/sys/class/kgsl/kgsl-3d0/gpu_model", O_RDONLY) = -1 ENOENT\n'
                )
                stream.write('1722230000.300 uname({sysname="Linux"}) = 0\n')
                stream.write('1722230000.400 ioctl(17, 0xc0100946, 0x7f00) = -1\n')
            with open(
                os.path.join(tmp, "static_candidates.tsv"), "w", encoding="utf-8"
            ) as stream:
                stream.write("libtersafe.so\tproperty\tro.hardware\n")
                stream.write("libtersafe.so\tpath\t/sys/fs/selinux/enforce\n")

            report = module.build_report(tmp)

        self.assertEqual(report["schema"], 1)
        self.assertGreaterEqual(report["summary"]["filesystem"], 3)
        self.assertEqual(report["summary"]["kernel"], 1)
        self.assertEqual(report["summary"]["ioctl"], 1)
        self.assertEqual(report["summary"]["property"], 1)
        values = {item["value"] for item in report["signals"]}
        self.assertIn("/proc/cpuinfo", values)
        self.assertIn("ro.hardware", values)
        self.assertIn("uname", values)

    def test_report_is_deterministic_and_writes_json(self):
        from cloud_agent_import import load_environment_audit_report

        module = load_environment_audit_report(ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "strace.7"), "w", encoding="utf-8") as stream:
                stream.write('1.0 openat(AT_FDCWD, "/proc/version", O_RDONLY) = 3\n')
                stream.write('2.0 openat(AT_FDCWD, "/proc/version", O_RDONLY) = 3\n')
            output = os.path.join(tmp, "report.json")
            with redirect_stdout(io.StringIO()):
                rc = module.main([tmp, "--json", output])
            self.assertEqual(rc, 0)
            with open(output, encoding="utf-8") as stream:
                payload = json.load(stream)

        self.assertEqual(payload["summary"]["filesystem"], 2)
        self.assertEqual(len(payload["signals"]), 1)
        self.assertEqual(payload["signals"][0]["count"], 2)


if __name__ == "__main__":
    unittest.main()
