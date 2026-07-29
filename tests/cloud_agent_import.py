import importlib.util
import os


def load_environment_audit_report(root):
    path = os.path.join(root, "cloud-agent", "environment_audit_report.py")
    spec = importlib.util.spec_from_file_location("environment_audit_report", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
