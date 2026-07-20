# -*- coding: utf-8 -*-
# ============================================================
# 法器: DeltaForge/runner/forge_controller.py
# 调用者: CLI (python forge_controller.py) 或 bot_runner.py import
# API: 通过 adb forward TCP 9510 控制 cloud-agent/native/forge.c
# 数据: config/forge_config.json (连接参数), config/map_routes.json (跑刀路线)
# ============================================================

import socket
import json
import time
import sys
import os
import subprocess

CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")
FORGE_HOST = "127.0.0.1"
FORGE_PORT = 9510
ADB_SERIAL = os.environ.get("ADB_SERIAL", "")


def adb(args: str) -> str:
    cmd = ["adb"]
    if ADB_SERIAL:
        cmd.extend(["-s", ADB_SERIAL])
    cmd.extend(args.split())
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.stdout.strip()


def send_forge_command(cmd: str, timeout: float = 30.0) -> dict:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((FORGE_HOST, FORGE_PORT))
        sock.sendall((cmd + "\n").encode())
        resp = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk: break
                resp += chunk
                if b"\n" in resp: break
            except socket.timeout:
                break
        sock.close()
        return json.loads(resp.decode().strip())
    except Exception as e:
        return {"status": "err", "msg": str(e)}


def setup_adb_forward():
    adb("forward --remove tcp:9510 2>/dev/null")
    adb("forward tcp:9510 tcp:9510")


def wait_for_device(timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = adb("get-state")
        if out == "device": return True
        time.sleep(2)
    return False


def push_and_start_forge():
    base = os.path.dirname(os.path.abspath(__file__))
    forge_path = os.path.join(base, "..", "cloud-agent", "native", "forge")
    if not os.path.exists(forge_path):
        forge_path = os.path.join(base, "forge")
    if not os.path.exists(forge_path):
        print(f"[-] forge binary not found: {forge_path}")
        return False
    adb(f"push {forge_path} /data/local/tmp/forge")
    adb("shell chmod 755 /data/local/tmp/forge")
    # 同时推送 hook 库
    hook_path = os.path.join(os.path.dirname(forge_path), "libforgehook.so")
    if not os.path.exists(hook_path):
        hook_path = os.path.join(base, "libforgehook.so")
    if os.path.exists(hook_path):
        adb(f"push {hook_path} /data/local/tmp/libforgehook.so")
        adb("shell chmod 644 /data/local/tmp/libforgehook.so")
        print("[+] libforgehook.so pushed")
    else:
        print("[!] libforgehook.so not found — /proc/cpuinfo hook unavailable")
    adb("shell pkill forge 2>/dev/null")
    time.sleep(1)
    adb("shell '/data/local/tmp/forge -d &'")
    time.sleep(2)
    print("[+] forge daemon started")
    return True


class ForgeController:
    def __init__(self): self.connected = False

    def connect(self) -> bool:
        if not wait_for_device(): return False
        setup_adb_forward()
        time.sleep(1)
        for attempt in range(5):
            resp = send_forge_command("ping")
            if resp.get("status") == "ok":
                print(f"[+] forge connected v{resp.get('version','?')}")
                self.connected = True
                return True
            time.sleep(2)
        if push_and_start_forge():
            setup_adb_forward(); time.sleep(2)
            resp = send_forge_command("ping")
            if resp.get("status") == "ok":
                self.connected = True; return True
        print("[-] forge connection failed")
        return False

    def prepare(self) -> bool:
        resp = send_forge_command("prepare", timeout=120)
        print(f"    prepare: {resp}")
        return resp.get("status") == "ok"

    def launch(self) -> bool:
        resp = send_forge_command("launch", timeout=180)
        print(f"    launch: {resp}")
        return resp.get("status") in ("ok", "partial")

    def patch_only(self) -> bool:
        resp = send_forge_command("patch", timeout=60)
        print(f"    patch: {resp}")
        return resp.get("status") in ("ok", "partial")

    def stop(self) -> bool:
        resp = send_forge_command("stop")
        return resp.get("status") == "ok"

    def status(self) -> dict:
        return send_forge_command("status")

    def clean(self) -> int:
        resp = send_forge_command("clean")
        return resp.get("cleaned", 0)

    def spoof(self) -> bool:
        resp = send_forge_command("spoof")
        return resp.get("status") == "ok"

    def restart_cycle(self):
        print("=" * 50)
        print("[*] Full restart cycle")
        self.stop(); time.sleep(2)
        self.clean(); self.spoof(); self.prepare(); self.launch()
        print("[*] Done")
        print("=" * 50)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="DeltaForge Controller")
    parser.add_argument("action", nargs="?", default="full",
                        choices=["full","prepare","launch","patch","stop","status","clean","spoof","restart"])
    parser.add_argument("--serial","-s",help="adb device serial")
    args = parser.parse_args()
    if args.serial: ADB_SERIAL = args.serial

    ctrl = ForgeController()
    if args.action == "status":
        if ctrl.connect(): print(json.dumps(ctrl.status(), indent=2, ensure_ascii=False))
        sys.exit(0)
    if not ctrl.connect(): print("[-] Cannot connect"); sys.exit(1)

    if args.action == "full": ctrl.restart_cycle()
    elif args.action == "prepare": ctrl.prepare()
    elif args.action == "launch": ctrl.launch()
    elif args.action == "patch": ctrl.patch_only()
    elif args.action == "stop": ctrl.stop()
    elif args.action == "clean": ctrl.clean()
    elif args.action == "spoof": ctrl.spoof()
    elif args.action == "restart": ctrl.restart_cycle()
