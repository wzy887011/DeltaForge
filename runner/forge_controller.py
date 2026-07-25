# -*- coding: utf-8 -*-
# ============================================================
# runner/forge_controller.py v7.0
# 改进: [v7.0 P2-2] SipHash-2-4 命令认证，配合 forge.c v7.0 TCP 认证
# ============================================================

import socket, json, time, sys, os, subprocess, struct, secrets

FORGE_HOST       = "127.0.0.1"
FORGE_PORT       = 9510
ADB_SERIAL       = os.environ.get("ADB_SERIAL", "")
SESSION_KEY_FILE = "/data/local/tmp/.forge_key"
SESSION_KEY_LOCAL = "/tmp/.forge_key_cache"


# ── SipHash-2-4（与 forge.c v7.0 完全一致） ──────────────────
def _rot64(v, n): return ((v << n) | (v >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

def siphash24(key16: bytes, data: bytes) -> int:
    k0 = struct.unpack_from('<Q', key16, 0)[0]
    k1 = struct.unpack_from('<Q', key16, 8)[0]
    v0 = 0x736f6d6570736575 ^ k0; v1 = 0x646f72616e646f6d ^ k1
    v2 = 0x6c7967656e657261 ^ k0; v3 = 0x7465646279746573 ^ k1
    def sr():
        nonlocal v0, v1, v2, v3
        v0=(v0+v1)&0xFFFFFFFFFFFFFFFF; v1=_rot64(v1,13); v1^=v0; v0=_rot64(v0,32)
        v2=(v2+v3)&0xFFFFFFFFFFFFFFFF; v3=_rot64(v3,16); v3^=v2
        v0=(v0+v3)&0xFFFFFFFFFFFFFFFF; v3=_rot64(v3,21); v3^=v0
        v2=(v2+v1)&0xFFFFFFFFFFFFFFFF; v1=_rot64(v1,17); v1^=v2; v2=_rot64(v2,32)
    n = len(data); i = 0
    while i + 8 <= n:
        m = struct.unpack_from('<Q', data, i)[0]; v3^=m; sr(); sr(); v0^=m; i+=8
    last = (n & 0xFF) << 56
    for j in range(n-i): last |= data[i+j] << (j*8)
    v3^=last; sr(); sr(); v0^=last; v2^=0xFF
    for _ in range(4): sr()
    return v0^v1^v2^v3


_session_key: bytes = b""


def adb(args: str) -> str:
    cmd = ["adb"]
    if ADB_SERIAL: cmd += ["-s", ADB_SERIAL]
    cmd += args.split()
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    return r.stdout.strip()


def load_session_key() -> bool:
    global _session_key
    if _session_key: return True
    if os.path.exists(SESSION_KEY_LOCAL):
        with open(SESSION_KEY_LOCAL, 'rb') as f: d = f.read()
        if len(d) == 16: _session_key = d; return True
    b64 = adb(f"shell su -c 'base64 {SESSION_KEY_FILE}'").strip()
    if b64:
        import base64
        try:
            key = base64.b64decode(b64)
            if len(key) == 16:
                _session_key = key
                with open(SESSION_KEY_LOCAL, 'wb') as f: f.write(key)
                os.chmod(SESSION_KEY_LOCAL, 0o600)
                return True
        except Exception: pass
    print("[!] 无法获取 session key，将以无认证模式运行")
    return False


def build_auth_header(cmd: str) -> str:
    if not _session_key: return ""
    nonce = secrets.token_bytes(8)
    combined = nonce + cmd.encode('utf-8', errors='replace')[:256]
    mac = siphash24(_session_key, combined)
    return f"AUTH:{nonce.hex()}:{mac:016x}\n"


def send_forge_command(cmd: str, timeout: float = 30.0) -> dict:
    load_session_key()
    payload = (build_auth_header(cmd) + cmd + "\n").encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout); s.connect((FORGE_HOST, FORGE_PORT))
        s.sendall(payload)
        resp = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk: break
                resp += chunk
                if b"\n" in resp: break
            except socket.timeout: break
        s.close()
        return json.loads(resp.decode().strip())
    except json.JSONDecodeError:
        return {"status": "err", "msg": f"invalid json: {resp[:100]}"}
    except Exception as e:
        return {"status": "err", "msg": str(e)}


def setup_adb_forward():
    adb("forward --remove tcp:9510 2>/dev/null")
    adb("forward tcp:9510 tcp:9510")


def wait_for_device(timeout=60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if adb("get-state") == "device": return True
        time.sleep(2)
    return False


def push_and_start_forge() -> bool:
    base       = os.path.dirname(os.path.abspath(__file__))
    native_dir = os.path.join(base, "..", "cloud-agent", "native")
    def _find(name):
        for d in [native_dir, base]:
            p = os.path.join(d, name)
            if os.path.exists(p): return p
        return None
    forge_path = _find("forge")
    if not forge_path:
        print("[-] forge 未找到，请先编译: clang -pie -Os forge.c -o forge"); return False
    adb(f"push {forge_path} /data/local/tmp/forge")
    adb("shell chmod 755 /data/local/tmp/forge"); print("[+] forge pushed")
    for name, perm in [("libforgehook.so","644"),("injector","755"),("touch_injector","755")]:
        p = _find(name)
        if p:
            adb(f"push {p} /data/local/tmp/{name}")
            adb(f"shell chmod {perm} /data/local/tmp/{name}")
            print(f"[+] {name} pushed")
    adb("shell su -c 'pkill forge 2>/dev/null; sleep 1'")
    adb("shell su -c '/data/local/tmp/forge -d > /data/local/tmp/forge.log 2>&1 &'")
    time.sleep(2)
    global _session_key
    _session_key = b""
    if os.path.exists(SESSION_KEY_LOCAL): os.remove(SESSION_KEY_LOCAL)
    time.sleep(1); load_session_key()
    print("[+] forge daemon started"); return True


class ForgeController:
    def __init__(self): self.connected = False

    def connect(self) -> bool:
        if not wait_for_device(): print("[-] 设备不可达"); return False
        setup_adb_forward(); time.sleep(1)
        for _ in range(5):
            resp = send_forge_command("ping")
            if resp.get("status") == "ok":
                print(f"[+] forge 连接成功 v{resp.get('version','?')}")
                self.connected = True; return True
            time.sleep(2)
        if push_and_start_forge():
            setup_adb_forward(); time.sleep(2)
            resp = send_forge_command("ping")
            if resp.get("status") == "ok": self.connected = True; return True
        print("[-] forge 连接失败"); return False

    def prepare(self)   -> bool: r=send_forge_command("prepare",timeout=120); print(f"    prepare: {r}"); return r.get("status")=="ok"
    def launch(self)    -> bool: r=send_forge_command("launch", timeout=180); print(f"    launch: {r}");  return r.get("status") in ("ok","partial")
    def patch_only(self)-> bool: r=send_forge_command("patch",  timeout=60);  print(f"    patch: {r}");   return r.get("status") in ("ok","partial")
    def stop(self)      -> bool: return send_forge_command("stop").get("status")=="ok"
    def status(self)    -> dict: return send_forge_command("status")
    def clean(self)     -> int:  return send_forge_command("clean").get("cleaned",0)
    def adapt_props(self)->bool: return send_forge_command("adapt").get("status")=="ok"

    def restart_cycle(self):
        print("="*50+"\n[*] Full restart cycle")
        self.stop(); time.sleep(2); self.clean(); self.adapt_props(); self.prepare(); self.launch()
        print("[*] Done\n"+"="*50)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="DeltaForge Controller v7.0")
    p.add_argument("action", nargs="?", default="full",
                   choices=["full","prepare","launch","patch","stop","status","clean","adapt","restart"])
    p.add_argument("--serial","-s", help="adb device serial")
    a = p.parse_args()
    if a.serial: ADB_SERIAL = a.serial
    ctrl = ForgeController()
    if a.action == "status":
        if ctrl.connect(): print(json.dumps(ctrl.status(), indent=2, ensure_ascii=False))
        sys.exit(0)
    if not ctrl.connect(): print("[-] 无法连接"); sys.exit(1)
    {"full":ctrl.restart_cycle,"prepare":ctrl.prepare,"launch":ctrl.launch,
     "patch":ctrl.patch_only,"stop":ctrl.stop,"clean":ctrl.clean,
     "adapt":ctrl.adapt_props,"restart":ctrl.restart_cycle}[a.action]()
