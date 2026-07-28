"""
DeltaForge PC SOCKS5 proxy — auth + brute-force protection + connection log.
"""
import socket, threading, struct, sys, secrets, time
from datetime import datetime
from collections import defaultdict

HOST     = "0.0.0.0"
PORT     = 1080
USERNAME = "forge"
PASSWORD = "Q3DLo_jYvBCAZkJpDCOmdQ"   # set once, stable across restarts

MAX_FAIL     = 5        # failed auth attempts before temp-ban
BAN_SECONDS  = 300      # 5-minute ban per offending IP
MAX_CONNS    = 20       # max concurrent connections total

_lock        = threading.Lock()
_fail_count  = defaultdict(int)
_ban_until   = {}
_active      = 0


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def is_banned(ip):
    until = _ban_until.get(ip)
    if until and time.time() < until:
        return True
    if until:
        del _ban_until[ip]
        _fail_count[ip] = 0
    return False


def record_fail(ip):
    with _lock:
        _fail_count[ip] += 1
        if _fail_count[ip] >= MAX_FAIL:
            _ban_until[ip] = time.time() + BAN_SECONDS
            log(f"[BAN] {ip} — too many auth failures, banned {BAN_SECONDS}s")


def auth_ok(conn, ip):
    data = conn.recv(515)
    if not data or data[0] != 1:
        record_fail(ip)
        return False
    ulen  = data[1]
    uname = data[2:2 + ulen].decode(errors="ignore")
    plen  = data[2 + ulen]
    passwd = data[3 + ulen:3 + ulen + plen].decode(errors="ignore")
    ok = (uname == USERNAME and passwd == PASSWORD)
    conn.sendall(b"\x01" + (b"\x00" if ok else b"\x01"))
    if not ok:
        record_fail(ip)
        log(f"[FAIL] {ip} bad credentials")
    return ok


def handle(conn, addr):
    global _active
    ip = addr[0]
    with _lock:
        if _active >= MAX_CONNS:
            conn.close()
            log(f"[DROP] {ip} — max connections reached")
            return
        _active += 1
    try:
        if is_banned(ip):
            log(f"[BAN]  {ip} rejected (still banned)")
            return

        data = conn.recv(262)
        if not data or data[0] != 5:
            return
        methods = data[2:2 + data[1]]
        if 0x02 not in methods:
            conn.sendall(b"\x05\xff")
            log(f"[DROP] {ip} — no auth method")
            return
        conn.sendall(b"\x05\x02")

        if not auth_ok(conn, ip):
            return

        data = conn.recv(4)
        if len(data) < 4 or data[1] != 1:
            conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return

        atyp = data[3]
        if atyp == 1:
            dst_host = socket.inet_ntoa(conn.recv(4))
        elif atyp == 3:
            n = conn.recv(1)[0]
            dst_host = conn.recv(n).decode()
        elif atyp == 4:
            dst_host = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
        else:
            conn.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return

        dst_port = struct.unpack("!H", conn.recv(2))[0]
        log(f"[CONN] {ip} → {dst_host}:{dst_port}")

        try:
            remote = socket.create_connection((dst_host, dst_port), timeout=10)
        except Exception as e:
            conn.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            log(f"[ERR]  {ip} connect {dst_host}:{dst_port} failed: {e}")
            return

        bind = remote.getsockname()
        bip  = socket.inet_aton(bind[0]) if ":" not in bind[0] else b"\x00" * 4
        conn.sendall(b"\x05\x00\x00\x01" + bip + struct.pack("!H", bind[1]))

        remote.settimeout(None)
        conn.settimeout(None)
        stop = threading.Event()

        def pipe(src, dst):
            try:
                while not stop.is_set():
                    d = src.recv(4096)
                    if not d: break
                    dst.sendall(d)
            except Exception:
                pass
            finally:
                stop.set()

        t = threading.Thread(target=pipe, args=(remote, conn), daemon=True)
        t.start()
        pipe(conn, remote)
        t.join(timeout=2)
        remote.close()
    except Exception:
        pass
    finally:
        with _lock:
            _active -= 1
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(128)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "unknown"

    print(f"[+] SOCKS5 proxy listening on {HOST}:{PORT}")
    print(f"[*] Local IP  : {local_ip}")
    print(f"[*] Username  : {USERNAME}")
    print(f"[*] Password  : {PASSWORD}")
    print(f"[*] Security  : auth required | {MAX_FAIL} fails = {BAN_SECONDS}s ban | max {MAX_CONNS} conns")
    print(f"[*] Keep this window open")
    print()

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
        sys.exit(0)
