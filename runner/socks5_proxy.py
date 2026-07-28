"""
DeltaForge PC SOCKS5 proxy — with username/password authentication (RFC 1929).
Only authenticated clients can use this proxy.
Run: python socks5_proxy.py
"""
import socket
import threading
import struct
import sys
import secrets
import string

HOST = "0.0.0.0"
PORT = 1080

# Credentials — auto-generated on first run, printed to console
USERNAME = "forge"
PASSWORD = secrets.token_urlsafe(16)  # random 16-char password each run


def auth_ok(conn):
    """SOCKS5 username/password sub-negotiation (RFC 1929)."""
    data = conn.recv(515)
    if not data or data[0] != 1:
        return False
    ulen = data[1]
    uname = data[2:2 + ulen].decode(errors="ignore")
    plen = data[2 + ulen]
    passwd = data[3 + ulen:3 + ulen + plen].decode(errors="ignore")
    ok = (uname == USERNAME and passwd == PASSWORD)
    conn.sendall(b"\x01" + (b"\x00" if ok else b"\x01"))
    return ok


def handle(conn, addr):
    try:
        # SOCKS5 greeting — advertise username/password auth only
        data = conn.recv(262)
        if not data or data[0] != 5:
            return
        # Check client supports method 0x02 (username/password)
        methods = data[2:2 + data[1]]
        if 0x02 not in methods:
            conn.sendall(b"\x05\xff")  # no acceptable method
            return
        conn.sendall(b"\x05\x02")  # require username/password

        if not auth_ok(conn):
            return  # wrong credentials — drop silently

        # SOCKS5 request
        data = conn.recv(4)
        if len(data) < 4 or data[1] != 1:
            conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return

        atyp = data[3]
        if atyp == 1:    # IPv4
            raw = conn.recv(4)
            dst_host = socket.inet_ntoa(raw)
        elif atyp == 3:  # domain
            n = conn.recv(1)[0]
            dst_host = conn.recv(n).decode()
        elif atyp == 4:  # IPv6
            raw = conn.recv(16)
            dst_host = socket.inet_ntop(socket.AF_INET6, raw)
        else:
            conn.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return

        dst_port = struct.unpack("!H", conn.recv(2))[0]

        try:
            remote = socket.create_connection((dst_host, dst_port), timeout=10)
        except Exception:
            conn.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            return

        bind = remote.getsockname()
        bip = socket.inet_aton(bind[0]) if ":" not in bind[0] else b"\x00" * 4
        conn.sendall(b"\x05\x00\x00\x01" + bip + struct.pack("!H", bind[1]))

        remote.settimeout(None)
        conn.settimeout(None)
        stop = threading.Event()

        def pipe(src, dst):
            try:
                while not stop.is_set():
                    d = src.recv(4096)
                    if not d:
                        break
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

    print(f"[+] SOCKS5 proxy (auth required) listening on {HOST}:{PORT}")
    print(f"[*] PC local IP : {local_ip}")
    print(f"[*] Username    : {USERNAME}")
    print(f"[*] Password    : {PASSWORD}")
    print(f"[*] Keep this window open — password changes on restart")
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
