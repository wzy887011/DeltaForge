"""
DeltaForge PC SOCKS5 proxy — no dependencies, pure stdlib Python 3.
Listens on 0.0.0.0:1080, forwards traffic through PC's internet connection.
Run: python socks5_proxy.py
"""
import socket
import threading
import struct
import sys

HOST = "0.0.0.0"
PORT = 1080


def handle(conn, addr):
    try:
        # SOCKS5 greeting
        data = conn.recv(262)
        if not data or data[0] != 5:
            return
        conn.sendall(b"\x05\x00")  # no auth

        # SOCKS5 request
        data = conn.recv(4)
        if len(data) < 4 or data[1] != 1:  # only CONNECT supported
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

        # connect to target
        try:
            remote = socket.create_connection((dst_host, dst_port), timeout=10)
        except Exception:
            conn.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            return

        # reply success
        bind = remote.getsockname()
        bip = socket.inet_aton(bind[0]) if ":" not in bind[0] else b"\x00" * 4
        conn.sendall(b"\x05\x00\x00\x01" + bip + struct.pack("!H", bind[1]))

        # relay
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

    # show PC outbound IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "unknown"

    print(f"[+] SOCKS5 proxy listening on {HOST}:{PORT}")
    print(f"[*] PC local IP: {local_ip}")
    print(f"[*] Keep this window open")
    print(f"[*] On cloud phone run:")
    print(f"       su -c \"sh /data/local/tmp/proxy_phone.sh start\"")
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
