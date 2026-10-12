"""Probe jaringan untuk `bench-selftest`: dijalankan DI DALAM perintah AI yang terkurung (`python3 -c <isi berkas ini> <mode> ...`), supaya bukti jaringan berasal dari
jalur sungguhan (Landlock + jaringan internal), bukan dari proses selftest yang tidak terkurung. Hanya pustaka standar. Berkas ini juga diuji dari tes lokal.

Mode:
  direct  HOST PORT                -> "CONNECTED" bila koneksi TCP berhasil, selain itu "ERRNO <nama>" (mis. EACCES = ditolak Landlock)
  resolve NAMA                     -> "RESOLVED <ip>" atau "NXDOMAIN"
  connect PROXY_HOST PROXY_PORT T  -> kirim `CONNECT T` ke proxy; "STATUS <kode> REASON <alasan>" (alasan dari header X-Egress-Reason)
"""

import errno
import socket
import sys

# Target yang proxy WAJIB tolak (403) apa pun isi daftar putih, bahkan bila AI_SHELL_NET_ALLOW=`*`: metadata cloud, loopback (beberapa penulisan), alamat privat, nama
# internal/tanpa titik (layanan lain di jaringan Docker), alamat IPv4 gaya lama, dan proxy itu sendiri. `{proxy}` diganti dengan host:port proxy.
DENY_TARGETS = ("169.254.169.254:443", "127.0.0.1:443", "localhost:443", "[::1]:443", "10.0.0.1:443", "redis:6379", "web:8000", "{proxy}",
                "metadata.google.internal:443", "2130706433:443")


def direct(host: str, port: int, timeout: float = 4.0) -> str:
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return "CONNECTED"
    except socket.timeout:
        return "ERRNO TIMEOUT"
    except OSError as exc:
        return "ERRNO " + (errno.errorcode.get(exc.errno, str(exc.errno)) if exc.errno else type(exc).__name__)


def resolve(name: str) -> str:
    try:
        return "RESOLVED " + socket.getaddrinfo(name, None)[0][4][0]
    except OSError:
        return "NXDOMAIN"


def connect(proxy_host: str, proxy_port: int, target: str, timeout: float = 6.0) -> str:
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    except OSError as exc:
        return "NOPROXY " + (errno.errorcode.get(exc.errno, "?") if exc.errno else type(exc).__name__)
    try:
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii", "replace"))
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except OSError as exc:
        return "NORESPONSE " + type(exc).__name__
    finally:
        sock.close()
    lines = data.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    status = parts[1] if len(parts) > 1 and parts[1].isdigit() else "?"
    reason = next((ln.split(":", 1)[1].strip() for ln in lines[1:] if ln.lower().startswith("x-egress-reason:")), "")
    return f"STATUS {status} REASON {reason}"


def main(argv: list[str]) -> int:
    mode = argv[0] if argv else ""
    if mode == "direct" and len(argv) == 3:
        print(direct(argv[1], int(argv[2])))
    elif mode == "resolve" and len(argv) == 2:
        print(resolve(argv[1]))
    elif mode == "connect" and len(argv) == 4:
        print(connect(argv[1], int(argv[2]), argv[3]))
    else:
        print("pemakaian: direct HOST PORT | resolve NAMA | connect PROXY_HOST PROXY_PORT TARGET", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
