"""Sandbox-side probe for the live egress test. Prints one JSON object.

usage: egress_client.py MODE PROXY_IP HOST [CA_FILE] [EXTRA]
  connect  CONNECT HOST:443 through PROXY_IP:3128, then TLS (SNI=HOST) + GET /
  http     plain GET http://HOST/ through PROXY_IP:3128
  sni      TLS straight to PROXY_IP:10443 with SNI=HOST + GET /
  front    TLS to PROXY_IP:10443 with SNI=HOST but Host header EXTRA
  direct   bypass the proxy: resolve HOST, then TCP to EXTRA (ip) port 443
  poll     repeat `connect` every 50 ms until it succeeds (EXTRA=until-denied:
           until it fails) or 30 s pass
"""

import json
import socket
import ssl
import sys
import time

TIMEOUT = 5


def tls_get(sock, host, ca, header_host=None):
    ctx = ssl.create_default_context(cafile=ca)
    with ctx.wrap_socket(sock, server_hostname=host) as tls:
        tls.sendall(f"GET / HTTP/1.1\r\nHost: {header_host or host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while chunk := tls.recv(4096):
            data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    return {"status": int(head.split()[1]), "body": body.decode().strip()}


def connect(proxy, host, ca):
    sock = socket.create_connection((proxy, 3128), timeout=TIMEOUT)
    sock.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("proxy closed during CONNECT")
        head += chunk
    status = int(head.split()[1])
    if status != 200:
        rest = sock.recv(4096).decode(errors="replace").strip()
        sock.close()
        return {"ok": False, "proxy_status": status, "body": rest}
    out = tls_get(sock, host, ca)
    return {"ok": out["status"] == 200, "proxy_status": 200, **out}


def http(proxy, host):
    sock = socket.create_connection((proxy, 3128), timeout=TIMEOUT)
    sock.sendall(f"GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while chunk := sock.recv(4096):
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split()[1])
    return {"ok": status == 200, "status": status, "body": body.decode().strip()}


def sni(proxy, host, ca, header_host=None):
    sock = socket.create_connection((proxy, 10443), timeout=TIMEOUT)
    out = tls_get(sock, host, ca, header_host)
    return {"ok": out["status"] == 200, **out}


def direct(host, ip):
    result = {"ok": False}
    try:
        result["resolved"] = socket.gethostbyname(host)
    except OSError as e:
        result["resolve_error"] = type(e).__name__
    try:
        socket.create_connection((ip, 443), timeout=3).close()
        result["ok"] = True
    except OSError as e:
        result["connect_error"] = f"{type(e).__name__}: {e}"
    return result


def main():
    mode, proxy, host = sys.argv[1:4]
    ca = sys.argv[4] if len(sys.argv) > 4 else None
    extra = sys.argv[5] if len(sys.argv) > 5 else None
    try:
        if mode == "connect":
            out = connect(proxy, host, ca)
        elif mode == "http":
            out = http(proxy, host)
        elif mode == "sni":
            out = sni(proxy, host, ca)
        elif mode == "front":
            out = sni(proxy, host, ca, extra)
        elif mode == "direct":
            out = direct(host, extra)
        elif mode == "poll":
            want = extra != "until-denied"
            start, attempts, out = time.time(), 0, {}
            print(json.dumps({"polling_since": start}), flush=True)
            while time.time() - start < 30:
                attempts += 1
                try:
                    out = connect(proxy, host, ca)
                except (OSError, ssl.SSLError) as e:
                    out = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                if bool(out.get("ok")) == want:
                    break
                time.sleep(0.05)
            out.update({"attempts": attempts, "succeeded_at": time.time()})
        else:
            raise SystemExit(f"unknown mode {mode}")
    except (OSError, ssl.SSLError, ValueError, IndexError) as e:
        out = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    print(json.dumps(out), flush=True)


if __name__ == "__main__":
    main()
