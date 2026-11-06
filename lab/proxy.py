#!/usr/bin/env python3
"""HTTP CONNECT proxy for lab tests of -Proxy (binds 127.0.0.1 only). Squid-like answers:
200 after the target accepted, 503 + X-Squid-Error ERR_CONNECT_FAIL 111 on refused, ... 110 on timeout,
407 when -auth is set and Proxy-Authorization is missing/wrong, 403 for ports in -deny.
   proxy.py <port> [--auth user:pass] [--deny 22,25] [--timeout 3] [--log file]
"""
import argparse, base64, socket, threading, time

ap = argparse.ArgumentParser()
ap.add_argument("port", type=int)
ap.add_argument("--auth")
ap.add_argument("--deny", default="")
ap.add_argument("--timeout", type=float, default=3.0)
ap.add_argument("--log")
a = ap.parse_args()
deny = {int(x) for x in a.deny.split(",") if x}
lock = threading.Lock()
stats = {"connect": 0, "ok": 0, "refused": 0, "timeout": 0, "denied": 0, "auth": 0}


def log(msg):
    if a.log:
        with lock, open(a.log, "a") as f:
            f.write("%.3f %s\n" % (time.time(), msg))


def pipe(src, dst):
    try:
        while True:
            b = src.recv(65536)
            if not b:
                break
            dst.sendall(b)
    except OSError:
        pass
    for s in (dst, src):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def handle(c):
    try:
        c.settimeout(10)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 16384:
            ch = c.recv(4096)
            if not ch:
                return
            data += ch
        head, rest = data.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        method, target, _ = (lines[0].split(" ") + ["", "", ""])[:3]
        hdrs = {l.split(":", 1)[0].strip().lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
        with lock:
            stats["connect"] += 1
        if method != "CONNECT":
            c.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            return
        if a.auth:
            want = "Basic " + base64.b64encode(a.auth.encode()).decode()
            if hdrs.get("proxy-authorization") != want:
                with lock:
                    stats["auth"] += 1
                log("407 %s" % target)
                c.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="lab"\r\nContent-Length: 0\r\n\r\n')
                return
        host, _, port = target.rpartition(":")
        host = host.strip("[]")
        port = int(port)
        if port in deny:
            with lock:
                stats["denied"] += 1
            log("403 %s" % target)
            c.sendall(b"HTTP/1.1 403 Forbidden\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\nContent-Length: 0\r\n\r\n")
            return
        fam = socket.AF_INET6 if ":" in host else socket.AF_INET
        u = socket.socket(fam, socket.SOCK_STREAM)
        u.settimeout(a.timeout)
        try:
            u.connect((host, port))
        except socket.timeout:
            with lock:
                stats["timeout"] += 1
            log("503-110 %s" % target)
            c.sendall(b"HTTP/1.1 503 Service Unavailable\r\nX-Squid-Error: ERR_CONNECT_FAIL 110\r\nContent-Length: 0\r\n\r\n")
            u.close()
            return
        except OSError as e:
            with lock:
                stats["refused"] += 1
            log("503-%s %s" % (getattr(e, "errno", 0), target))
            c.sendall(("HTTP/1.1 503 Service Unavailable\r\nX-Squid-Error: ERR_CONNECT_FAIL %d\r\nContent-Length: 0\r\n\r\n" % (e.errno or 111)).encode())
            u.close()
            return
        with lock:
            stats["ok"] += 1
        log("200 %s" % target)
        u.settimeout(None)
        c.settimeout(None)
        c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        if rest:
            u.sendall(rest)
        t = threading.Thread(target=pipe, args=(u, c), daemon=True)
        t.start()
        pipe(c, u)
        t.join(30)
        u.close()
    except Exception as e:
        log("error %r" % e)
    finally:
        try:
            c.close()
        except OSError:
            pass


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", a.port))
s.listen(512)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
