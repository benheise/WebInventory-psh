#!/usr/bin/env python3
"""Minimal RDP listener for lab tests of -Rdp (127.0.0.1 only). Answers the X.224 connection request, does TLS, and
answers a CredSSP TSRequest with an NTLM CHALLENGE (no authentication is ever completed).
   fakerdp.py <port> <mode: nla|tls|legacy|rdponly> <cert.pem> <key.pem> [--build 20348] [--name RDPHOST01]
nla      SSL|HYBRID offered; HYBRID chosen; TLS-only or standard RDP requests get HYBRID_REQUIRED_BY_SERVER (5)
tls      SSL chosen when offered, standard RDP security accepted when asked for alone (no NLA)
legacy   connection confirm without negotiation data (pre-RDP 5.2 servers)
rdponly  only standard RDP security: TLS/HYBRID requests get SSL_NOT_ALLOWED_BY_SERVER (2)
--tls10  the TLS layer speaks TLS 1.0 only (an old RDP server; a scanner host with TLS 1.0 disabled cannot handshake)
"""
import argparse, socket, ssl, struct, threading, time

ap = argparse.ArgumentParser()
ap.add_argument("port", type=int)
ap.add_argument("mode", choices=["nla", "tls", "legacy", "rdponly"])
ap.add_argument("cert")
ap.add_argument("key")
ap.add_argument("--build", type=int, default=20348)
ap.add_argument("--name", default="RDPHOST01")
ap.add_argument("--domain", default="LAB")
ap.add_argument("--dnsdomain", default="lab.test")
ap.add_argument("--tls10", action="store_true")
a = ap.parse_args()

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(a.cert, a.key)
if a.tls10:
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError
        b += c
    return b


def der(tag, content):
    n = len(content)
    if n < 128:
        l = bytes([n])
    elif n < 256:
        l = bytes([0x81, n])
    else:
        l = bytes([0x82, n >> 8, n & 255])
    return bytes([tag]) + l + content


def av(id_, s):
    v = s.encode("utf-16-le")
    return struct.pack("<HH", id_, len(v)) + v


def challenge():
    ti = av(2, a.domain) + av(1, a.name) + av(4, a.dnsdomain) + av(3, a.name.lower() + "." + a.dnsdomain) + av(5, a.dnsdomain)
    ti += struct.pack("<HHQ", 7, 8, 133000000000000000) + struct.pack("<HH", 0, 0)
    tn = a.domain.encode("utf-16-le")
    off = 56
    hdr = b"NTLMSSP\0" + struct.pack("<I", 2)
    hdr += struct.pack("<HHI", len(tn), len(tn), off)
    hdr += struct.pack("<I", 0xE28A8215)
    hdr += b"\x11" * 8 + b"\0" * 8
    hdr += struct.pack("<HHI", len(ti), len(ti), off + len(tn))
    hdr += bytes([10, 0]) + struct.pack("<H", a.build) + b"\0\0\0\x0f"
    return hdr + tn + ti


def confirm(selected=None, failure=None):
    if failure is not None:
        neg = struct.pack("<BBHI", 3, 0, 8, failure)
    elif selected is not None:
        neg = struct.pack("<BBHI", 2, 0x1f, 8, selected)
    else:
        neg = b""
    x224 = bytes([6 + len(neg), 0xD0, 0, 0, 0x12, 0x34, 0]) + neg
    return struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224


def handle(c):
    try:
        c.settimeout(10)
        h = recv_exact(c, 4)
        body = recv_exact(c, struct.unpack(">H", h[2:4])[0] - 4)
        req = 0
        i = body.find(b"\x01\x00\x08\x00")
        if i >= 0 and i + 8 <= len(body):
            req = struct.unpack("<I", body[i + 4:i + 8])[0]
        if a.mode == "legacy":
            c.sendall(confirm())
            time.sleep(0.2)
            return
        if a.mode == "rdponly":
            if req & 3:
                c.sendall(confirm(failure=2))
            else:
                c.sendall(confirm(selected=0))
            time.sleep(0.2)
            return
        if a.mode == "nla":
            if req & 2:
                sel = 2
            else:
                c.sendall(confirm(failure=5))
                time.sleep(0.2)
                return
        else:  # tls
            sel = 1 if req & 1 else 0
        c.sendall(confirm(selected=sel))
        if sel == 0:
            time.sleep(0.2)
            return
        t = ctx.wrap_socket(c, server_side=True)
        if sel == 2:
            data = t.recv(8192)
            if data[:1] == b"\x30":
                ts = der(0x30, der(0xA0, der(0x02, b"\x06")) + der(0xA1, der(0x30, der(0x30, der(0xA0, der(0x04, challenge()))))))
                t.sendall(ts)
                try:
                    t.recv(8192)    # the client stops here; nothing more is answered
                except Exception:
                    pass
        else:
            time.sleep(0.2)
        t.close()
    except Exception:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", a.port))
s.listen(64)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
