#!/usr/bin/env python3
"""Fake legacy TLS endpoint: TLS 1.0 only, picks 3DES (0x000A) when offered, sends ServerHello+Certificate+ServerHelloDone.
Exercises the raw ClientHello parser and weak-cipher detection without needing a legacy OpenSSL build."""
import socket, ssl, struct, sys, threading, os

pem = open(sys.argv[1]).read()
DER = ssl.PEM_cert_to_DER_cert(pem)
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 18447


def rec(ct, ver, body):
    return bytes([ct]) + struct.pack(">HH", ver, len(body)) + body


def hs(t, body):
    return bytes([t]) + struct.pack(">I", len(body))[1:] + body


def handle(c):
    try:
        c.settimeout(5)
        hdr = c.recv(5)
        if len(hdr) < 5 or hdr[0] != 0x16:
            c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        ln = struct.unpack(">H", hdr[3:5])[0]
        data = b""
        while len(data) < ln:
            d = c.recv(ln - len(data))
            if not d:
                return
            data += d
        body = data[4:]
        cver = struct.unpack(">H", body[0:2])[0]
        p = 2 + 32
        sl = body[p]; p += 1 + sl
        cl = struct.unpack(">H", body[p:p + 2])[0]; p += 2
        suites = [struct.unpack(">H", body[p + i:p + i + 2])[0] for i in range(0, cl, 2)]
        if cver < 0x0301 or 0x000A not in suites:
            c.sendall(rec(0x15, 0x0301, bytes([2, 40])))      # handshake_failure
            return
        sh = struct.pack(">H", 0x0301) + os.urandom(32) + b"\x00" + struct.pack(">H", 0x000A) + b"\x00"
        cert = struct.pack(">I", len(DER))[1:] + DER
        certs = struct.pack(">I", len(cert))[1:] + cert
        msgs = hs(2, sh) + hs(11, certs) + hs(14, b"")
        c.sendall(rec(0x16, 0x0301, msgs))
        try:
            c.recv(1024)
        except Exception:
            pass
    except Exception:
        pass
    finally:
        c.close()


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
s.listen(50)
print("faketls up", PORT, flush=True)
while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
