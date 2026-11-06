#!/usr/bin/env python3
"""Minimal DNS responder for -Cname tests (127.0.0.1 only): answers A queries with a CNAME chain and an A record.
   fakedns.py <port> name=target1,target2 [name2=...]   (unknown names: NXDOMAIN)"""
import socket, struct, sys
PORT = int(sys.argv[1])
TAB = {}
for a in sys.argv[2:]:
    n, _, t = a.partition('=')
    TAB[n.lower().rstrip('.')] = [x for x in t.split(',') if x]
def enc(name):
    return b''.join(bytes([len(l)]) + l.encode() for l in name.rstrip('.').split('.')) + b'\0'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', PORT))
while True:
    q, peer = s.recvfrom(1500)
    p = 12; labels = []
    while q[p]:
        labels.append(q[p + 1:p + 1 + q[p]].decode()); p += 1 + q[p]
    name = '.'.join(labels).lower(); qend = p + 5
    chain = TAB.get(name)
    if chain is None:
        r = q[:2] + b'\x81\x83' + b'\0\1\0\0\0\0\0\0' + q[12:qend]
    else:
        ans = b''; owner = enc(name)
        for t in chain:
            rd = enc(t); ans += owner + struct.pack('>HHIH', 5, 1, 60, len(rd)) + rd; owner = rd
        ans += owner + struct.pack('>HHIH', 1, 1, 60, 4) + bytes([127, 0, 0, 1])
        r = q[:2] + b'\x81\x80' + struct.pack('>HHHH', 1, len(chain) + 1, 0, 0) + q[12:qend] + ans
    s.sendto(r, peer)
    sys.stderr.write('%s %s\n' % (name, chain)); sys.stderr.flush()
