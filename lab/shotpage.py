#!/usr/bin/env python3
"""Page with third-party references for -Screenshot scope tests (127.0.0.1 only):
/ loads a same-origin image plus resources from other origins (which the scope proxy must refuse).
   shotpage.py <port> [cert.pem key.pem]   (with a certificate: HTTPS, HTTP/1.1 only)"""
import http.server, ssl, sys
PORT = int(sys.argv[1])
PAGE = b"""<!doctype html><html><head><title>Shot test</title>
<link rel="stylesheet" href="https://fonts.example.net/css?family=Lab">
<script src="http://cdn.example.org/lib.js"></script></head>
<body style="background:#1d4ed8;color:#fff;font:48px sans-serif"><h1>WebInventory screenshot test</h1>
<img src="/local.svg" width="200"><img src="http://127.0.0.1:18999/other-port.png"><img src="https://tracker.example.com/pixel.gif">
<iframe src="http://203.0.113.10/"></iframe></body></html>"""
SVG = b"""<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100"><rect width="200" height="100" fill="#f59e0b"/></svg>"""
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body, ct = (SVG, "image/svg+xml") if self.path == "/local.svg" else (PAGE, "text/html")
        self.send_response(200); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a):
        sys.stderr.write("%s %s\n" % (self.client_address[0], self.requestline))
srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H)
if len(sys.argv) > 3:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[2], sys.argv[3]); ctx.set_alpn_protocols(["http/1.1"])
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
