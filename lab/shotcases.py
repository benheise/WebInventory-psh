#!/usr/bin/env python3
"""Screenshot-check cases for -Screenshot (127.0.0.1 only): one port per case, from <base> to <base>+7.
   +0 ok page | +1 empty 200 body | +2 white page whose content needs a third-party script | +3 302 to another host
   +4 503 to a headless browser, 200 to the scanner | +5 and +6 the same rendered page under two titles
   +7 a script renames the page after load
   shotcases.py <base port>"""
import http.server, sys, threading
BASE = int(sys.argv[1])
OK = b"""<!doctype html><html><head><title>Shot ok</title></head><body style="background:#1d4ed8;color:#fff;font:40px sans-serif">
<h1>Inventory screenshot check</h1><p>Plain page with text and colour.</p></body></html>"""
WHITE = b"""<!doctype html><html><head><title>App shell</title><script src="http://cdn.example.org/app.js"></script></head>
<body style="background:#fff"><div id="app" style="display:none">Loading the application</div></body></html>"""
TWIN = b"""<!doctype html><html><head><title>%s</title></head><body style="background:#065f46;color:#fff;font:40px sans-serif">
<h1>Shared error page</h1><p>Upstream unavailable.</p></body></html>"""
RENAME = b"""<!doctype html><html><head><title>Grafana</title></head><body style="font:32px sans-serif"><h1>Dashboard</h1>
<script>document.title = 'Proxy Error';</script></body></html>"""
def handler(case):
    class H(http.server.BaseHTTPRequestHandler):
        def send(self, code, body, ct="text/html", extra=()):
            self.send_response(code); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(body)))
            for k, v in extra: self.send_header(k, v)
            self.end_headers(); self.wfile.write(body)
        def do_GET(self):
            ua = self.headers.get("User-Agent", "")
            if self.path != "/":
                return self.send(404, b"not found", "text/plain")
            if case == 0: return self.send(200, OK)
            if case == 1: return self.send(200, b"")
            if case == 2: return self.send(200, WHITE)
            if case == 3: return self.send(302, b"", extra=(("Location", "http://login.example.com/sso"),))
            if case == 4:
                if "HeadlessChrome" in ua: return self.send(503, b"<html><body><h1>Service Unavailable</h1><p>busy</p></body></html>")
                return self.send(200, OK.replace(b"Shot ok", b"Busy app"))
            if case in (5, 6): return self.send(200, TWIN % (b"Portal A" if case == 5 else b"Portal B"))
            if case == 7: return self.send(200, RENAME)
        def log_message(self, *a): sys.stderr.write("%d %s %s\n" % (case, self.requestline, self.headers.get("User-Agent", "")[:40]))
    return H
for i in range(8):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", BASE + i), handler(i))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
threading.Event().wait()
