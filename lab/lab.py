#!/usr/bin/env python3
"""Local lab of fake services for exercising Invoke-WebInventory.ps1 (binds 127.0.0.1 only)."""
import os, socket, socketserver, ssl, struct, sys, threading, time

CERTS = sys.argv[1]
HERE = os.path.dirname(os.path.abspath(__file__))
FAVICON = bytes(range(256)) * 3          # same vector as the self-test (mmh3 1836528006)
ESC = chr(27)


def resp(code, reason, headers, body):
    if isinstance(body, str):
        body = body.encode()
    h = "HTTP/1.1 %d %s\r\n" % (code, reason)
    names = [k.lower() for k, _ in headers]
    if "content-length" not in names:
        headers = headers + [("Content-Length", str(len(body)))]
    headers = headers + [("Connection", "close")]
    h += "".join("%s: %s\r\n" % (k, v) for k, v in headers)
    return h.encode("latin-1") + b"\r\n" + body


def read_request(sock):
    data = b""
    sock.settimeout(5)
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("", "/")
    hdrs = {}
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return method, path, hdrs


# ---------------------------------------------------------------- route tables
def iis(method, path, h):
    if path == "/":
        return resp(200, "OK", [("Server", "Microsoft-IIS/10.0"), ("X-Powered-By", "ASP.NET"), ("X-AspNet-Version", "4.0.30319"),
                                ("Set-Cookie", "ASP.NET_SessionId=abc123; path=/"), ("Content-Type", "text/html; charset=utf-8")],
                    '<html><head><title>IIS Windows Server</title><link rel="shortcut icon" href="/static/fav.ico">'
                    '<script src="/scripts/jquery-1.12.4.min.js"></script></head><body><img src="iisstart.png"></body></html>')
    if path == "/static/fav.ico":
        return resp(200, "OK", [("Server", "Microsoft-IIS/10.0"), ("Content-Type", "image/x-icon")], FAVICON)
    if path == "/robots.txt":
        return resp(200, "OK", [("Content-Type", "text/plain")], "User-agent: *\nDisallow: /admin\nDisallow: /backup\nSitemap: /sitemap.xml\n")
    if path == "/.well-known/security.txt":
        return resp(200, "OK", [("Content-Type", "text/plain")], "Contact: mailto:security@lab.test\nExpires: 2027-01-01T00:00:00Z\n")
    if path == "/certsrv/":
        return resp(401, "Unauthorized", [("Server", "Microsoft-IIS/10.0"), ("WWW-Authenticate", "Negotiate"), ("WWW-Authenticate", "NTLM")], "<html><head><title>401 - Unauthorized</title></head></html>")
    return resp(404, "Not Found", [("Server", "Microsoft-IIS/10.0"), ("Content-Type", "text/html")],
                "<html><head><title>IIS 10.0 Detailed Error - 404.0 - Not Found</title></head><body>IIS 10.0 Detailed Error</body></html>")


def redirect_to_tls(method, path, h):
    return resp(301, "Moved Permanently", [("Location", "https://127.0.0.1:18443/login"), ("Server", "nginx/1.18.0 (Ubuntu)")], "")


def tls_vhosts(method, path, h):
    host = h.get("host", "").split(":")[0]
    if host == "app1.lab.test":
        return resp(200, "OK", [("X-Jenkins", "2.401.3"), ("Server", "Jetty(10.0.13)"), ("Set-Cookie", "JSESSIONID.abc=1; Path=/; HttpOnly"), ("Content-Type", "text/html")],
                    "<html><head><title>Dashboard [Jenkins]</title></head><body>Jenkins</body></html>")
    if host == "app2.lab.test":
        return resp(200, "OK", [("Content-Type", "text/html"), ("Set-Cookie", "grafana_session=x; Path=/; HttpOnly; Secure")],
                    '<html><head><title>Grafana</title></head><body><script>window.grafanaBootData = {"settings":{"buildInfo":{"hideVersion":false,"version":"9.5.2","commit":"abc"}}};</script></body></html>')
    if path == "/login":
        return resp(200, "OK", [("Server", "nginx/1.18.0 (Ubuntu)"), ("Set-Cookie", "session=1; Path=/"), ("Content-Type", "text/html"),
                                ("Strict-Transport-Security", "max-age=31536000"), ("Alt-Svc", 'h3=":443"; ma=86400')],
                    '<html><head><title>Sign in</title></head><body><form><input type="password" name="p"></form></body></html>')
    if path == "/":
        return resp(200, "OK", [("Server", "nginx/1.18.0 (Ubuntu)"), ("Content-Type", "text/html")], "<html><head><title>Welcome to nginx!</title></head></html>")
    return resp(404, "Not Found", [("Server", "nginx/1.18.0 (Ubuntu)")], "<html><body><hr><center>nginx/1.18.0 (Ubuntu)</center></body></html>")


def tomcat(method, path, h):
    if path == "/":
        return resp(200, "OK", [("Content-Type", "text/html")], "<html><head><title>Apache Tomcat/9.0.65</title></head><body>If you're seeing this...</body></html>")
    return resp(404, "", [("Content-Type", "text/html")], "<html><body><h3>Apache Tomcat/9.0.65</h3></body></html>")


def basic_auth(method, path, h):
    return resp(401, "Unauthorized", [("WWW-Authenticate", 'Basic realm="Tomcat Manager Application"'), ("Server", "Apache-Coyote/1.1")], "")


def offhost(method, path, h):
    return resp(302, "Found", [("Location", "http://example.invalid/portal")], "")


def k8s(method, path, h):
    if path == "/version":
        return resp(200, "OK", [("Content-Type", "application/json")], '{"major":"1","minor":"27","gitVersion":"v1.27.4","platform":"linux/amd64"}')
    return resp(403, "Forbidden", [("Content-Type", "application/json")],
                '{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User \\"system:anonymous\\" cannot get path \\"/\\"","reason":"Forbidden","code":403}')


def blog(method, path, h):
    if path == "/":
        # hostile values: CSV formula, HTML injection and an ANSI escape in a header
        return resp(200, "OK", [("Server", "Apache/2.4.41 (Ubuntu)" + ESC + "[31m"), ("X-Powered-By", "PHP/7.4.3"), ("Content-Type", "text/html")],
                    '<html><head><title>=HYPERLINK("http://evil/","x") &lt;script&gt;</title><meta name="generator" content="WordPress 6.4.2">'
                    '<link rel="stylesheet" href="/wp-content/themes/t/style.css"></head><body>blog</body></html>')
    return resp(404, "Not Found", [("Server", "Apache/2.4.41 (Ubuntu)")], "<address>Apache/2.4.41 (Ubuntu) Server at lab Port 80</address>")


def rich(method, path, h):
    # client-side stack typical of an internal Node/SPA app; mentions DHL without being a store (gate must suppress it)
    return resp(200, "OK", [("X-Powered-By", "Express"), ("Set-Cookie", "connect.sid=s%3Aabc; Path=/; HttpOnly"), ("Content-Type", "text/html")],
                '<html><head><title>Ops Portal</title>'
                '<script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>'
                '<script src="/js/bootstrap-5.2.3.min.js"></script><script src="/js/react-18.2.0.min.js"></script>'
                '<script src="/js/moment.min.js"></script><script src="/js/lodash.min.js"></script>'
                '<script async src="https://www.googletagmanager.com/gtag/js?id=G-TEST123"></script>'
                '</head><body><div id="root"></div><p>Inbound freight arrives by DHL on Tuesdays.</p></body></html>')


def shop(method, path, h):
    return resp(200, "OK", [("Server", "Apache"), ("X-Powered-By", "PHP/8.1.2"), ("Link", '<https://shop.lab.test/wp-json/>; rel="https://api.w.org/"'),
                            ("Content-Type", "text/html; charset=UTF-8")],
                '<html><head><title>Lab Store</title><meta name="generator" content="WordPress 6.4.2"><meta name="generator" content="WooCommerce 8.2.1">'
                '<script src="/wp-content/plugins/woocommerce/assets/js/frontend/woocommerce.min.js?ver=8.2.1"></script></head>'
                '<body><p>Free shipping with DHL on orders over $50.</p></body></html>')


def php_host(server, powered_by, title, cookie=True):
    """Header-only PHP2Shell fixture: advertises a PHP build; no PHP runtime, no vulnerable code."""
    def route(method, path, h):
        hdrs = [("Content-Type", "text/html; charset=UTF-8")]
        if server:
            hdrs.append(("Server", server))
        if powered_by:
            hdrs.append(("X-Powered-By", powered_by))
        if cookie:
            hdrs.append(("Set-Cookie", "PHPSESSID=0123456789abcdef0123456789; path=/; HttpOnly"))
        if path == "/":
            return resp(200, "OK", hdrs, "<html><head><title>%s</title></head><body>index.php</body></html>" % title)
        return resp(404, "Not Found", hdrs, "<html><body>Not Found</body></html>")
    return route


# ---------------------------------------------------------------- servers
class Threading(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def http_server(port, router, tls_ctx=None, mismatch=False):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            try:
                if mismatch:
                    sock.settimeout(5)
                    first = sock.recv(1, socket.MSG_PEEK)
                    if first != b"\x16":
                        read_request(sock)
                        sock.sendall(resp(400, "Bad Request", [("Server", "nginx"), ("Content-Type", "text/html")],
                                          "<html><head><title>400 The plain HTTP request was sent to HTTPS port</title></head>"
                                          "<body><center><h1>400 Bad Request</h1></center><center>The plain HTTP request was sent to HTTPS port</center><hr><center>nginx</center></body></html>"))
                        return
                if tls_ctx:
                    sock = tls_ctx.wrap_socket(sock, server_side=True)
                m, p, h = read_request(sock)
                if not m:
                    return
                sock.sendall(router(m, p, h))
            except Exception:
                pass
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
    s = Threading(("127.0.0.1", port), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()


def banner_server(port, data, wait_for_input=False):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request.sendall(data)
                self.request.settimeout(3)
                try:
                    self.request.recv(1024)
                except Exception:
                    pass
            finally:
                self.request.close()
    s = Threading(("127.0.0.1", port), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()


def tarpit(port):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            time.sleep(30)
    s = Threading(("127.0.0.1", port), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()


def tls_ctx(alpn=True):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.load_cert_chain(os.path.join(CERTS, "lab.pem"), os.path.join(CERTS, "lab.key"))
    if alpn:
        c.set_alpn_protocols(["h2", "http/1.1"])
    return c


if __name__ == "__main__":
    http_server(18080, iis)
    http_server(18081, redirect_to_tls)
    http_server(18443, tls_vhosts, tls_ctx())
    http_server(18444, tomcat, tls_ctx(alpn=False), mismatch=True)
    http_server(18082, basic_auth)
    http_server(18085, offhost)
    http_server(18086, k8s)
    http_server(18089, blog)
    http_server(18090, rich)
    http_server(18091, shop)
    # PHP2Shell (CVE-2026-109618/109619) fixtures
    http_server(18092, php_host("Apache/2.4.58 (Ubuntu) PHP/8.3.6", "PHP/8.3.6", "Staff Portal"))        # vulnerable, mod_php
    http_server(18093, php_host("nginx/1.24.0", "PHP/8.4.27", "Patched App (php-fpm)"))                  # fixed release
    http_server(18094, php_host("Apache", "PHP/7.4.33", "Legacy App"))                                   # EOL branch
    http_server(18095, php_host("Apache/2.4.52 (Ubuntu)", "PHP/8.1.2-1ubuntu2.20", "Ubuntu 22.04 App"))  # EOL + distro build
    http_server(18096, php_host("nginx", None, "Hardened App"))                                          # expose_php=Off
    banner_server(18022, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    banner_server(18021, b"220 ProFTPD 1.3.5 Server (Debian) [::ffff:127.0.0.1]\r\n")
    ver = b"8.0.36-0ubuntu0.22.04.1"
    payload = b"\x0a" + ver + b"\x00" + struct.pack("<I", 9) + b"abcdefgh\x00" + b"\xff\xf7\x08\x02\x00"
    banner_server(18306, struct.pack("<I", len(payload))[:3] + b"\x00" + payload)
    tarpit(18087)
    # slow application (1.5 s think time): guards against timeout "optimizations" that drop real but slow apps
    def slow(method, path, h):
        time.sleep(1.5)
        return resp(200, "OK", [("Server", "Apache-Coyote/1.1"), ("Content-Type", "text/html")],
                    "<html><head><title>Slow Report Server</title></head><body>generated in 1500 ms</body></html>")
    http_server(18097, slow)
    print("lab up", flush=True)
    while True:
        time.sleep(3600)
