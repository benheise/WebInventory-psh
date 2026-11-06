#!/usr/bin/env python3
"""Benchmark web farm for Invoke-WebInventory.ps1 (loopback only).

Serves N hosts on 127.0.10.1..N, each with four services, plus silent tarpits on 127.0.11.1..M:
  19080  nginx-style corporate page (~8 KB)        19081  WordPress/PHP page (~35 KB, cookies, generator)
  19082  single-page app (~125 KB, many scripts)    19443  TLS + ALPN, Jenkins-style redirect to /login
  127.0.11.x:19090/19091  accept and never answer (tarpit / SYN-proxy firewall behaviour)
Content is deterministic per host so two scans can be compared field by field.
Set FARM_LOG=<file> to log every request as "ip port method path host" (for duplicate-request analysis).
"""
import asyncio, os, socketserver, ssl, sys, threading, time

CERTS = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 50
M = int(sys.argv[3]) if len(sys.argv) > 3 else 20
LOG = os.environ.get("FARM_LOG")
BASE = os.environ.get("FARM_BASE", "127.0.10")
PITBASE = os.environ.get("FARM_PITS", "127.0.11")
logbuf = []


def resp(code, reason, headers, body):
    if isinstance(body, str):
        body = body.encode()
    h = "HTTP/1.1 %d %s\r\n" % (code, reason)
    headers = headers + [("Content-Length", str(len(body))), ("Connection", "close")]
    h += "".join("%s: %s\r\n" % (k, v) for k, v in headers)
    return h.encode("latin-1") + b"\r\n" + body


LOREM = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore "
         "magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo. ")
FAV = bytes((i * 7) % 256 for i in range(1150))


def corp(i):
    ver = "1.%d.%d" % (18 + i % 7, i % 3)
    body = ('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Corp Intranet %d</title>'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<link rel="icon" href="/favicon.ico"><link rel="stylesheet" href="/css/site.css">'
            '<script src="/js/jquery-3.6.%d.min.js"></script></head><body><header><nav>' % (i, i % 5) +
            "".join('<a href="/section/%d">Section %d</a>' % (k, k) for k in range(20)) +
            '</nav></header><main>' + ("<p>%s</p>" % LOREM) * 50 + '</main><footer>&copy; Corp</footer></body></html>')
    hdr = [("Server", "nginx/" + ver), ("Content-Type", "text/html; charset=utf-8"), ("X-Frame-Options", "SAMEORIGIN")]

    def route(m, p, h):
        if p == "/":
            return resp(200, "OK", hdr, body)
        if p == "/favicon.ico":
            return resp(200, "OK", [("Server", "nginx/" + ver), ("Content-Type", "image/x-icon")], FAV)
        if p == "/robots.txt" and i % 2 == 0:
            return resp(200, "OK", [("Server", "nginx/" + ver), ("Content-Type", "text/plain")], "User-agent: *\nDisallow: /private\n")
        return resp(404, "Not Found", [("Server", "nginx/" + ver), ("Content-Type", "text/html")],
                    "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/%s</center></body></html>" % ver)
    return route


def wordpress(i):
    wp = "6.%d.%d" % (i % 5, i % 3)
    php = ["PHP/8.1.%d" % (2 + i % 20), "PHP/7.4.33", "PHP/8.3.%d" % (i % 12), "PHP/8.2.%d" % (10 + i % 9)][i % 4]
    posts = "".join('<article class="post"><h2><a href="/?p=%d">Post %d</a></h2><div class="entry-content"><p>%s</p><p>%s</p></div></article>'
                    % (k, k, LOREM, LOREM) for k in range(60))
    body = ('<!DOCTYPE html><html lang="en-US"><head><meta charset="UTF-8"><title>Team Blog %d &#8211; Just another WordPress site</title>'
            '<meta name="generator" content="WordPress %s">'
            "<link rel='stylesheet' id='wp-block-library-css' href='/wp-includes/css/dist/block-library/style.min.css?ver=%s' media='all' />"
            "<script src='/wp-includes/js/jquery/jquery.min.js?ver=3.7.1' id='jquery-core-js'></script>"
            "<script src='/wp-content/themes/twentytwentyfour/assets/js/theme.js?ver=1.%d'></script>"
            '<link rel="https://api.w.org/" href="/wp-json/"></head><body class="home blog">' % (i, wp, wp, i % 4) + posts + '</body></html>')
    hdr = [("Server", "Apache/2.4.%d (Ubuntu)" % (41 + i % 17)), ("X-Powered-By", php), ("Content-Type", "text/html; charset=UTF-8"),
           ("Link", '</wp-json/>; rel="https://api.w.org/"'), ("Set-Cookie", "wordpress_test_cookie=WP%20Cookie%20check; path=/")]

    def route(m, p, h):
        if p == "/":
            return resp(200, "OK", hdr, body)
        if p == "/robots.txt":
            return resp(200, "OK", [("Content-Type", "text/plain")], "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\nSitemap: /wp-sitemap.xml\n")
        return resp(404, "Not Found", hdr[:3], "<html><head><title>Page not found &#8211; Team Blog</title></head><body>" + ("<p>%s</p>" % LOREM) * 8 + "</body></html>")
    return route


def spa(i):
    libs = ["/static/js/react-18.2.0.production.min.js", "/static/js/react-dom-18.2.0.production.min.js", "/static/js/lodash-4.17.%d.min.js" % (15 + i % 6),
            "/static/js/moment-2.29.%d.min.js" % (i % 5), "/static/js/axios-1.%d.0.min.js" % (i % 6), "/static/js/bootstrap-5.%d.3.bundle.min.js" % (i % 3),
            "https://cdn.jsdelivr.net/npm/chart.js@4.%d.0/dist/chart.umd.min.js" % (i % 4), "/static/js/main.%08x.chunk.js" % (i * 2654435761 % 2 ** 32)]
    state = "{" + ",".join('"item%d":{"id":%d,"name":"Widget %d","desc":"%s"}' % (k, k, k, LOREM[:90]) for k in range(850)) + "}"
    body = ('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Ops Console %d</title>'
            '<meta name="description" content="Operations console"><meta name="theme-color" content="#000000">'
            '<link rel="manifest" href="/manifest.json"><link rel="icon" href="/static/favicon-32.png">' % i +
            "".join('<script defer src="%s"></script>' % s for s in libs) +
            '<link href="/static/css/main.%08x.css" rel="stylesheet"></head><body><noscript>You need to enable JavaScript to run this app.</noscript>'
            '<div id="root"></div><script>window.__INITIAL_STATE__=%s;</script></body></html>' % (i, state))
    hdr = [("Content-Type", "text/html"), ("X-Powered-By", "Express"), ("ETag", 'W/"%x"' % (i * 977)),
           ("Set-Cookie", "connect.sid=s%%3A%04d; Path=/; HttpOnly" % i)]

    def route(m, p, h):
        if p == "/":
            return resp(200, "OK", hdr, body)
        if p == "/static/favicon-32.png":
            return resp(200, "OK", [("Content-Type", "image/png")], FAV[:600])
        return resp(404, "Not Found", [("Content-Type", "text/html"), ("X-Powered-By", "Express")], "<!DOCTYPE html><html><head><title>Error</title></head><body><pre>Cannot GET %s</pre></body></html>" % "/")
    return route


def jenkins(i):
    ver = "2.%d.%d" % (400 + i % 40, 1 + i % 3)
    hdr = [("X-Jenkins", ver), ("X-Hudson", "1.395"), ("Server", "Jetty(10.0.%d)" % (13 + i % 5)), ("Content-Type", "text/html;charset=utf-8"),
           ("X-Content-Type-Options", "nosniff")]

    def route(m, p, h):
        if p == "/":
            return resp(302, "Found", hdr + [("Location", "/login?from=%2F")], "")
        if p.startswith("/login"):
            return resp(200, "OK", hdr + [("Set-Cookie", "JSESSIONID.%04x=node0abc; Path=/; Secure; HttpOnly" % i)],
                        '<!DOCTYPE html><html><head><title>Sign in [Jenkins]</title><link rel="icon" href="/favicon.ico"></head><body>'
                        '<form method="post" action="j_spring_security_check"><input name="j_username"><input type="password" name="j_password"></form>'
                        + ("<p>%s</p>" % LOREM) * 10 + '</body></html>')
        if p == "/favicon.ico":
            return resp(200, "OK", [("Content-Type", "image/x-icon")], FAV[100:900])
        return resp(404, "Not Found", hdr, "<html><head><title>Error 404 Not Found</title></head><body><h2>HTTP ERROR 404 Not Found</h2></body></html>")
    return route


async def read_request(reader):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = await asyncio.wait_for(reader.read(4096), 10)
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


def http_handler(router, ip, port):
    async def handle(reader, writer):
        try:
            m, p, h = await read_request(reader)
            if not m:
                return
            if LOG:
                logbuf.append("%s %d %s %s %s\n" % (ip, port, m, p, h.get("host", "")))
            if m == "OPTIONS":
                writer.write(resp(200, "OK", [("Allow", "GET, HEAD, POST, OPTIONS")], ""))
            else:
                writer.write(router(m, p, h))
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
    return handle


def tarpit_handler(ip, port):
    async def handle(reader, writer):
        if LOG:
            logbuf.append("%s %d CONNECT - -\n" % (ip, port))
        try:
            async def drain():
                while await reader.read(65536):   # read and discard until the client gives up; never answer
                    pass
            await asyncio.wait_for(drain(), 120)
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
    return handle


class _TS(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256


def threaded_tls(ip, port, router, ctx):
    """TLS listeners use blocking sockets in threads (asyncio's TLS transport proved unreliable under load)."""
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            try:
                sock.settimeout(10)
                sock = ctx.wrap_socket(sock, server_side=True)
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
                lines = head.split("\r\n"); parts = lines[0].split(" ")
                if len(parts) < 2:
                    return
                h = {}
                for l in lines[1:]:
                    if ":" in l:
                        k, v = l.split(":", 1); h[k.strip().lower()] = v.strip()
                if LOG:
                    logbuf.append("%s %d %s %s %s\n" % (ip, port, parts[0], parts[1], h.get("host", "")))
                if parts[0] == "OPTIONS":
                    sock.sendall(resp(200, "OK", [("Allow", "GET, HEAD, POST, OPTIONS")], ""))
                else:
                    sock.sendall(router(parts[0], parts[1], h))
            except Exception:
                pass
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
    srv = _TS((ip, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


async def flush_log():
    while True:
        await asyncio.sleep(0.5)
        if logbuf:
            n = len(logbuf); chunk = "".join(logbuf[:n]); del logbuf[:n]
            with open(LOG, "a") as f:
                f.write(chunk)


async def main():
    loop = asyncio.get_running_loop()
    if os.environ.get("FARM_EXC"):
        def exc(l, c):
            with open(os.environ["FARM_EXC"], "a") as f:
                f.write("%.3f %s %r %r\n" % (time.time(), c.get("message"), c.get("exception"), c.get("transport") or c.get("protocol")))
        loop.set_exception_handler(exc)
    else:
        loop.set_exception_handler(lambda l, c: None)   # aborted handshakes from the raw TLS probes are expected
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERTS, "lab.pem"), os.path.join(CERTS, "lab.key"))
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    servers = []
    for i in range(1, N + 1):
        ip = "%s.%d" % (BASE, i)
        for port, router in ((19080, corp(i)), (19081, wordpress(i)), (19082, spa(i))):
            servers.append(await asyncio.start_server(http_handler(router, ip, port), ip, port, backlog=256))
        threaded_tls(ip, 19443, jenkins(i), ctx)
    for i in range(1, M + 1):
        ip = "%s.%d" % (PITBASE, i)
        for port in (19090, 19091):
            servers.append(await asyncio.start_server(tarpit_handler(ip, port), ip, port, backlog=256))
    if LOG:
        asyncio.ensure_future(flush_log())
    print("farm up: %d web hosts x 4 services, %d tarpit hosts x 2" % (N, M), flush=True)
    await asyncio.Event().wait()


asyncio.run(main())
