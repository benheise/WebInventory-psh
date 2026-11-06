#!/usr/bin/env python3
"""Synthetic scanner output for store tests: a sequence of runs exercising every history rule.

usage: gen.py <outdir> [--big N]   (writes <outdir>/runN/WebInventory_<RunId>.{jsonl,csv}, _progress.txt, _run.json)
"""
import json, os, sys, random, hashlib

COLUMNS = ['RunId', 'ScanTag', 'ScannedAt', 'Host', 'IP', 'Port', 'ReverseDns', 'Vhost', 'VhostOf', 'State', 'IsWeb', 'Service', 'Scheme', 'Url', 'FinalUrl',
    'StatusCode', 'Title', 'Server', 'PoweredBy', 'Generator', 'ContentType', 'BodyLength', 'BodySha256', 'ResponseMs', 'RedirectChain',
    'Auth', 'Cookies', 'CookieFlagIssues', 'MissingSecHeaders', 'HstsMaxAge', 'AltSvc',
    'Products', 'Technologies', 'Categories', 'CPEs', 'OsHint', 'Hardware',
    'FaviconPath', 'FaviconMmh3', 'FaviconMd5', 'Robots', 'SecurityTxt', 'AllowedMethods', 'RiskyMethods', 'IdentifiedPaths',
    'TlsVersion', 'TlsCipher', 'TlsKeyExchange', 'TlsSupported', 'TlsCiphersByVersion', 'TlsWeakCipher', 'Alpn', 'Http2',
    'CertSubject', 'CertIssuer', 'CertSANs', 'CertNotBefore', 'CertNotAfter', 'CertDaysLeft', 'CertSelfSigned', 'CertSigAlg',
    'CertKeyAlg', 'CertKeySize', 'CertSerial', 'CertSha1', 'CertSha256', 'CertPolicyErrors', 'CertChainStatus', 'CertSource',
    'Flags', 'Advisories', 'Banner', 'Notes']


def row(run, host, ip, port, **kw):
    r = {c: "" for c in COLUMNS}
    r.update(RunId=run, ScanTag="store-test", ScannedAt=kw.pop("at", "2026-10-01T10:00:00"), Host=host, IP=ip, Port=port, Vhost=False, State="open",
             IsWeb=True, ResponseMs=random.randint(1, 500), BodySha256=hashlib.sha256(os.urandom(8)).hexdigest(), BodyLength=random.randint(100, 9000))
    web = kw.pop("web", True)
    if web:
        tls = kw.pop("tls", False)
        sch = "https" if tls else "http"
        r.update(Scheme=sch, Service=sch, Url="%s://%s:%d/" % (sch, host, port), FinalUrl="%s://%s:%d/" % (sch, host, port), StatusCode=200, ContentType="text/html")
        if tls:
            r.update(TlsVersion="Tls12", TlsCipher="Aes256-256 Sha384", TlsSupported="TLS1.2,TLS1.3", Alpn="h2", Http2=True, CertSubject="CN=" + host,
                     CertIssuer="CN=Test CA", CertNotBefore="2026-01-01T00:00:00", CertNotAfter="2026-10-21T00:00:00", CertDaysLeft=20, CertSelfSigned=False,
                     CertSigAlg="sha256RSA", CertKeyAlg="RSA", CertKeySize=2048, CertSource="schannel")
    else:
        r.update(IsWeb=False, Url="tcp://%s:%d" % (ip, port), BodySha256="", BodyLength="", ResponseMs="")
    for k, v in kw.items():
        if k not in r:
            raise KeyError(k)
        r[k] = v
    return r


def csv_line(vals):
    out = []
    for v in vals:
        if v is True: v = "True"
        elif v is False: v = "False"
        out.append('"' + str(v).replace('"', '""') + '"')
    return ",".join(out)


def write_run(outdir, name, run_id, started, rows, checked, profile=None, complete=True, run_json=True):
    d = os.path.join(outdir, name)
    os.makedirs(d, exist_ok=True)
    b = os.path.join(d, "WebInventory_" + run_id)
    with open(b + ".jsonl", "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps({**r, "Detections": []}, separators=(",", ":")) + "\n")
    with open(b + ".csv", "w", encoding="utf-8-sig") as f:
        f.write(",".join('"%s"' % c for c in COLUMNS) + "\n")
        for r in rows:
            f.write(csv_line([r[c] for c in COLUMNS]) + "\n")
    with open(b + "_progress.txt", "w") as f:
        for c in checked:
            f.write(c + "\n")
    if run_json:
        p = {"tlsScan": True, "favicon": True, "extras": True, "options": False, "identifyPaths": False, "probeSans": True, "reverseDns": True}
        p.update(profile or {})
        info = {"format": 1, "runId": run_id, "startedAt": started, "finishedAt": started, "complete": complete, "synthesized": False,
                "scanner": "WebInventory test", "tag": "store-test", "operator": "TEST\\tester", "computer": "TESTHOST", "checks": len(checked),
                "profile": p, "sessions": []}
        with open(b + "_run.json", "w") as f:
            json.dump(info, f, indent=1)
    return d


def scenario(out):
    random.seed(7)
    T = "+00:00"
    def ck(*hips):
        return ["%s|%s|%d" % h for h in hips]
    base_checked = [("10.0.0.1", "10.0.0.1", 80), ("10.0.0.1", "10.0.0.1", 443), ("10.0.0.2", "10.0.0.2", 443), ("10.0.0.3", "10.0.0.3", 22),
                    ("10.0.0.5", "10.0.0.5", 25), ("10.0.0.8", "10.0.0.8", 443), ("10.0.0.9", "10.0.0.9", 443), ("10.0.0.20", "10.0.0.20", 8080)]

    def A(run, **k): return row(run, "10.0.0.1", "10.0.0.1", 80, Title="Welcome", Server="nginx/1.24.0", Products="nginx 1.24.0", Technologies="nginx", Categories="Web servers", **k)
    def B(run, title="Jenkins", flags="CertExpiring:20d;SelfSigned", tlsscan=True, **k):
        r = row(run, "10.0.0.2", "10.0.0.2", 443, tls=True, Title=title, Server="Jetty(10.0.13)", Products="Jenkins 2.400;Jetty 10.0.13", Technologies="Jenkins;Jetty",
                CertSha256="b" * 64, Flags=flags, **k)
        if not tlsscan:
            for f in ("TlsSupported", "TlsCiphersByVersion", "TlsWeakCipher", "Alpn", "Http2"): r[f] = ""
        return r
    def C(run, ver="8.9p1", **k): return row(run, "10.0.0.3", "10.0.0.3", 22, web=False, Service="ssh", Banner="SSH-2.0-OpenSSH_" + ver, Products="OpenSSH " + ver, Technologies="OpenSSH", **k)
    def D(run, ip): return row(run, "web01.corp.local", ip, 8443, tls=True, Title="Portal", CertSha256="d" * 64, Server="IIS/10.0", Products="IIS 10.0")
    def V(run): r = row(run, "app.corp.local", "10.0.0.2", 443, tls=True, Title="App", CertSha256="b" * 64, Vhost=True, VhostOf="10.0.0.2"); return r
    def F(run): return row(run, "10.0.9.9", "10.0.9.9", 80, Title="Old box", Server="Apache")
    def M(run, day): return row(run, "10.0.0.5", "10.0.0.5", 25, web=False, Service="smtp", Banner="220 mail ESMTP Exim 4.96 %s, 0%d Oct 2026 10:00:0%d +0000" % (["Wed", "Thu", "Fri", "Sat", "Sun"][day - 1], day, day), Products="Exim 4.96")
    def P(run, ip, cert): return row(run, ip, ip, 443, tls=True, Title="Printer", ReverseDns="printer1.corp.local", CertSha256=cert, Server="HP-ChaiSOE/1.0", Products="HP printer")
    def K(run, ip): return row(run, ip, ip, 443, tls=True, Title="Kibana", CertSha256="e" * 64, Server="", Products="Kibana")
    def X(run, ip): return row(run, ip, ip, 443, tls=True, Title="Cluster", CertSha256="f" * 64, Server="nginx", Products="nginx")
    def E(run, server="Tomcat"): return row(run, "10.0.0.20", "10.0.0.20", 8080, Title="Tomcat", Server=server, Products="Apache Tomcat")

    r1 = "20261001_100000"
    rows = [A(r1), B(r1), C(r1), D(r1, "10.0.0.4"), V(r1), F(r1), M(r1, 1), P(r1, "10.0.0.6", "1" * 64), K(r1, "10.0.0.7"), X(r1, "10.0.0.8"), X(r1, "10.0.0.9")]
    chk = ck(*base_checked, ("web01.corp.local", "10.0.0.4", 8443), ("10.0.9.9", "10.0.9.9", 80), ("10.0.0.6", "10.0.0.6", 443), ("10.0.0.7", "10.0.0.7", 443))
    write_run(out, "run1", r1, "2026-10-01T10:00:00" + T, rows, chk)

    r2 = "20261002_100000"
    rows = [A(r2), B(r2, title="Jenkins [prod]", flags="CertExpiring:19d;SelfSigned"), D(r2, "10.0.0.14"), V(r2), M(r2, 2), P(r2, "10.0.0.16", "2" * 64),
            K(r2, "10.0.0.17"), X(r2, "10.0.0.9"), X(r2, "10.0.0.10"), E(r2)]
    chk = ck(*base_checked, ("web01.corp.local", "10.0.0.14", 8443), ("10.0.0.6", "10.0.0.6", 443), ("10.0.0.16", "10.0.0.16", 443), ("10.0.0.7", "10.0.0.7", 443),
             ("10.0.0.17", "10.0.0.17", 443), ("10.0.0.10", "10.0.0.10", 443))
    write_run(out, "run2", r2, "2026-10-02T10:00:00" + T, rows, chk)

    r3 = "20261003_100000"
    a3 = A(r3); a3["Title"] = ""; a3["Notes"] = "incomplete: local socket resources exhausted, some requests not sent"
    rows = [a3, B(r3, title="Jenkins [prod]", flags="CertExpiring:18d;SelfSigned", tlsscan=False), D(r3, "10.0.0.14"), M(r3, 3), P(r3, "10.0.0.16", "2" * 64),
            K(r3, "10.0.0.17"), X(r3, "10.0.0.9"), X(r3, "10.0.0.10"), E(r3)]
    chk = ck(*base_checked, ("web01.corp.local", "10.0.0.14", 8443), ("10.0.0.16", "10.0.0.16", 443), ("10.0.0.17", "10.0.0.17", 443), ("10.0.0.10", "10.0.0.10", 443))
    write_run(out, "run3", r3, "2026-10-03T10:00:00" + T, rows, chk, profile={"tlsScan": False, "probeSans": False})

    r4 = "20261004_100000"
    rows = [A(r4), B(r4, title="Jenkins [prod]", flags="CertExpiring:17d;SelfSigned"), D(r4, "10.0.0.14"), M(r4, 4), P(r4, "10.0.0.16", "2" * 64),
            K(r4, "10.0.0.17"), X(r4, "10.0.0.9"), X(r4, "10.0.0.10"), E(r4, server="Tomcat/10.1")]
    write_run(out, "run4", r4, "2026-10-04T10:00:00" + T, rows, chk)

    r5 = "20261005_100000"
    rows = [A(r5), B(r5, title="Jenkins [prod]", flags="CertExpiring:16d;SelfSigned"), C(r5, ver="9.6p1"), D(r5, "10.0.0.14"), V(r5), M(r5, 5), P(r5, "10.0.0.16", "2" * 64),
            K(r5, "10.0.0.17"), X(r5, "10.0.0.9"), X(r5, "10.0.0.10"), E(r5, server="Tomcat/10.1")]
    write_run(out, "run5", r5, "2026-10-05T10:00:00" + T, rows, chk)

    # an interrupted run (complete=false) and an old-format run without run.json (synthesised on import)
    r6 = "20261006_100000"
    write_run(out, "run6", r6, "2026-10-06T10:00:00" + T, [A(r6)], ck(("10.0.0.1", "10.0.0.1", 80)), complete=False)
    r0 = "20260901_090000"
    write_run(out, "old", r0, "", [A(r0), C(r0)], ck(("10.0.0.1", "10.0.0.1", 80), ("10.0.0.3", "10.0.0.3", 22)), run_json=False)


def big(out, n):
    """Two large runs: n services, then the same with 2% changed, 1% gone, 1% new (ingest timing)."""
    random.seed(11)
    for k, (rid, start) in enumerate((("20261010_100000", "2026-10-10T10:00:00+00:00"), ("20261011_100000", "2026-10-11T10:00:00+00:00"))):
        rows, chk = [], []
        for i in range(n):
            a, b_, c = (i >> 16) & 255, (i >> 8) & 255, i & 255
            ip = "10.%d.%d.%d" % (a, b_, c)
            port = (80, 443, 8080, 8443)[i % 4]
            chk.append("%s|%s|%d" % (ip, ip, port))
            if k == 1 and i % 100 == 7:
                continue            # gone
            title = "Service %d" % (i % 997)
            if k == 1 and i % 50 == 3:
                title += " v2"      # changed
            rows.append(row(rid, ip, ip, port, tls=(port in (443, 8443)), Title=title, Server="nginx/1.%d" % (i % 30), Products="nginx 1.%d" % (i % 30),
                            Technologies="nginx", CertSha256=("%064x" % i) if port in (443, 8443) else "", Flags="CertExpiring:%dd" % (20 - k)))
        if k == 1:
            for j in range(n // 100):
                ip = "10.200.%d.%d" % ((j >> 8) & 255, j & 255)
                chk.append("%s|%s|80" % (ip, ip))
                rows.append(row(rid, ip, ip, 80, Title="New %d" % j, Server="Apache", Products="Apache httpd"))
        write_run(out, "big%d" % (k + 1), rid, start, rows, chk)


if __name__ == "__main__":
    out = sys.argv[1]
    if "--big" in sys.argv:
        big(out, int(sys.argv[sys.argv.index("--big") + 1]))
    else:
        scenario(out)
