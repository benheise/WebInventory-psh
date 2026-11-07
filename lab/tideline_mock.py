#!/usr/bin/env python3
"""A stand-in for Tideline's ingest service, for tests: the protocol of SHIPPING.md with the checks the platform plan
gives ingest (mutual TLS, sensor identity from the certificate, ES256 manifest signature, per-part SHA-256, gzip
limits, record schemas), plus fault injection. Not a server to deploy.

  serve:  python3 lab/tideline_mock.py serve --port 18443 --cert server.crt --key server.key --client-ca client-ca.pem \
              --data DIR [--sensors wi-test01,...] [--schemas schemas] [--fault put:2:503:1 ...] [--log requests.jsonl]
  bundle: python3 lab/tideline_mock.py verify-bundle BUNDLE.zip --ca root.pem [--intermediate inter.pem] [--schemas schemas]
  runs:   python3 lab/tideline_mock.py show --data DIR

Faults (each SPEC fires COUNT times, default 1): post:STATUS, put:N:STATUS, complete:STATUS, drop:put:N (close the
connection without answering), slow:put:N:SECONDS."""
import argparse, base64, gzip, hashlib, http.server, io, json, os, pathlib, re, socketserver, ssl, sys, threading, time, zipfile, zlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

URN = "urn:tideline:sensor:"
MAX_MANIFEST = 1 << 20
MAX_PART_COMPRESSED = 64 << 20
MAX_PART = 512 << 20
MAX_RATIO = 50          # only above 1 MiB uncompressed; tiny parts of repetitive JSON compress far better
MAX_RECORD = 1 << 20
RUN_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def sensor_of(cert):
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
    ids = {u[len(URN):] for u in san.get_values_for_type(x509.UniformResourceIdentifier) if u.lower().startswith(URN)}
    return ids.pop() if len(ids) == 1 else None


def verify_signature(header, data, cert):
    """Tideline-Signature: alg=ES256; enc=p1363|der; sig=<base64>"""
    f = dict(p.strip().split("=", 1) for p in header.split(";") if "=" in p)
    if f.get("alg") != "ES256":
        raise ValueError("alg must be ES256")
    sig = base64.b64decode(f.get("sig", ""))
    enc = f.get("enc", "der")
    if enc == "p1363":
        if len(sig) != 64:
            raise ValueError("p1363 signature must be 64 bytes")
        sig = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    elif enc != "der":
        raise ValueError("enc must be p1363 or der")
    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        raise ValueError("the client key is not ECDSA P-256")
    pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))


def load_validators(d):
    if not d:
        return None, None
    from jsonschema import Draft202012Validator
    v = {}
    for p in pathlib.Path(d).glob("*.json"):   # the vendored Tideline schemas, keyed by their id (webinventory.service/1)
        s = json.loads(p.read_text(encoding="utf-8"))
        if "x-tideline-schema" in s:
            v[s["x-tideline-schema"]] = Draft202012Validator(s)
    return v, v.get("tideline-envelope/1")


def schema_key(record_schema):
    return record_schema


def inflate(body, limit):
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = io.BytesIO()
    data = body
    while data:
        chunk = d.decompress(data, 1 << 20)
        out.write(chunk)
        if out.tell() > limit:
            raise ValueError("part larger than %d bytes uncompressed" % limit)
        data = d.unconsumed_tail
    out.write(d.flush())
    if not d.eof:
        raise ValueError("truncated gzip stream")
    return out.getvalue()


def check_part(part, raw, validators):
    """problems of one uploaded part (decompressed bytes) against its manifest entry: list of (line, message)"""
    if len(raw) != part["bytes"]:
        return [(0, "size %d, the manifest says %d" % (len(raw), part["bytes"]))]
    if hashlib.sha256(raw).hexdigest() != part["sha256"]:
        return [(0, "sha256 differs from the manifest")]
    if part["kind"] == "artifact":
        return []
    problems, records = [], 0
    v = validators.get(schema_key(part["schema"])) if validators else None
    if validators is not None and v is None:
        return [(0, "unknown record schema " + part["schema"])]
    for i, line in enumerate(raw.split(b"\n"), 1):
        if not line.strip():
            continue
        records += 1
        if len(line) > MAX_RECORD:
            problems.append((i, "record larger than 1 MiB")); continue
        try:
            rec = json.loads(line)
        except Exception as e:
            problems.append((i, "not JSON: %s" % e)); continue
        if v:
            errs = list(v.iter_errors(rec))
            if errs:
                problems.append((i, "%s: %s" % ("/".join(map(str, errs[0].path)), errs[0].message[:200])))
        if len(problems) >= 20:
            break
    if not problems and records != part["records"]:
        problems.append((0, "%d records, the manifest says %d" % (records, part["records"])))
    return problems


class State:
    def __init__(self, data, sensors, engagements, validators, envelope, faults, log):
        self.data = pathlib.Path(data); self.data.mkdir(parents=True, exist_ok=True)
        self.sensors, self.engagements = sensors, engagements
        self.validators, self.envelope = validators, envelope
        self.faults, self.lock, self.logf = faults, threading.Lock(), log

    def run_dir(self, rid): return self.data / "runs" / rid
    def load(self, rid):
        p = self.run_dir(rid) / "state.json"
        return json.loads(p.read_text()) if p.exists() else None
    def save(self, rid, st):
        d = self.run_dir(rid); d.mkdir(parents=True, exist_ok=True)
        tmp = d / "state.json.tmp"; tmp.write_text(json.dumps(st, indent=1)); os.replace(tmp, d / "state.json")
    def fault(self, *key):
        with self.lock:
            for f in self.faults:
                if f["key"] == key and f["left"] > 0:
                    f["left"] -= 1
                    return f
        return None
    def log(self, **e):
        if self.logf:
            with self.lock, open(self.logf, "a") as f:
                f.write(json.dumps(dict(e, t=round(time.time(), 3))) + "\n")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "tideline-mock/1"

    def log_message(self, fmt, *a): pass

    def send_json(self, code, obj):
        b = (json.dumps(obj) + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        self.send_header("Connection", "close"); self.end_headers(); self.wfile.write(b)
        self.close_connection = True

    def no_content(self):
        self.send_response(204); self.send_header("Content-Length", "0"); self.send_header("Connection", "close"); self.end_headers()
        self.close_connection = True

    def body(self, limit):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            raise OverflowError(n)
        return self.rfile.read(n) if n else b""

    def sensor(self):
        der = self.connection.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der)
        sid = sensor_of(cert)
        st = self.server.state
        if not sid:
            return None, cert, "the client certificate names no single " + URN + "<id>"
        if st.sensors is not None and sid not in st.sensors:
            return None, cert, "sensor %s is not active" % sid
        return sid, cert, None

    def dispatch(self, method):
        st = self.server.state
        sid, cert, why = self.sensor()
        path = self.path.split("?")[0]
        st.log(method=method, path=path, sensor=sid)
        if why:
            return self.send_json(403, {"error": why})
        m = re.match(r"^/v1/runs/?$", path)
        if m and method == "POST":
            return self.open_run(sid, cert)
        m = re.match(r"^/v1/runs/([0-9a-f-]{36})/parts/(\d+)$", path)
        if m and method == "PUT":
            return self.put_part(sid, m.group(1), int(m.group(2)))
        m = re.match(r"^/v1/runs/([0-9a-f-]{36})/complete$", path)
        if m and method == "POST":
            return self.complete(sid, m.group(1))
        m = re.match(r"^/v1/runs/([0-9a-f-]{36})$", path)
        if m and method == "GET":
            return self.status(sid, m.group(1))
        return self.send_json(404, {"error": "no such endpoint"})

    def do_POST(self): self.dispatch("POST")
    def do_PUT(self): self.dispatch("PUT")
    def do_GET(self): self.dispatch("GET")

    def missing(self, run):
        return [p["n"] for p in run["manifest"]["parts"] if str(p["n"]) not in run["received"]]

    def open_run(self, sid, cert):
        st = self.server.state
        f = st.fault("post")
        if f:
            self.body(MAX_MANIFEST); return self.send_json(f["status"], {"error": "injected"})
        try:
            raw = self.body(MAX_MANIFEST)
        except OverflowError:
            return self.send_json(413, {"error": "manifest larger than 1 MiB"})
        try:
            verify_signature(self.headers.get("Tideline-Signature", ""), raw, cert)
        except (InvalidSignature, ValueError) as e:
            return self.send_json(401, {"error": "manifest signature: " + (str(e) or "does not verify")})
        try:
            man = json.loads(raw)
        except Exception as e:
            return self.send_json(400, {"error": "manifest is not JSON: %s" % e})
        if st.envelope:
            errs = list(st.envelope.iter_errors(man))
            if errs:
                return self.send_json(422, {"error": "manifest: %s: %s" % ("/".join(map(str, errs[0].path)), errs[0].message[:200])})
        if man.get("sensor") != sid:
            return self.send_json(403, {"error": "the manifest names sensor %r, the certificate is %r" % (man.get("sensor"), sid)})
        if st.engagements is not None and man.get("engagement") not in st.engagements:
            return self.send_json(403, {"error": "sensor %s is not assigned to engagement %r" % (sid, man.get("engagement"))})
        ns = [p["n"] for p in man["parts"]]
        if ns != list(range(1, len(ns) + 1)):
            return self.send_json(422, {"error": "parts must be numbered 1..N"})
        rid = man["run_id"]
        with st.lock:
            run = st.load(rid)
            if run:
                if run["manifest_sha256"] != hashlib.sha256(raw).hexdigest():
                    return self.send_json(409, {"error": "run %s exists with a different manifest" % rid})
                return self.send_json(200, {"run_id": rid, "state": run["state"], "missing": self.missing(run)})
            run = {"run_id": rid, "sensor": sid, "state": "receiving", "manifest": man, "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                   "signature": self.headers.get("Tideline-Signature"), "received": {}, "opened": time.time()}
            d = st.run_dir(rid); d.mkdir(parents=True, exist_ok=True)
            (d / "manifest.json").write_bytes(raw)
            st.save(rid, run)
        return self.send_json(201, {"run_id": rid, "state": "receiving", "missing": self.missing(run)})

    def put_part(self, sid, rid, n):
        st = self.server.state
        f = st.fault("drop", "put", n)
        if f:
            self.close_connection = True
            try: self.connection.shutdown(2)
            except Exception: pass
            return
        f = st.fault("slow", "put", n)
        if f: time.sleep(f["status"])
        try:
            body = self.body(MAX_PART_COMPRESSED)
        except OverflowError:
            return self.send_json(413, {"error": "part larger than 64 MiB compressed"})
        f = st.fault("put", n)
        if f:
            return self.send_json(f["status"], {"error": "injected"})
        run = st.load(rid)
        if not run or run["sensor"] != sid:
            return self.send_json(404, {"error": "no run %s for sensor %s" % (rid, sid)})
        if n < 1 or n > len(run["manifest"]["parts"]):
            return self.send_json(404, {"error": "no part %d" % n})
        if str(n) in run["received"]:
            return self.no_content()
        part = run["manifest"]["parts"][n - 1]
        enc = (self.headers.get("Content-Encoding") or "identity").lower()
        if enc != part["encoding"]:
            return self.send_json(400, {"error": "Content-Encoding %s, the manifest says %s" % (enc, part["encoding"])})
        try:
            raw = inflate(body, MAX_PART) if enc == "gzip" else body
        except ValueError as e:
            return self.send_json(413 if "larger" in str(e) else 400, {"error": str(e)})
        if enc == "gzip" and len(raw) > (1 << 20) and len(raw) > MAX_RATIO * max(1, len(body)):
            return self.send_json(413, {"error": "compression ratio above %d:1" % MAX_RATIO})
        problems = check_part(part, raw, st.validators)
        if problems:
            return self.send_json(422, {"error": "part %d: %s" % (n, problems[0][1]), "lines": [p[0] for p in problems if p[0]]})
        with st.lock:
            run = st.load(rid)
            (st.run_dir(rid) / ("part-%04d" % n)).write_bytes(raw)
            run["received"][str(n)] = {"bytes": len(raw), "wire": len(body)}
            st.save(rid, run)
        return self.no_content()

    def complete(self, sid, rid):
        st = self.server.state
        self.body(1 << 16)
        f = st.fault("complete")
        if f:
            return self.send_json(f["status"], {"error": "injected"})
        with st.lock:
            run = st.load(rid)
            if not run or run["sensor"] != sid:
                return self.send_json(404, {"error": "no run %s for sensor %s" % (rid, sid)})
            miss = self.missing(run)
            if miss:
                return self.send_json(409, {"error": "parts missing", "missing": miss})
            if run["state"] == "receiving":
                run["state"] = "verified"; run["verified"] = time.time(); st.save(rid, run)
        return self.send_json(202, {"run_id": rid, "state": run["state"]})

    def status(self, sid, rid):
        run = self.server.state.load(rid)
        if not run or run["sensor"] != sid:
            return self.send_json(404, {"error": "no run %s for sensor %s" % (rid, sid)})
        return self.send_json(200, {"run_id": rid, "state": run["state"], "received": sorted(int(k) for k in run["received"]), "missing": self.missing(run)})


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(a):
    faults = []
    for spec in a.fault or []:
        p = spec.split(":")
        if p[0] in ("post", "complete"):
            faults.append({"key": (p[0],), "status": int(p[1]), "left": int(p[2]) if len(p) > 2 else 1})
        elif p[0] == "put":
            faults.append({"key": ("put", int(p[1])), "status": int(p[2]), "left": int(p[3]) if len(p) > 3 else 1})
        elif p[0] in ("drop", "slow"):
            faults.append({"key": (p[0], "put", int(p[2])), "status": float(p[3]) if p[0] == "slow" else 0, "left": int(p[4]) if p[0] == "slow" and len(p) > 4 else (int(p[3]) if p[0] == "drop" and len(p) > 3 else 1)})
        else:
            sys.exit("bad fault " + spec)
    validators, envelope = load_validators(a.schemas)
    sensors = None if a.sensors in (None, "", "any") else set(a.sensors.split(","))
    engagements = None if a.engagements in (None, "", "any") else set(x if x != "null" else None for x in a.engagements.split(","))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM")
    ctx.load_cert_chain(a.cert, a.key)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=a.client_ca)
    srv = Server((a.host, a.port), Handler)
    srv.state = State(a.data, sensors, engagements, validators, envelope, faults, a.log)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print("tideline-mock listening on https://%s:%d (data %s)" % (a.host, a.port, a.data), flush=True)
    if a.ready:
        pathlib.Path(a.ready).write_text("ready\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def verify_bundle(a):
    validators, envelope = load_validators(a.schemas)
    z = zipfile.ZipFile(a.bundle)
    raw = z.read("manifest.json")
    sig = z.read("manifest.sig").decode().strip()
    chain = x509.load_pem_x509_certificates(z.read("sensor-chain.pem"))
    leaf = chain[0]
    from cryptography.x509.verification import PolicyBuilder, Store
    roots = x509.load_pem_x509_certificates(pathlib.Path(a.ca).read_bytes())
    verifier = PolicyBuilder().store(Store(roots)).build_client_verifier()
    verifier.verify(leaf, chain[1:])
    verify_signature(sig, raw, leaf)
    man = json.loads(raw)
    if envelope:
        errs = list(envelope.iter_errors(man))
        if errs: sys.exit("FAIL manifest: " + errs[0].message)
    if man["sensor"] != sensor_of(leaf):
        sys.exit("FAIL the manifest names sensor %s, the certificate %s" % (man["sensor"], sensor_of(leaf)))
    idx = json.loads(z.read("bundle.json"))
    files = {p["n"]: p for p in idx["parts"]}
    bad = 0
    for part in man["parts"]:
        f = files.get(part["n"])
        if not f:
            print("FAIL part %d missing" % part["n"]); bad += 1; continue
        body = z.read(f["path"])
        rawp = inflate(body, MAX_PART) if part["encoding"] == "gzip" else body
        probs = check_part(part, rawp, validators)
        if probs:
            print("FAIL part %d (%s): %s" % (part["n"], part["name"], probs[0][1])); bad += 1
    print("bundle %s: run %s, sensor %s, %d parts, %s" % (a.bundle, man["run_id"], man["sensor"], len(man["parts"]), "OK" if not bad else "%d bad" % bad))
    sys.exit(1 if bad else 0)


def show(a):
    for p in sorted((pathlib.Path(a.data) / "runs").glob("*/state.json")):
        r = json.loads(p.read_text())
        m = r["manifest"]
        print(json.dumps({"run_id": r["run_id"], "sensor": r["sensor"], "state": r["state"], "tool_version": m.get("tool_version"), "engagement": m.get("engagement"),
                          "exit_code": m.get("exit_code"), "parts": len(m["parts"]), "received": len(r["received"]),
                          "kinds": sorted({x["kind"] if x["kind"] != "artifact" else "artifact:" + x["role"] for x in m["parts"]})}))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=18443)
    s.add_argument("--cert", required=True); s.add_argument("--key", required=True); s.add_argument("--client-ca", required=True)
    s.add_argument("--data", required=True); s.add_argument("--sensors"); s.add_argument("--engagements"); s.add_argument("--schemas")
    s.add_argument("--fault", action="append"); s.add_argument("--log"); s.add_argument("--ready")
    b = sub.add_parser("verify-bundle")
    b.add_argument("bundle"); b.add_argument("--ca", required=True); b.add_argument("--schemas")
    w = sub.add_parser("show"); w.add_argument("--data", required=True)
    a = ap.parse_args()
    {"serve": serve, "verify-bundle": verify_bundle, "show": show}[a.cmd](a)


if __name__ == "__main__":
    main()
