#!/usr/bin/env python3
"""WebInventory macro benchmark runner.

usage: bench.py --script <Invoke-WebInventory.ps1> --label <name> [--scenarios a,b,...] [--reps 3] [--out <dir>]
                [--pwsh <path>] [--ref <label>]  [--extra "<extra args>"]

Runs each scenario --reps times against the lab started by lab/start-lab.sh, measuring per run:
  wall seconds, scanner CPU seconds (user+sys of the pwsh process only, via wait4), peak RSS,
  requests / rows / web counts from the run summary, and phase times parsed from the run log.
Results go to <out>/<label>/<scenario>/run<N>/ (scan outputs) and <out>/<label>/results.json.
With --ref, the first run of every scenario is checked field by field against the reference label's first run
(tests/perf/golden.py) and the verdict is stored with the results.
"""
import argparse, datetime, json, os, re, shutil, statistics, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_TARGETS = os.path.join(HERE, "lab-targets.txt")

SCENARIOS = {
    # accuracy reference: every probe type, TLS oddities, banners, vhosts, tarpit, slow app
    "lab":       ["-TargetFile", LAB_TARGETS, "-ProbeSans", "-IdentifyPaths", "-Options", "-ReverseDns", "-TimeoutMs", "2000"],
    # 200 web services on 50 hosts (CPU-bound: parsing, rule evaluation, TLS scans)
    "farm":      ["-Target", "127.0.10.1-50", "-Port", "19080,19081,19082,19443", "-TimeoutMs", "2000"],
    # same farm behind a 20 ms RTT relay (round-trip bound)
    "farm-rtt":  ["-Target", "127.0.20.1-50", "-Port", "19080,19081,19082,19443", "-TimeoutMs", "2000"],
    # 40 silent listeners (tarpit / SYN-proxy firewall)
    "tarpit":    ["-Target", "127.0.11.1-20", "-Port", "19090,19091", "-TimeoutMs", "1000"],
    # 4000 closed ports (RST): pure per-check overhead
    "closed":    ["-Target", "127.0.30.1-20", "-Port", "20000-20199", "-TimeoutMs", "1000"],
    # 320 filtered ports (SYN dropped by iptables): timeout bound
    "filtered":  ["-Target", "127.0.31.1-10", "-Port", "20000-20031", "-TimeoutMs", "500"],
    # accuracy references: same targets at low concurrency and generous timeouts (no load-induced misses)
    "farm-ref":  ["-Target", "127.0.10.1-50", "-Port", "19080,19081,19082,19443", "-TimeoutMs", "10000", "-Threads", "4"],
    "farmrtt-ref": ["-Target", "127.0.20.1-50", "-Port", "19080,19081,19082,19443", "-TimeoutMs", "10000", "-Threads", "8"],
    # startup only (engine compile + rule load + preflight)
    "startup":   ["-Target", "127.0.0.1:80", "-ListTargets"],
    # target expansion: 16,384 hosts x 26 web ports = 425,984 checks (ListTargets, output discarded)
    "expand":    ["-Target", "10.10.0.0/18", "-ListTargets", "-Force"],
}
COMPARE = {"lab": "lab", "farm": "farm-ref", "farm-rtt": "farmrtt-ref", "tarpit": "tarpit"}
TS = re.compile(r"^(\S+) \[(\w+)\s*\] (.*)$")


def parse_log(path):
    out = {"phases": {}}
    first = prev = None
    marks = {}
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return out
    for l in lines:
        m = TS.match(l)
        if not m:
            continue
        t = datetime.datetime.fromisoformat(m.group(1)).timestamp()
        msg = m.group(3)
        if first is None:
            first = t
        for key, pfx in (("preflight", "Preflight:"), ("scope", "Scope:"), ("start", "WebInventory v"), ("done", "Done in"),
                         ("done", "INTERRUPTED"), ("listed", "ListTargets:")):
            if msg.startswith(pfx) and key not in marks:
                marks[key] = t
        if msg.startswith("Done in") or msg.startswith("INTERRUPTED") or msg.startswith("TIME LIMIT"):
            for k, rx in (("requests", r"requests=(\d+)"), ("rows", r"rows=(\d+)"), ("web", r"web=(\d+)"), ("open", r"open=(\d+)"),
                          ("closed", r"closed=(\d+)"), ("filtered", r"filtered=(\d+)"), ("worker_errors", r"worker-errors=(\d+)"),
                          ("regex_timeouts", r"rule-regex-timeouts=(\d+)")):
                mm = re.search(rx, msg)
                if mm:
                    out[k] = int(mm.group(1))
    if first is not None:
        if "preflight" in marks: out["phases"]["startup_s"] = round(marks["preflight"] - first, 3)
        if "scope" in marks and "preflight" in marks: out["phases"]["targets_s"] = round(marks["scope"] - marks["preflight"], 3)
        if "done" in marks and "start" in marks: out["phases"]["scan_s"] = round(marks["done"] - marks["start"], 3)
        if "listed" in marks and "scope" in marks: out["phases"]["list_s"] = round(marks["listed"] - marks["scope"], 3)
    return out


def run_one(pwsh, script, args, outdir):
    os.makedirs(outdir, exist_ok=True)
    cmd = [pwsh, "-NoProfile", "-NonInteractive", "-File", script] + args + ["-OutputDir", outdir, "-NoProgress", "-Quiet", "-NoHtml",
                                                                              "-Tag", "bench"]
    t0 = time.monotonic()
    with open(os.path.join(outdir, "stdout.txt"), "wb") as so:
        p = subprocess.Popen(cmd, cwd=outdir, stdout=so, stderr=subprocess.STDOUT)
        _, status, ru = os.wait4(p.pid, 0)
    wall = time.monotonic() - t0
    logs = [f for f in os.listdir(outdir) if f.endswith("_run.log")]
    info = parse_log(os.path.join(outdir, sorted(logs)[-1])) if logs else {"phases": {}}
    info.update({"wall_s": round(wall, 3), "cpu_s": round(ru.ru_utime + ru.ru_stime, 3), "user_s": round(ru.ru_utime, 3),
                 "sys_s": round(ru.ru_stime, 3), "maxrss_mb": round(ru.ru_maxrss / 1024.0, 1), "exit": os.waitstatus_to_exitcode(status)})
    return info


def summarize(runs):
    keys = ["wall_s", "cpu_s", "maxrss_mb", "requests", "rows", "web"]
    s = {}
    for k in keys:
        vals = [r[k] for r in runs if k in r]
        if vals:
            s[k] = statistics.median(vals)
            if len(vals) > 1 and k in ("wall_s", "cpu_s"):
                s[k + "_min"] = min(vals); s[k + "_max"] = max(vals)
    ph = {}
    for r in runs:
        for k, v in r.get("phases", {}).items():
            ph.setdefault(k, []).append(v)
    s["phases"] = {k: statistics.median(v) for k, v in ph.items()}
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--script", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--scenarios", default="lab,farm,farm-rtt,tarpit,closed,filtered,startup,expand")
    ap.add_argument("--certs", default=None)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out", default=os.path.join(HERE, "results"))
    ap.add_argument("--pwsh", default=shutil.which("pwsh") or "pwsh")
    ap.add_argument("--ref", default=None)
    ap.add_argument("--extra", default="")
    a = ap.parse_args()
    script = os.path.abspath(a.script)
    base = os.path.join(a.out, a.label)
    resfile = os.path.join(base, "results.json")
    results = json.load(open(resfile)) if os.path.exists(resfile) else {"label": a.label, "script": script, "scenarios": {}}
    for sc in a.scenarios.split(","):
        args = SCENARIOS[sc] + (a.extra.split() if a.extra else [])
        runs = []
        for i in range(a.reps):
            d = os.path.join(base, sc, "run%d" % (i + 1))
            shutil.rmtree(d, ignore_errors=True)
            r = run_one(a.pwsh, script, args, d)
            runs.append(r)
            print("%-10s %-9s run%d wall=%7.2fs cpu=%7.2fs rss=%6.1fMB req=%s rows=%s exit=%s %s" % (
                a.label, sc, i + 1, r["wall_s"], r["cpu_s"], r["maxrss_mb"], r.get("requests", "-"), r.get("rows", "-"), r["exit"],
                " ".join("%s=%.2f" % kv for kv in sorted(r["phases"].items()))), flush=True)
        entry = {"args": args, "runs": runs, "summary": summarize(runs)}
        if a.ref and sc in COMPARE:
            refdir = os.path.join(a.out, a.ref, COMPARE[sc], "run1")
            verdicts = []
            for i in range(a.reps):
                g = subprocess.run([sys.executable, os.path.join(HERE, "golden.py"), refdir, os.path.join(base, sc, "run%d" % (i + 1))], capture_output=True, text=True)
                verdicts.append({"identical": g.returncode == 0, "summary": (g.stdout.splitlines() or [g.stderr[-300:]])[0], "report": g.stdout[-3000:]})
                print("%-10s %-9s run%d golden vs %s/%s: %s" % (a.label, sc, i + 1, a.ref, COMPARE[sc], verdicts[-1]["summary"]), flush=True)
            entry["golden"] = verdicts
        results["scenarios"][sc] = entry
        os.makedirs(base, exist_ok=True)
        json.dump(results, open(resfile, "w"), indent=1)


if __name__ == "__main__":
    main()
