#!/usr/bin/env python3
"""Summarise benchmark results: baseline vs candidate, then each leave-one-out variant vs the full candidate.

usage: report.py <results-root> <baseline-label> <candidate-label> [--json out.json] [--md out.md]
"""
import json, os, sys

SCEN_ORDER = ["lab", "farm", "farm-rtt", "tarpit", "closed", "filtered", "startup", "expand"]
VARIANTS = [("cand-prefilter", "literal prefilter"), ("cand-sched", "scheduler + long-lived workers"), ("cand-silence", "silent-listener parallel TLS probes"),
            ("cand-parse", "C# response parsing"), ("cand-writer", "C# CSV/JSONL writer"), ("cand-warmramp", "TLS warm-up + worker ramp"),
            ("cand-warmup", "TLS warm-up"), ("cand-ramp", "worker ramp"), ("cand-jobs", "C# target expansion"), ("cand-connect", "select-based connect")]


def load(root, label):
    p = os.path.join(root, label, "results.json")
    return json.load(open(p)) if os.path.exists(p) else None


def acc(entry):
    g = entry.get("golden")
    if not g:
        s = entry["summary"]
        runs = entry["runs"]
        states = ["open=%s closed=%s filtered=%s" % (r.get("open"), r.get("closed"), r.get("filtered")) for r in runs if "closed" in r]
        return (", ".join(sorted(set(states))) if states else "-")
    ok = sum(1 for v in g if v["identical"])
    return "%d/%d identical" % (ok, len(g)) if ok == len(g) else "%d/%d identical (%s)" % (ok, len(g), "; ".join(v["summary"].split(", ")[-1] for v in g if not v["identical"]))


def main():
    root, base, cand = sys.argv[1:4]
    B, C = load(root, base), load(root, cand)
    out = {"baseline": base, "candidate": cand, "scenarios": [], "variants": []}
    lines = ["| Scenario | v2.0.2 wall s | v2.1 wall s | speed-up | v2.0.2 CPU s | v2.1 CPU s | CPU saved | peak RSS MB (old→new) | accuracy v2.0.2 | accuracy v2.1 |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---|---|"]
    for sc in SCEN_ORDER:
        if sc not in B["scenarios"] or sc not in C["scenarios"]:
            continue
        b, c = B["scenarios"][sc], C["scenarios"][sc]
        bs, cs = b["summary"], c["summary"]
        row = {"scenario": sc, "base_wall": bs["wall_s"], "cand_wall": cs["wall_s"], "base_cpu": bs["cpu_s"], "cand_cpu": cs["cpu_s"],
               "base_rss": bs["maxrss_mb"], "cand_rss": cs["maxrss_mb"], "speedup": round(bs["wall_s"] / cs["wall_s"], 2),
               "cpu_saved_pct": round(100 * (1 - cs["cpu_s"] / bs["cpu_s"]), 1), "base_acc": acc(b), "cand_acc": acc(c),
               "base_phases": bs.get("phases", {}), "cand_phases": cs.get("phases", {})}
        out["scenarios"].append(row)
        lines.append("| %s | %.1f | %.1f | %.2fx | %.1f | %.1f | %.0f%% | %.0f→%.0f | %s | %s |" % (
            sc, row["base_wall"], row["cand_wall"], row["speedup"], row["base_cpu"], row["cand_cpu"], row["cpu_saved_pct"],
            row["base_rss"], row["cand_rss"], row["base_acc"], row["cand_acc"]))
    lines += ["", "| Switched off | Scenario | full v2.1 wall / CPU s | without it wall / CPU s | contribution (wall, CPU) | accuracy without it |",
              "|---|---|---:|---:|---:|---|"]
    for label, name in VARIANTS:
        V = load(root, label)
        if not V:
            continue
        for sc, e in V["scenarios"].items():
            if sc not in C["scenarios"]:
                continue
            cs, vs = C["scenarios"][sc]["summary"], e["summary"]
            row = {"variant": label, "feature": name, "scenario": sc, "cand_wall": cs["wall_s"], "cand_cpu": cs["cpu_s"], "var_wall": vs["wall_s"],
                   "var_cpu": vs["cpu_s"], "wall_factor": round(vs["wall_s"] / cs["wall_s"], 2), "cpu_factor": round(vs["cpu_s"] / cs["cpu_s"], 2), "acc": acc(e)}
            out["variants"].append(row)
            lines.append("| %s | %s | %.1f / %.1f | %.1f / %.1f | %.2fx, %.2fx | %s |" % (name, sc, row["cand_wall"], row["cand_cpu"], row["var_wall"], row["var_cpu"],
                                                                         row["wall_factor"], row["cpu_factor"], row["acc"]))
    md = "\n".join(lines)
    print(md)
    if "--json" in sys.argv:
        json.dump(out, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
    if "--md" in sys.argv:
        open(sys.argv[sys.argv.index("--md") + 1], "w").write(md + "\n")


if __name__ == "__main__":
    main()
