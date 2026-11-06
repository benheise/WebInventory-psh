# WebInventory performance suite

Measures speed and accuracy together: a change only counts as an improvement if every result field still matches a
reference scan. Everything runs against a local lab (loopback only).

## Pieces

| File | What it does |
|---|---|
| `../../lab/start-lab.sh <certdir> [hosts] [tarpits] [one-way-ms]` | Starts the regression lab (`lab.py`, `faketls.py`, two `openssl s_server` legacy-TLS endpoints), the benchmark farm (`farm.py`: 50 hosts x 4 web services on 127.0.10.x, 20 tarpit hosts on 127.0.11.x), the latency relay (`latproxy.py`: the farm again on 127.0.20.x at +20 ms RTT) and an iptables DROP for 127.0.31.0/24 (filtered ports). Foreground; stop with Ctrl+C or `stop-lab.sh` |
| `../../lab/with-lab.sh <certdir> <command...>` | Starts the lab, runs one command, tears the lab down |
| `bench.py` | Macro scenarios. Per run: wall time, CPU of the scanner process only (wait4), peak RSS, requests/rows/states, phase times from the run log. `--ref <label>` checks every run field by field against the reference |
| `golden.py <ref-dir> <cand-dir>` | Accuracy gate: CSV and JSONL compared per Host/IP/Port/Vhost; only run id, timestamps and measured response time are ignored |
| `micro.ps1 -Script <ps1> -Out <json>` | Attribution: rule evaluation per page (and per field), response parsing, row writing, per-check dispatch cost, DNS window (simulated resolver) |
| `prefilter-check.ps1 -Script <ps1> [-CorpusDir dir]` | Proves the rule prefilter changes nothing: literal-extraction cases, every rule example (2,335) and a response corpus evaluated with the prefilter on and off |
| `report.py <root> <baseline> <candidate>` | Markdown tables: baseline vs candidate, and leave-one-out contributions |
| `run-ablation.sh` + `ablation/` | The leave-one-out study used for v2.1. It needs the instrumented build in `ablation/` (the shipped script no longer has the switches) |
| `lab-targets.txt` | Target file for the `lab` scenario |

## Scenarios

| Name | Targets | Stresses |
|---|---|---|
| `lab` | every regression fixture, `-ProbeSans -IdentifyPaths -Options -ReverseDns` | accuracy across all probe types (bounded by a 1.5 s slow app) |
| `farm` / `farm-rtt` | 200 web services (nginx, WordPress, 120 KB SPA, TLS Jenkins) direct / at 20 ms RTT | CPU: parsing, rule evaluation, TLS |
| `farm-ref` / `farmrtt-ref` | same, 4-8 threads, 10 s timeouts | the accuracy reference (no load-induced misses) |
| `tarpit` | 40 listeners that accept and never answer | silent ports, SYN-proxy firewalls |
| `closed` | 4,000 closed ports (RST) | per-check overhead |
| `filtered` | 320 dropped ports | timeout-bound dispatch |
| `startup` | `-ListTargets` of one target | engine compile, rule load, preflight |
| `expand` | `-ListTargets` of a /18 x 26 ports (425,984 checks) | target expansion |

## Typical use

```bash
# reference and baseline (once)
lab/with-lab.sh CERTS python3 tests/perf/bench.py --script baseline/Invoke-WebInventory-v2.0.2.ps1 --label v2.0.2 --ref v2.0.2 \
    --scenarios farm-ref,farmrtt-ref,lab,farm,farm-rtt,tarpit,closed,filtered,startup,expand
# a candidate, checked against the v2.0.2 references
lab/with-lab.sh CERTS python3 tests/perf/bench.py --script dist/Invoke-WebInventory.ps1 --label next --ref v2.0.2
python3 tests/perf/report.py tests/perf/results v2.0.2 next
```

The farm saturates a 2-vCPU machine, which is deliberate: the v2.0.2 baseline loses HTTPS services and detections
under that load, and the suite reports it. Run benchmarks one at a time; anything else using the CPU skews them.
