#!/usr/bin/env bash
# A/B (leave-one-out) study: the candidate with everything on, then with one optimization switched off at a time
# (WEBINV_PERF_OFF), each on the scenarios that optimization targets. Accuracy of every run is checked against the
# low-concurrency v2.0.2 reference runs.
#   run-ablation.sh <candidate.ps1> <out-dir> <ref-label> [reps]
set -u
CAND=${1:?script}; OUT=${2:?outdir}; REF=${3:?ref label}; REPS=${4:-3}
HERE=$(cd "$(dirname "$0")" && pwd)
b() { local label=$1 off=$2 sc=$3; WEBINV_PERF_OFF=$off python3 "$HERE/bench.py" --script "$CAND" --label "$label" --ref "$REF" --reps "$REPS" --out "$OUT" --scenarios "$sc"; }
b cand            ""          lab,farm,farm-rtt,tarpit,closed,filtered,startup,expand
b cand-prefilter  prefilter   farm,farm-rtt
b cand-sched      sched       closed,filtered,farm,tarpit
b cand-silence    silence     tarpit
b cand-parse      parse       farm
b cand-writer     writer      farm
b cand-warmramp   warmup,ramp farm,farm-rtt
b cand-warmup     warmup      farm
b cand-ramp       ramp        farm
b cand-jobs       jobs        expand
b cand-connect    connect     closed,filtered
