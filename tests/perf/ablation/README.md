`Invoke-WebInventory-2.1-ablation.ps1` is the instrumented v2.1 candidate used for the leave-one-out study. It is the
shipped logic plus `WEBINV_PERF_OFF=<list>` switches that put back the v2.0.2 behaviour of one component at a time:
`prefilter`, `sched` (one PowerShell instance per check, 20 ms polling), `silence`, `parse`, `writer`, `jobs`, `dns`,
`connect` (BeginConnect), `warmup`, `ramp`. Not for production use; it still reports version 2.0.2 internally (the bump came after the study). Copy the rule packs next to it and run
`../run-ablation.sh ablation/Invoke-WebInventory-2.1-ablation.ps1 <out> v2.0.2`.
