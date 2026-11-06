| Scenario | v2.0.2 wall s | v2.1 wall s | speed-up | v2.0.2 CPU s | v2.1 CPU s | CPU saved | peak RSS MB (old→new) | accuracy v2.0.2 | accuracy v2.1 |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| lab | 40.3 | 39.9 | 1.01x | 17.0 | 13.2 | 22% | 387→406 | 3/3 identical | 3/3 identical |
| farm | 39.7 | 12.4 | 3.20x | 67.1 | 20.6 | 69% | 1115→530 | 0/3 identical (450 differences; 585 differences; 540 differences) | 3/3 identical |
| farm-rtt | 41.9 | 13.2 | 3.18x | 69.3 | 21.3 | 69% | 1072→549 | 0/3 identical (720 differences; 585 differences; 450 differences) | 3/3 identical |
| tarpit | 12.9 | 9.3 | 1.39x | 14.0 | 14.3 | -2% | 446→446 | 3/3 identical | 3/3 identical |
| closed | 139.4 | 12.4 | 11.25x | 202.2 | 21.7 | 89% | 2809→444 | open=0 closed=4000 filtered=0 | open=0 closed=4000 filtered=0 |
| filtered | 17.4 | 12.9 | 1.35x | 25.3 | 19.5 | 23% | 807→472 | open=0 closed=0 filtered=320 | open=0 closed=0 filtered=320 |
| startup | 3.1 | 3.4 | 0.90x | 4.2 | 4.8 | -13% | 326→356 | - | - |
| expand | 11.6 | 9.4 | 1.23x | 14.4 | 12.1 | 16% | 356→409 | - | - |

| Switched off | Scenario | full v2.1 wall / CPU s | without it wall / CPU s | contribution (wall, CPU) | accuracy without it |
|---|---|---:|---:|---:|---|
| literal prefilter | farm | 12.4 / 20.6 | 17.3 / 30.4 | 1.39x, 1.47x | 2/3 identical (17 differences) |
| literal prefilter | farm-rtt | 13.2 / 21.3 | 18.6 / 32.0 | 1.42x, 1.50x | 2/3 identical (6 differences) |
| scheduler + long-lived workers | closed | 12.4 / 21.7 | 156.5 / 229.9 | 12.63x, 10.58x | open=0 closed=4000 filtered=0 |
| scheduler + long-lived workers | filtered | 12.9 / 19.5 | 17.9 / 26.9 | 1.39x, 1.38x | open=0 closed=0 filtered=320 |
| scheduler + long-lived workers | farm | 12.4 / 20.6 | 32.9 / 53.1 | 2.66x, 2.57x | 3/3 identical |
| scheduler + long-lived workers | tarpit | 9.3 / 14.3 | 9.6 / 12.6 | 1.04x, 0.88x | 3/3 identical |
| silent-listener parallel TLS probes | tarpit | 9.3 / 14.3 | 12.5 / 19.2 | 1.34x, 1.34x | 3/3 identical |
| C# response parsing | farm | 12.4 / 20.6 | 14.1 / 23.8 | 1.14x, 1.15x | 2/3 identical (2 differences) |
| C# CSV/JSONL writer | farm | 12.4 / 20.6 | 14.0 / 23.8 | 1.13x, 1.15x | 2/3 identical (6 differences) |
| TLS warm-up + worker ramp | farm | 12.4 / 20.6 | 20.6 / 36.9 | 1.66x, 1.79x | 1/3 identical (45 differences; 180 differences) |
| TLS warm-up + worker ramp | farm-rtt | 13.2 / 21.3 | 21.7 / 37.4 | 1.65x, 1.76x | 1/3 identical (135 differences; 180 differences) |
| TLS warm-up | farm | 12.4 / 20.6 | 19.3 / 34.3 | 1.55x, 1.66x | 2/3 identical (51 differences) |
| worker ramp | farm | 12.4 / 20.6 | 13.1 / 22.2 | 1.05x, 1.07x | 2/3 identical (1 differences) |
| C# target expansion | expand | 9.4 / 12.1 | 10.7 / 13.5 | 1.14x, 1.11x | - |
| select-based connect | closed | 12.4 / 21.7 | 13.3 / 23.8 | 1.08x, 1.09x | open=0 closed=4000 filtered=0 |
| select-based connect | filtered | 12.9 / 19.5 | 12.6 / 16.2 | 0.98x, 0.83x | open=0 closed=0 filtered=320 |
