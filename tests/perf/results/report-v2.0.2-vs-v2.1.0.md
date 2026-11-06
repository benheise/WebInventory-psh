| Scenario | v2.0.2 wall s | v2.1 wall s | speed-up | v2.0.2 CPU s | v2.1 CPU s | CPU saved | peak RSS MB (old→new) | accuracy v2.0.2 | accuracy v2.1 |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| lab | 40.3 | 39.4 | 1.02x | 17.0 | 12.8 | 24% | 387→409 | 3/3 identical | 3/3 identical |
| farm | 39.7 | 12.4 | 3.21x | 67.1 | 19.8 | 70% | 1115→543 | 0/3 identical (450 differences; 585 differences; 540 differences) | 3/3 identical |
| farm-rtt | 41.9 | 13.0 | 3.22x | 69.3 | 20.4 | 71% | 1072→534 | 0/3 identical (720 differences; 585 differences; 450 differences) | 3/3 identical |
| tarpit | 12.9 | 8.1 | 1.59x | 14.0 | 10.0 | 29% | 446→430 | 3/3 identical | 3/3 identical |
| closed | 139.4 | 12.1 | 11.56x | 202.2 | 20.2 | 90% | 2809→459 | open=0 closed=4000 filtered=0 | open=0 closed=4000 filtered=0 |
| filtered | 17.4 | 12.8 | 1.36x | 25.3 | 12.3 | 51% | 807→436 | open=0 closed=0 filtered=320 | open=0 closed=0 filtered=320 |
| startup | 3.1 | 3.6 | 0.85x | 4.2 | 5.0 | -17% | 326→366 | - | - |
| expand | 11.6 | 8.9 | 1.30x | 14.4 | 11.5 | 20% | 356→406 | - | - |

| Switched off | Scenario | full v2.1 wall / CPU s | without it wall / CPU s | contribution (wall, CPU) | accuracy without it |
|---|---|---:|---:|---:|---|
| literal prefilter | farm | 12.4 / 19.8 | 17.3 / 30.4 | 1.40x, 1.53x | 2/3 identical (17 differences) |
| literal prefilter | farm-rtt | 13.0 / 20.4 | 18.6 / 32.0 | 1.44x, 1.57x | 2/3 identical (6 differences) |
| scheduler + long-lived workers | closed | 12.1 / 20.2 | 156.5 / 229.9 | 12.98x, 11.36x | open=0 closed=4000 filtered=0 |
| scheduler + long-lived workers | filtered | 12.8 / 12.3 | 17.9 / 26.9 | 1.40x, 2.18x | open=0 closed=0 filtered=320 |
| scheduler + long-lived workers | farm | 12.4 / 19.8 | 32.9 / 53.1 | 2.67x, 2.68x | 3/3 identical |
| scheduler + long-lived workers | tarpit | 8.1 / 10.0 | 9.6 / 12.6 | 1.18x, 1.27x | 3/3 identical |
| silent-listener parallel TLS probes | tarpit | 8.1 / 10.0 | 12.5 / 19.2 | 1.53x, 1.93x | 3/3 identical |
| C# response parsing | farm | 12.4 / 19.8 | 14.1 / 23.8 | 1.14x, 1.20x | 2/3 identical (2 differences) |
| C# CSV/JSONL writer | farm | 12.4 / 19.8 | 14.0 / 23.8 | 1.13x, 1.20x | 2/3 identical (6 differences) |
| TLS warm-up + worker ramp | farm | 12.4 / 19.8 | 20.6 / 36.9 | 1.67x, 1.86x | 1/3 identical (45 differences; 180 differences) |
| TLS warm-up + worker ramp | farm-rtt | 13.0 / 20.4 | 21.7 / 37.4 | 1.67x, 1.84x | 1/3 identical (135 differences; 180 differences) |
| TLS warm-up | farm | 12.4 / 19.8 | 19.3 / 34.3 | 1.56x, 1.73x | 2/3 identical (51 differences) |
| worker ramp | farm | 12.4 / 19.8 | 13.1 / 22.2 | 1.06x, 1.12x | 2/3 identical (1 differences) |
| C# target expansion | expand | 8.9 / 11.5 | 10.7 / 13.5 | 1.21x, 1.18x | - |
| select-based connect | closed | 12.1 / 20.2 | 13.3 / 23.8 | 1.11x, 1.17x | open=0 closed=4000 filtered=0 |
| select-based connect | filtered | 12.8 / 12.3 | 12.6 / 16.2 | 0.98x, 1.32x | open=0 closed=0 filtered=320 |
