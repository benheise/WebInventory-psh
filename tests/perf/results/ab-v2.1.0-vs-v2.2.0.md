# Interleaved A/B: v2.1.0 vs v2.2.0 (scan path)

Same lab, same session, versions alternating per round. bench.py lines (one run per scenario per round):

```
ab21-1     farm      run1 wall=  17.40s cpu=  27.59s rss= 637.0MB req=1400 rows=200 exit=0 scan_s=15.75 startup_s=2.46 targets_s=0.21
ab21-1     lab       run1 wall=  40.63s cpu=  14.79s rss= 529.6MB req=457 rows=26 exit=2 scan_s=38.86 startup_s=2.39 targets_s=0.24
ab21-1     closed    run1 wall=  13.98s cpu=  23.34s rss= 591.7MB req=0 rows=0 exit=0 scan_s=12.39 startup_s=2.14 targets_s=0.16
ab21-1     startup   run1 wall=   3.51s cpu=   4.94s rss= 384.3MB req=- rows=- exit=0 list_s=0.01 startup_s=1.84 targets_s=0.14
ab21-1     farm-ref  run1 wall=  21.92s cpu=  18.49s rss= 568.2MB req=1400 rows=200 exit=0 scan_s=20.34 startup_s=1.92 targets_s=0.19
ab22-1     farm      run1 wall=  13.47s cpu=  21.63s rss= 630.5MB req=1400 rows=200 exit=0 scan_s=11.77 startup_s=1.94 targets_s=0.15
ab22-1     lab       run1 wall=  39.94s cpu=  14.19s rss= 566.6MB req=457 rows=26 exit=2 scan_s=38.19 startup_s=2.00 targets_s=0.24
ab22-1     closed    run1 wall=  14.16s cpu=  24.01s rss= 609.6MB req=0 rows=0 exit=0 scan_s=12.43 startup_s=1.93 targets_s=0.21
ab22-1     startup   run1 wall=   3.56s cpu=   4.93s rss= 445.9MB req=- rows=- exit=0 list_s=0.02 startup_s=1.89 targets_s=0.19
ab22-1     farm-ref  run1 wall=  23.10s cpu=  20.66s rss= 580.4MB req=1400 rows=200 exit=0 scan_s=21.29 startup_s=2.02 targets_s=0.17
ab21-2     farm      run1 wall=  16.44s cpu=  27.12s rss= 642.4MB req=1400 rows=200 exit=0 scan_s=14.37 startup_s=2.35 targets_s=0.17
ab21-2     lab       run1 wall=  40.22s cpu=  15.02s rss= 522.8MB req=457 rows=26 exit=2 scan_s=38.53 startup_s=2.10 targets_s=0.21
ab21-2     closed    run1 wall=  14.09s cpu=  23.67s rss= 594.9MB req=0 rows=0 exit=0 scan_s=12.08 startup_s=1.99 targets_s=0.15
ab21-2     startup   run1 wall=   4.30s cpu=   6.02s rss= 381.9MB req=- rows=- exit=0 list_s=0.01 startup_s=2.42 targets_s=0.17
ab21-2     farm-ref  run1 wall=  23.34s cpu=  21.55s rss= 559.3MB req=1400 rows=200 exit=0 scan_s=21.30 startup_s=2.16 targets_s=0.18
ab22-2     farm      run1 wall=  16.05s cpu=  26.15s rss= 634.9MB req=1400 rows=200 exit=0 scan_s=14.03 startup_s=2.49 targets_s=0.18
ab22-2     lab       run1 wall=  39.99s cpu=  14.26s rss= 565.8MB req=457 rows=26 exit=2 scan_s=38.34 startup_s=1.95 targets_s=0.23
ab22-2     closed    run1 wall=  15.37s cpu=  26.00s rss= 592.8MB req=0 rows=0 exit=0 scan_s=13.54 startup_s=2.28 targets_s=0.17
ab22-2     startup   run1 wall=   3.54s cpu=   5.07s rss= 445.8MB req=- rows=- exit=0 list_s=0.01 startup_s=1.80 targets_s=0.19
ab22-2     farm-ref  run1 wall=  22.70s cpu=  20.95s rss= 538.8MB req=1400 rows=200 exit=0 scan_s=21.05 startup_s=2.12 targets_s=0.17
ab21-3     farm      run1 wall=  15.70s cpu=  25.32s rss= 650.5MB req=1400 rows=200 exit=0 scan_s=13.86 startup_s=2.19 targets_s=0.18
ab21-3     lab       run1 wall=  40.41s cpu=  15.83s rss= 541.9MB req=457 rows=26 exit=2 scan_s=38.61 startup_s=2.12 targets_s=0.23
ab21-3     closed    run1 wall=  14.46s cpu=  24.17s rss= 617.7MB req=0 rows=0 exit=0 scan_s=12.64 startup_s=2.30 targets_s=0.16
ab21-3     startup   run1 wall=   4.19s cpu=   5.92s rss= 383.7MB req=- rows=- exit=0 list_s=0.01 startup_s=2.29 targets_s=0.18
ab21-3     farm-ref  run1 wall=  22.59s cpu=  20.47s rss= 556.7MB req=1400 rows=200 exit=0 scan_s=20.85 startup_s=1.94 targets_s=0.20
ab22-3     farm      run1 wall=  15.52s cpu=  25.38s rss= 634.1MB req=1400 rows=200 exit=0 scan_s=13.81 startup_s=1.98 targets_s=0.23
ab22-3     lab       run1 wall=  40.58s cpu=  15.23s rss= 560.3MB req=457 rows=26 exit=2 scan_s=38.72 startup_s=2.14 targets_s=0.20
ab22-3     closed    run1 wall=  15.50s cpu=  26.45s rss= 584.7MB req=0 rows=0 exit=0 scan_s=13.89 startup_s=1.91 targets_s=0.17
ab22-3     startup   run1 wall=   4.82s cpu=   6.77s rss= 445.3MB req=- rows=- exit=0 list_s=0.02 startup_s=2.36 targets_s=0.29
ab22-3     farm-ref  run1 wall=  23.45s cpu=  21.36s rss= 583.6MB req=1400 rows=200 exit=0 scan_s=21.35 startup_s=2.02 targets_s=0.20
```

Field-by-field accuracy (tests/perf/golden.py):

```
=== accuracy: v2.2.0 outputs vs v2.1.0 outputs, field by field
round 1 farm      golden: 200 rows reference, 200 rows candidate, 0 differences
round 1 lab       golden: 26 rows reference, 26 rows candidate, 0 differences
round 1 farm-ref  golden: 200 rows reference, 200 rows candidate, 0 differences
round 2 farm      golden: 200 rows reference, 200 rows candidate, 0 differences
round 2 lab       golden: 26 rows reference, 26 rows candidate, 0 differences
round 2 farm-ref  golden: 200 rows reference, 200 rows candidate, 0 differences
round 3 farm      golden: 200 rows reference, 200 rows candidate, 0 differences
round 3 lab       golden: 26 rows reference, 26 rows candidate, 0 differences
round 3 farm-ref  golden: 200 rows reference, 200 rows candidate, 0 differences
=== farm (64 threads) vs farm-ref (4 threads, 10 s timeouts), v2.2.0
round 1 golden: 200 rows reference, 200 rows candidate, 0 differences
round 2 golden: 200 rows reference, 200 rows candidate, 0 differences
round 3 golden: 200 rows reference, 200 rows candidate, 0 differences
```

Startup and closed-port sweep, 5 interleaved rounds (wall, CPU, peak RSS of the pwsh process):

```
v21 round 1  startup: 3.5 s wall, 4.9 s cpu, 345 MB maxrss, rc=0  |  closed: 12.1 s wall, 20.5 s cpu, 479 MB maxrss, rc=0
v22 round 1  startup: 3.9 s wall, 5.5 s cpu, 359 MB maxrss, rc=0  |  closed: 12.5 s wall, 20.7 s cpu, 443 MB maxrss, rc=0
v21 round 2  startup: 3.6 s wall, 5.0 s cpu, 347 MB maxrss, rc=0  |  closed: 13.0 s wall, 22.2 s cpu, 475 MB maxrss, rc=0
v22 round 2  startup: 3.8 s wall, 5.2 s cpu, 355 MB maxrss, rc=0  |  closed: 12.9 s wall, 21.7 s cpu, 467 MB maxrss, rc=0
v21 round 3  startup: 3.7 s wall, 5.2 s cpu, 361 MB maxrss, rc=0  |  closed: 12.4 s wall, 21.0 s cpu, 455 MB maxrss, rc=0
v22 round 3  startup: 3.8 s wall, 5.3 s cpu, 364 MB maxrss, rc=0  |  closed: 13.3 s wall, 22.4 s cpu, 476 MB maxrss, rc=0
v21 round 4  startup: 3.8 s wall, 5.2 s cpu, 365 MB maxrss, rc=0  |  closed: 12.2 s wall, 20.5 s cpu, 471 MB maxrss, rc=0
v22 round 4  startup: 3.7 s wall, 5.2 s cpu, 360 MB maxrss, rc=0  |  closed: 12.8 s wall, 21.4 s cpu, 478 MB maxrss, rc=0
v21 round 5  startup: 3.8 s wall, 5.3 s cpu, 346 MB maxrss, rc=0  |  closed: 12.4 s wall, 20.6 s cpu, 464 MB maxrss, rc=0
v22 round 5  startup: 3.8 s wall, 5.2 s cpu, 356 MB maxrss, rc=0  |  closed: 12.1 s wall, 20.4 s cpu, 471 MB maxrss, rc=0
```
