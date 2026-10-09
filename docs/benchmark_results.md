# ULPF Benchmark Results

Command: `python benchmark.py --count 20000`

Each configuration processes the same generated input through the shared `ulpf.ingest._process_line` implementation. API requests still use `process_line`, which commits both raw and normalized records per request. The benchmark-only helper reuses one SQLite connection per process; A commits after each event, while B/C/D commit after every 1,000 events. Every multiprocessing worker receives an evenly balanced input chunk and its own SQLite database. Event and raw-vault row counts are summed across worker databases and asserted equal to N after each trial. Configurations run three times; table seconds and rates are medians. Input generation, database setup, and 1,000-event warm-ups are outside measured intervals. SQLite uses `journal_mode=DELETE`, `synchronous=FULL` for all runs.

Hardware used: Intel Core i7-10610U, 4 physical cores / 8 logical processors, 32 GiB RAM, WDC PC SN520 NVMe SSD, Windows. Timings vary with host load and storage. Batching gain is B/A. Parallel speedups compare C/B and D/B only; multiprocessing is not compared with A.

```
Run                                    | Lines processed  | Vault rows   | Event rows   | Seconds (median)   | Events/sec (median) 
---------------------------------------+------------------+--------------+--------------+--------------------+---------------------
A) Single, commit/event                | 20,000           | 20,000       | 20,000       | 370.93             | 53.9                
B) Single, batch/1,000                 | 20,000           | 20,000       | 20,000       | 33.06              | 605.0               
C) Multiprocess, 4 workers, batch/1,000 | 20,000           | 20,000       | 20,000       | 15.97              | 1,252.3             
D) Multiprocess, 8 workers, batch/1,000 | 20,000           | 20,000       | 20,000       | 15.42              | 1,297.1             
```

Batching gain (B/A): 11.22x

Parallel speedup (C/B): 2.07x

Parallel speedup (D/B): 2.14x

Three trial durations (seconds):

- A) Single, commit/event: 370.93, 167.27, 480.68
- B) Single, batch/1,000: 33.06, 35.51, 27.85
- C) Multiprocess, 4 workers, batch/1,000: 15.97, 17.00, 13.68
- D) Multiprocess, 8 workers, batch/1,000: 15.70, 15.42, 13.02
