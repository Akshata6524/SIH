# ULPF — Universal Log Pre-processing Framework

## Problem

Perimeter devices produce logs in vendor-specific formats that are difficult to analyze together.
Parsing can lose original context, and onboarding another device often requires code changes.
ULPF is a local-first prototype for retaining, parsing, and normalizing these records.

## What ULPF does

ULPF accepts log lines through a FastAPI service, matches configured sources, parses known formats, and produces a common event structure. It stores the original text and SHA-256 digest in SQLite, retains parsed fields it cannot map in `vendor_extras`, and provides lookup and export endpoints.

Source parser definitions live in `configs/`. Add a YAML file and reload the configs, or generate a candidate from representative samples with `/autogen`. A Streamlit dashboard provides overview, trace, quality, onboarding, and anomaly pages.

## Architecture

See [the architecture notes](docs/architecture.md) for the pipeline, schema, retention, exporters, benchmark, and scale-out design boundary.

```text
Device logs
    |
    v
FastAPI /ingest, /upload, optional UDP syslog
    |
    +--> SQLite raw_events: exact text + SHA-256 + receipt metadata
    |
    v
Format guess + YAML source match
    |
    +--> Configured parser (syslog-kv / CSV / JSON / regex / CEF)
    |
    +--> Generic extraction for unknown sources
    |
    v
Normalize to unified event + preserve vendor_extras + score quality
    |
    +--> SQLite events
    +--> data/events.jsonl
    |
    +--> /events, /raw, /stats, /export
              |
              +--> Streamlit dashboard
```

## Features mapped to requirements a-k

| Requirement | Feature in this project |
|---|---|
| a. Lossless input retention | Original UTF-8 log text is stored in SQLite `raw_events` with a UUID, SHA-256, receive time, and optional source IP. |
| b. Traceability | Normalized events carry `raw_event_id` and `raw_sha256`; `GET /raw/{raw_event_id}` returns the stored text and verifies its digest. |
| c. No-code source onboarding | Source rules are YAML files in `configs/`; `/reload-configs` reloads them without an API restart. |
| d. Preserve unmapped fields | Fields not mapped by a source config remain in `vendor_extras`. |
| e. Unknown-source fallback | Unknown or unparseable lines are retained and generic extraction attempts timestamps, IP addresses, and key-value pairs. |
| f. Parse quality | Events receive `parse_score` and `parse_status` (`success`, `partial`, or `failed`). |
| g. Multiple log formats | The configured parser supports syslog key-value, CSV, JSON, named-group regex, and CEF. The detector also recognizes XML/plain text, but there is no configured XML parser. |
| h. Unified analytics event | The normalizer emits the shared event structure, including source, category, action, endpoints, protocol, user, rule, byte counts, extras, and schema version. |
| i. Ingestion and query API | FastAPI provides `/ingest`, `/upload`, `/events`, `/stats`, health/docs routes, and an optional UDP listener on port 5140. |
| j. Export | Export endpoints support CEF, OCSF Network Activity, JSON, and Parquet. |
| k. Dashboard and offline packaging | Streamlit presents event, trace, quality, onboarding, and anomaly views; Docker and image save/load scripts support offline deployment. |

## Setup without Docker

Use Python 3.11 or another compatible Python version and create a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Start the API, dashboard, and sample loader in separate terminals from the project root:

```powershell
uvicorn ulpf.ingest:app --reload
```

```powershell
streamlit run dashboard/app.py
```

```powershell
python scripts/load_samples.py
```

The API docs are at <http://127.0.0.1:8000/docs>; the dashboard is at <http://127.0.0.1:8501>. The dashboard's API URL defaults to `http://127.0.0.1:8000` and can be changed in its sidebar or with `ULPF_API_URL`.

## Setup with Docker

Build the API/dashboard image and start both services:

```sh
docker compose up --build
```

The API is published on port 8000 and the dashboard on port 8501. Compose mounts `./data` and `./configs` from the host, so the SQLite/JSONL data and generated configs persist outside the containers. The API health endpoint is `GET /health`.

## Offline install

On a machine with Docker and the required image build dependencies available, build and save the image:

```sh
sh scripts/build_offline_bundle.sh
```

This creates `ulpf-offline.tar`. Transfer that tar file, the project files (including `docker-compose.yml` and configs), and an installed Docker Engine/Compose plugin to the air-gapped host. From the project root on that host, load the saved image and start the services:

```sh
sh scripts/offline_install.sh
```

PowerShell equivalents are `scripts/build_offline_bundle.ps1` and `scripts/offline_install.ps1`. Building the image and installing Python dependencies are preparation steps; the image-load/start path on the target host does not download application dependencies. By default, application traffic is local between the dashboard and API; no external service integration is required.

## How to onboard a new source

### Add a YAML config

Copy a config into `configs/` and adapt its detection, field names, and timestamp rule. For example:

```yaml
name: fortigate
vendor: Fortinet
product: FortiGate
format: syslog-kv
detect:
  contains: "devname="
mapping:
  srcip: src.ip
  srcport: src.port
  dstip: dst.ip
  dstport: dst.port
  proto: protocol
  action: action
  policyid: rule.id
  sentbyte: bytes.out
  rcvdbyte: bytes.in
value_maps:
  action:
    deny: block
    accept: allow
category: network_activity
timestamp:
  fields: [date, time]
  format: "%Y-%m-%d %H:%M:%S"
  tz: UTC
```

Then activate it without restarting:

```sh
curl -X POST http://127.0.0.1:8000/reload-configs
```

### Generate a candidate with `/autogen`

Send representative lines and source metadata to `POST /autogen`. With `"save": false`, the API returns a generated config, YAML, and mapped/unmapped confidence report without writing a file. With `"save": true`, it writes `<name>.yaml` to `configs/` and reloads configs so the parser can be used immediately.

```json
{
  "samples": [
    "ts=2026-10-03T10:20:01 device=AcmeFW client_ip=192.168.1.10 sport=40001 server_ip=1.1.1.1 dport=443 verdict=denied user=ravi"
  ],
  "name": "acmefw",
  "vendor": "Acme",
  "product": "AcmeFW",
  "save": false
}
```

Auto-generated configs are heuristics: inspect the mapping, detection rule, and timestamp format against your own records before relying on them.

## Run tests

Run the test suite from the project root:

```sh
python -m pytest tests/ -v
```

The sample retention test processes the five bundled sample sources and checks that raw-vault row counts match submitted records.

## Benchmark results

The following is copied from [`docs/benchmark_results.md`](docs/benchmark_results.md). It is a local synthetic-data benchmark, not a production capacity claim.

Hardware used: Intel Core i7-10610U, 4 physical cores / 8 logical processors, 32 GiB RAM, WDC PC SN520 NVMe SSD, Windows.

```text
Run                                    | Lines processed  | Vault rows   | Event rows   | Seconds (median)   | Events/sec (median) 
---------------------------------------+------------------+--------------+--------------+--------------------+---------------------
A) Single, commit/event                | 20,000           | 20,000       | 20,000       | 370.93             | 53.9                
B) Single, batch/1,000                 | 20,000           | 20,000       | 20,000       | 33.06              | 605.0               
C) Multiprocess, 4 workers, batch/1,000 | 20,000           | 20,000       | 20,000       | 15.97              | 1,252.3             
D) Multiprocess, 8 workers, batch/1,000 | 20,000           | 20,000       | 20,000       | 15.42              | 1,297.1             
```

- Batching gain (B/A): **11.22x**
- Parallel speedup (C/B): **2.07x**
- Parallel speedup (D/B): **2.14x**

Each configuration ran three times; the table reports median durations and rates. Input generation, database setup, and 1,000-line warm-up are outside the timed interval. Each run verifies exactly 20,000 rows in both the raw vault and event table. The three trial durations and benchmark method are recorded in `docs/benchmark_results.md`.

## Limitations

- Parser behavior and quality have been tested against the bundled sample logs; this is not validation against a comprehensive vendor log corpus.
- The dashboard anomaly page offers synthetic FortiGate demo traffic when there are too few events. Generated traffic is not real telemetry.
- The measured benchmark is a local synthetic workload on one machine. It is evidence for that run only; scale beyond it is a design estimate, not a demonstrated production capacity.
- The current service stores data in SQLite and writes a local JSONL file. It does not include a Kafka deployment, distributed ingestion service, or production cluster manager.
- XML and plain text can be identified by the detector, but source-configured extraction is implemented for syslog-kv, CSV, JSON, regex, and CEF.

## Project structure

```text
.
├── configs/                 YAML source parsers
├── dashboard/app.py         Streamlit dashboard
├── data/                    Runtime SQLite and JSONL data
├── docs/                    Architecture and benchmark report
├── sample_logs/             Five bundled 20-line sample sources
├── schema/                  Unified schema artifact
├── scripts/                 Sample loader and offline image scripts
├── tests/                   Unit and pipeline tests
├── ulpf/
│   ├── autogen.py            Parser config generation
│   ├── detector.py           Format and source detection
│   ├── exporters.py          CEF, OCSF, JSONL, and Parquet conversion
│   ├── ingest.py             FastAPI pipeline and endpoints
│   ├── normalizer.py         Unified event normalization
│   ├── parser_engine.py      Configured log parsers
│   ├── quality.py            Parse scoring
│   └── vault.py              SQLite raw-event storage
├── benchmark.py              Local throughput benchmark
├── docker-compose.yml        API and dashboard services
├── Dockerfile                Python container image
├── requirements.txt          Pinned Python dependencies
├── try_autogen.py            API onboarding demonstration
└── try_it.py                 API ingestion demonstration
```
