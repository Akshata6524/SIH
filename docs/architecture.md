# ULPF Architecture

ULPF is a local-first Python log ingestion and normalization prototype. This document distinguishes implemented behavior from a possible future scale-out design.

## Six-stage pipeline

```text
1. Receive line (HTTP, file upload, optional UDP)
       |
2. Store original text and SHA-256 in SQLite raw_events
       |
3. Guess format and match source against loaded YAML
       |
4. Parse configured fields or use generic fallback extraction
       |
5. Normalize event, retain extras, calculate quality
       |
6. Persist SQLite event + JSONL; expose query and export APIs
```

1. **Receive:** `POST /ingest` accepts one line or a list; `POST /upload` accepts `.log` and `.txt` files. An optional UDP listener uses port 5140 when `ULPF_UDP_ENABLED` is enabled.
2. **Retain:** A UUID and SHA-256 are created for the input string. SQLite stores the unmodified string, receive time, and optional source IP.
3. **Detect:** The detector recognizes syslog key-value, JSON, CSV, CEF, XML, and plain text. YAML `detect.contains` and `detect.regex` rules select a source config.
4. **Parse:** Configured parsers support syslog-kv, CSV, JSON, named-group regex, and CEF. If no config matches, generic extraction attempts timestamps, IP addresses, and key-value pairs. Parser exceptions are logged and fall back to a generic event.
5. **Normalize and score:** Config mappings and value maps populate the shared event structure. Parseable timestamps are converted to UTC; supported protocol numbers are named. Unmapped fields remain in `vendor_extras`; `parse_score` and `parse_status` describe mapping coverage.
6. **Persist and serve:** The event is written to SQLite `events` and `data/events.jsonl`. Event lookup, raw verification, stats, and export routes serve API clients; Streamlit reads these endpoints.

The API's `process_line` opens one SQLite connection and commits the raw and normalized records per request. Batched commits are only used by the separate benchmark helper; they are not an API ingestion option.

## Unified event summary

The normalizer emits version `1.0` events containing:

- `event_id`, `raw_event_id`, `raw_sha256`, `timestamp`, `ingest_time`
- `source` (vendor, product, format, device IP), `category`, `action`, `severity`
- `src` and `dst` (IP and port), `protocol`, `user`, `rule` (ID and name)
- `bytes` (in and out), `vendor_extras`, `parse_status`, `parse_score`, `schema_version`

When a value cannot populate a normalized slot, the original extracted value is retained in `vendor_extras` where applicable.

## Lossless retention and traceability

`ulpf.vault` writes raw text, UUID, digest, receive time, and optional source IP to SQLite `raw_events`. The digest is SHA-256 over the UTF-8 encoding of the input string. Each normalized event carries `raw_event_id` and `raw_sha256`. `GET /raw/{raw_event_id}` returns the saved text and a `verified` flag based on recomputing its digest.

Source fields not mapped to the unified event remain under `vendor_extras`. Unknown sources receive generic extraction rather than being intentionally discarded. This provides lineage from normalized event to raw text and exposes data that still needs a source-specific mapping.

## Plug-and-play onboarding

YAML files in `configs/` define source name/vendor/product, format, detection, mappings, and optional value maps, category, CSV columns, regex pattern, or timestamp rules. `/reload-configs` rereads the directory without restarting the API.

`POST /autogen` accepts sample lines and source metadata. It heuristically selects a dominant format, recognizes common field synonyms, guesses action maps/category/timestamp/detection, and returns config YAML plus a mapped/unmapped confidence report. With `save: true`, it writes `<name>.yaml` and reloads configs. Generated configs should be reviewed against real records; the inference is not a guarantee of correct parsing.

## Exporters

- **CEF:** `/export?format=cef` returns one CEF line per event, with available network fields and raw-event identifiers.
- **OCSF:** the converter uses Network Activity class UID 4001, includes available endpoint/traffic fields, places extras in `unmapped`, and fetches raw text for `raw_data`.
- **Parquet:** `/export?format=parquet` flattens nested fields and stores `vendor_extras` as JSON, using pandas and PyArrow.
- **JSON:** the API returns normalized event lists; the local exporter module also provides JSONL writing.

## Scale design and benchmark

**Implemented:** local FastAPI workers write to SQLite and a JSONL file. `benchmark.py` generates synthetic mixed-format records, warms each configuration with 1,000 lines, runs each configuration three times, and verifies stored row totals. The benchmark machine was an Intel Core i7-10610U (4 physical/8 logical processors), 32 GiB RAM, and a WDC PC SN520 NVMe SSD on Windows.

For 20,000 input lines, the report in `docs/benchmark_results.md` records:

| Configuration | Event rows / vault rows | Median seconds | Median events/sec |
|---|---:|---:|---:|
| Single process, commit per event | 20,000 / 20,000 | 370.93 | 53.9 |
| Single process, batch 1,000 | 20,000 / 20,000 | 33.06 | 605.0 |
| 4 processes, batch 1,000 | 20,000 / 20,000 | 15.97 | 1,252.3 |
| 8 processes, batch 1,000 | 20,000 / 20,000 | 15.42 | 1,297.1 |

These synthetic local measurements yield a batching gain of 11.22x (B/A), 2.07x parallel speedup (C/B), and 2.14x (D/B). They are not production capacity guarantees.

**Future design, not implemented:** a scale-out deployment could put stateless parser workers behind Kafka partitions, partitioned by source/device as appropriate. This repository has no Kafka, distributed worker service, or shared production store; SQLite/JSONL would need replacement for multi-host persistence. The local benchmark does not measure that architecture.

## Air-gapped operation

By default the dashboard talks to the local API. Compose runs API and dashboard from the same image and mounts host `data/` and `configs/`. Scripts save the built image with `docker save` and load it with `docker load`. Docker/Compose and the built image must be prepared before moving to the offline host; the preloaded image can start without downloading application dependencies. Runtime ingestion has no external-service dependency.

## Limitations

- The five bundled sources and AcmeFW demo are sample fixtures, not a comprehensive vendor/version corpus.
- XML/plain text detection exists, but configured parsing covers syslog-kv, CSV, JSON, regex, and CEF only.
- The anomaly page can submit synthetic FortiGate demo traffic; it is not real telemetry.
- Benchmark evidence is limited to the documented synthetic workload and one host; broader scale is a design estimate.
- SQLite, local JSONL, Kafka absence, and lack of distributed fault tolerance limit the current deployment scope.
