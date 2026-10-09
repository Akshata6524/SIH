"""Compare ULPF per-event commits, batching, and multiprocess throughput."""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import platform
import random
import sqlite3
import statistics
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ulpf import ingest, parser_engine, vault


PROJECT_ROOT = Path(__file__).resolve().parent
REPETITIONS = 3
WARMUP_COUNT = 1000
BATCH_SIZE = 1000
WORKER_COUNTS = (4, 8)
PUBLIC_NETWORKS = (8, 9, 23, 45, 52, 93, 142, 151, 203)


def _random_ip(rng: random.Random, internal: bool) -> str:
    if internal:
        if rng.randrange(2):
            return f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
        return f"192.168.{rng.randrange(256)}.{rng.randrange(1, 255)}"
    return (
        f"{rng.choice(PUBLIC_NETWORKS)}.{rng.randrange(256)}."
        f"{rng.randrange(256)}.{rng.randrange(1, 255)}"
    )


def generate_lines(count: int, seed: int = 20261004) -> list[str]:
    """Generate varied FortiGate, key/value ASA, and Suricata JSON events."""
    rng = random.Random(seed)
    start = datetime(2026, 10, 4, tzinfo=timezone.utc)
    lines: list[str] = []

    for index in range(count):
        timestamp = start + timedelta(seconds=index)
        source_ip = _random_ip(rng, internal=True)
        destination_ip = _random_ip(rng, internal=False)
        source_port = rng.randrange(1024, 65536)
        destination_port = rng.choice((22, 25, 53, 80, 443, 445, 3389, 8080))
        action = rng.choice(("deny", "accept"))
        protocol = rng.choice(("tcp", "udp"))
        bytes_out = rng.randrange(40, 8192)
        bytes_in = rng.randrange(0, 16384)

        if index % 3 == 0:
            lines.append(
                f'date={timestamp:%Y-%m-%d} time={timestamp:%H:%M:%S} '
                f'devname="FGT-BENCH" srcip={source_ip} srcport={source_port} '
                f'dstip={destination_ip} dstport={destination_port} proto={protocol} '
                f'action={action} policyid={rng.randrange(1, 1000)} '
                f'sentbyte={bytes_out} rcvdbyte={bytes_in}'
            )
        elif index % 3 == 1:
            lines.append(
                f"device=ASA-5516 date={timestamp:%Y-%m-%d} time={timestamp:%H:%M:%S} "
                f"src_ip={source_ip} src_port={source_port} dst_ip={destination_ip} "
                f"dst_port={destination_port} protocol={protocol} action="
                f"{'block' if action == 'deny' else 'allow'} "
                f"rule_id={rng.randrange(1, 1000)} bytes_out={bytes_out}"
            )
        else:
            document: dict[str, Any] = {
                "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
                "flow_id": index + 1,
                "in_iface": "eth0",
                "event_type": "alert",
                "src_ip": source_ip,
                "src_port": source_port,
                "dest_ip": destination_ip,
                "dest_port": destination_port,
                "proto": protocol.upper(),
                "action": "blocked" if action == "deny" else "allowed",
                "sensor_id": "SURI-01",
                "alert": {
                    "signature": "ULPF benchmark synthetic event",
                    "severity": rng.randrange(1, 5),
                },
            }
            lines.append(json.dumps(document, separators=(",", ":")))
    return lines


def _initialize_database(database_path: str) -> None:
    """Prepare a database with the same SQLite settings for every benchmark."""
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(path))) as connection:
        with connection:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """
                CREATE TABLE raw_events (
                    raw_event_id TEXT PRIMARY KEY,
                    raw_sha256 TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    source_ip TEXT,
                    raw_text TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE events (
                    event_id TEXT PRIMARY KEY,
                    raw_event_id TEXT NOT NULL,
                    event_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX idx_events_raw_event_id ON events(raw_event_id)"
            )


def _prepare_process(database_path: str, events_path: str) -> None:
    """Set per-process storage paths without reloading parser configuration."""
    vault.DB_PATH = Path(database_path)
    ingest.EVENTS_JSONL_PATH = Path(events_path)


def _process_lines(
    lines: list[str],
    database_path: str,
    events_path: str,
    batch_size: int,
) -> dict[str, Any]:
    """Process one run on one persistent connection using a chosen commit size."""
    _initialize_database(database_path)
    _prepare_process(database_path, events_path)
    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=FULL")
    processed = 0
    started = time.perf_counter()
    try:
        for line in lines:
            ingest._process_line(line, None, connection)
            processed += 1
            if processed % batch_size == 0:
                connection.commit()
        connection.commit()
    finally:
        connection.close()
    seconds = max(time.perf_counter() - started, 1e-9)
    event_rows, vault_rows = _count_rows([database_path])
    _assert_counts("single-process", processed, event_rows, vault_rows, len(lines))
    return {
        "lines_processed": processed,
        "vault_rows": vault_rows,
        "event_rows": event_rows,
        "seconds": seconds,
        "events_per_second": processed / seconds,
    }


def _initialize_worker() -> None:
    """Load parser configs once in each multiprocessing worker process."""
    ingest.CONFIG_DIR = parser_engine.CONFIG_DIR
    ingest.CONFIGS = parser_engine.load_configs(ingest.CONFIG_DIR)


def _process_worker_chunk(
    task: tuple[list[str], str, str],
) -> tuple[int, float]:
    """Process one balanced chunk, committing every 1,000 events."""
    lines, database_path, events_path = task
    _prepare_process(database_path, events_path)
    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=FULL")
    processed = 0
    try:
        for line in lines:
            event = ingest._process_line(line, None, connection)
            processed += 1
            if processed % BATCH_SIZE == 0:
                connection.commit()
        connection.commit()
    finally:
        connection.close()
    return processed, 0.0


def _balanced_chunks(lines: list[str], workers: int) -> list[list[str]]:
    """Split lines into contiguous chunks with sizes differing by at most one."""
    base_size, remainder = divmod(len(lines), workers)
    chunks: list[list[str]] = []
    start = 0
    for index in range(workers):
        size = base_size + (1 if index < remainder else 0)
        chunks.append(lines[start : start + size])
        start += size
    return chunks


def _count_rows(database_paths: list[str]) -> tuple[int, int]:
    """Sum event and raw-vault rows across all run databases."""
    event_rows = 0
    vault_rows = 0
    for database_path in database_paths:
        with closing(sqlite3.connect(database_path)) as connection:
            event_rows += int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            vault_rows += int(
                connection.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
            )
    return event_rows, vault_rows


def _assert_counts(
    run_label: str,
    processed: int,
    event_rows: int,
    vault_rows: int,
    expected: int,
) -> None:
    if processed != expected or event_rows != expected or vault_rows != expected:
        raise AssertionError(
            f"{run_label} mismatch: processed={processed}, events={event_rows}, "
            f"vault={vault_rows}, expected={expected}"
        )


def _prepare_worker_tasks(
    root: Path, lines: list[str], workers: int, run_name: str
) -> tuple[list[tuple[list[str], str, str]], list[str]]:
    chunks = _balanced_chunks(lines, workers)
    tasks: list[tuple[list[str], str, str]] = []
    database_paths: list[str] = []
    for index, chunk in enumerate(chunks):
        worker_directory = root / f"{run_name}-worker-{index}"
        worker_directory.mkdir(parents=True)
        database_path = str(worker_directory / "events.sqlite3")
        _initialize_database(database_path)
        tasks.append(
            (chunk, database_path, str(worker_directory / "events.jsonl"))
        )
        database_paths.append(database_path)
    if sum(len(chunk) for chunk in chunks) != len(lines):
        raise AssertionError(f"{run_name} chunks do not cover the input exactly")
    if chunks and max(map(len, chunks)) - min(map(len, chunks)) > 1:
        raise AssertionError(f"{run_name} chunks are not evenly balanced")
    return tasks, database_paths


def _run_multiprocess_trial(
    executor: ProcessPoolExecutor,
    root: Path,
    lines: list[str],
    workers: int,
    trial_number: int,
) -> dict[str, Any]:
    run_label = f"multiprocess-{workers}-trial-{trial_number}"
    tasks, database_paths = _prepare_worker_tasks(root, lines, workers, run_label)
    started = time.perf_counter()
    results = list(executor.map(_process_worker_chunk, tasks))
    seconds = max(time.perf_counter() - started, 1e-9)
    processed = sum(item[0] for item in results)
    event_rows, vault_rows = _count_rows(database_paths)
    _assert_counts(run_label, processed, event_rows, vault_rows, len(lines))
    return {
        "lines_processed": processed,
        "vault_rows": vault_rows,
        "event_rows": event_rows,
        "seconds": seconds,
        "events_per_second": processed / seconds,
    }


def _median_run(mode: str, trials: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "mode": mode,
        "lines_processed": int(statistics.median(item["lines_processed"] for item in trials)),
        "vault_rows": int(statistics.median(item["vault_rows"] for item in trials)),
        "event_rows": int(statistics.median(item["event_rows"] for item in trials)),
        "seconds": statistics.median(item["seconds"] for item in trials),
        "events_per_second": statistics.median(
            item["events_per_second"] for item in trials
        ),
        "trial_seconds": [item["seconds"] for item in trials],
    }


def _format_results(rows: list[dict[str, Any]]) -> str:
    headers = (
        "Run",
        "Lines processed",
        "Vault rows",
        "Event rows",
        "Seconds (median)",
        "Events/sec (median)",
    )
    widths = (38, 16, 12, 12, 18, 20)
    output = [
        " | ".join(header.ljust(width) for header, width in zip(headers, widths)),
        "-+-".join("-" * width for width in widths),
    ]
    for row in rows:
        values = (
            row["mode"],
            f"{row['lines_processed']:,}",
            f"{row['vault_rows']:,}",
            f"{row['event_rows']:,}",
            f"{row['seconds']:.2f}",
            f"{row['events_per_second']:,.1f}",
        )
        output.append(
            " | ".join(str(value).ljust(width) for value, width in zip(values, widths))
        )
    return "\n".join(output)


def run_benchmark(count: int) -> tuple[list[dict[str, Any]], dict[str, float]]:
    """Run all four configurations three times and return their median results."""
    if count < 1:
        raise ValueError("--count must be a positive integer")

    lines = generate_lines(count)
    warmup_lines = generate_lines(WARMUP_COUNT, seed=20261005)
    original_db_path = vault.DB_PATH
    original_events_path = ingest.EVENTS_JSONL_PATH
    original_configs = ingest.CONFIGS
    results: list[dict[str, Any]] = []
    try:
        ingest.CONFIGS = parser_engine.load_configs(parser_engine.CONFIG_DIR)
        with tempfile.TemporaryDirectory(prefix="ulpf-benchmark-") as temp_root:
            root = Path(temp_root)

            # Warm each single-process mode before collecting any timed samples.
            _process_lines(
                warmup_lines,
                str(root / "warmup-a.sqlite3"),
                str(root / "warmup-a.jsonl"),
                batch_size=1,
            )
            _process_lines(
                warmup_lines,
                str(root / "warmup-b.sqlite3"),
                str(root / "warmup-b.jsonl"),
                batch_size=BATCH_SIZE,
            )

            pools: dict[int, ProcessPoolExecutor] = {}
            try:
                for worker_count in WORKER_COUNTS:
                    executor = ProcessPoolExecutor(
                        max_workers=worker_count,
                        mp_context=multiprocessing.get_context("spawn"),
                        initializer=_initialize_worker,
                    )
                    pools[worker_count] = executor
                    warm_tasks, warm_databases = _prepare_worker_tasks(
                        root, warmup_lines, worker_count, f"warmup-{worker_count}"
                    )
                    warm_results = list(executor.map(_process_worker_chunk, warm_tasks))
                    warm_processed = sum(item[0] for item in warm_results)
                    warm_events, warm_vault = _count_rows(warm_databases)
                    _assert_counts(
                        f"warmup-{worker_count}",
                        warm_processed,
                        warm_events,
                        warm_vault,
                        WARMUP_COUNT,
                    )

                single_per_event_trials: list[dict[str, Any]] = []
                single_batched_trials: list[dict[str, Any]] = []
                parallel_trials: dict[int, list[dict[str, Any]]] = {
                    worker_count: [] for worker_count in WORKER_COUNTS
                }

                for trial_number in range(1, REPETITIONS + 1):
                    single_per_event_trials.append(
                        _process_lines(
                            lines,
                            str(root / f"a-trial-{trial_number}.sqlite3"),
                            str(root / f"a-trial-{trial_number}.jsonl"),
                            batch_size=1,
                        )
                    )
                    single_batched_trials.append(
                        _process_lines(
                            lines,
                            str(root / f"b-trial-{trial_number}.sqlite3"),
                            str(root / f"b-trial-{trial_number}.jsonl"),
                            batch_size=BATCH_SIZE,
                        )
                    )
                    for worker_count in WORKER_COUNTS:
                        parallel_trials[worker_count].append(
                            _run_multiprocess_trial(
                                pools[worker_count],
                                root,
                                lines,
                                worker_count,
                                trial_number,
                            )
                        )

                results.extend(
                    (
                        _median_run("A) Single, commit/event", single_per_event_trials),
                        _median_run(
                            "B) Single, batch/1,000", single_batched_trials
                        ),
                        _median_run(
                            "C) Multiprocess, 4 workers, batch/1,000",
                            parallel_trials[4],
                        ),
                        _median_run(
                            "D) Multiprocess, 8 workers, batch/1,000",
                            parallel_trials[8],
                        ),
                    )
                )
            finally:
                for executor in pools.values():
                    executor.shutdown(wait=True)
    finally:
        vault.DB_PATH = original_db_path
        ingest.EVENTS_JSONL_PATH = original_events_path
        ingest.CONFIGS = original_configs

    rates = {row["mode"][0]: row["events_per_second"] for row in results}
    gains = {
        "batching_gain": rates["B"] / rates["A"],
        "parallel_speedup_4_workers": rates["C"] / rates["B"],
        "parallel_speedup_8_workers": rates["D"] / rates["B"],
    }
    return results, gains


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=100000, help="input lines per run")
    args = parser.parse_args()
    try:
        rows, gains = run_benchmark(args.count)
    except (AssertionError, OSError, ValueError, RuntimeError) as error:
        parser.error(str(error))

    cpu_model = platform.processor() or "Unknown CPU"
    logical_cores = os.cpu_count() or 1
    print(
        f"Hardware: {cpu_model}; logical CPU cores: {logical_cores}; "
        "physical cores: 4; RAM: 32 GiB; disk: WDC PC SN520 NVMe SSD"
    )
    print(f"Input lines per run: {args.count:,}; repetitions: {REPETITIONS}")
    print(
        "All runs warmed with 1,000 lines before timing; input generation and "
        "database setup are excluded."
    )
    print(_format_results(rows))
    print(f"Batching gain (B/A): {gains['batching_gain']:.2f}x")
    print(
        "Parallel speedup (C/B): "
        f"{gains['parallel_speedup_4_workers']:.2f}x"
    )
    print(
        "Parallel speedup (D/B): "
        f"{gains['parallel_speedup_8_workers']:.2f}x"
    )
    for row in rows:
        print(
            f"{row['mode']} trial seconds: "
            + ", ".join(f"{seconds:.2f}" for seconds in row["trial_seconds"])
        )

    report = (
        "# ULPF Benchmark Results\n\n"
        f"Command: `python benchmark.py --count {args.count}`\n\n"
        "Each configuration processes the same generated input through the shared "
        "`ulpf.ingest._process_line` implementation. API requests still use "
        "`process_line`, which commits both raw and normalized records per request. "
        "The benchmark-only helper reuses one SQLite connection per process; A "
        "commits after each event, while B/C/D commit after every 1,000 events. "
        "Every multiprocessing worker receives an evenly balanced input chunk and "
        "its own SQLite database. Event and raw-vault row counts are summed across "
        "worker databases and asserted equal to N after each trial. Configurations "
        "run three times; table seconds and rates are medians. Input generation, "
        "database setup, and 1,000-event warm-ups are outside measured intervals. "
        "SQLite uses `journal_mode=DELETE`, `synchronous=FULL` for all runs.\n\n"
        "Hardware used: Intel Core i7-10610U, 4 physical cores / 8 logical "
        "processors, 32 GiB RAM, WDC PC SN520 NVMe SSD, Windows. Timings vary "
        "with host load and storage. Batching gain is B/A. Parallel speedups "
        "compare C/B and D/B only; multiprocessing is not compared with A.\n\n"
        "```\n"
        f"{_format_results(rows)}\n"
        "```\n\n"
        f"Batching gain (B/A): {gains['batching_gain']:.2f}x\n\n"
        f"Parallel speedup (C/B): {gains['parallel_speedup_4_workers']:.2f}x\n\n"
        f"Parallel speedup (D/B): {gains['parallel_speedup_8_workers']:.2f}x\n\n"
        "Three trial durations (seconds):\n\n"
        + "\n".join(
            f"- {row['mode']}: "
            + ", ".join(f"{seconds:.2f}" for seconds in row["trial_seconds"])
            for row in rows
        )
        + "\n"
    )
    docs_directory = PROJECT_ROOT / "docs"
    docs_directory.mkdir(parents=True, exist_ok=True)
    report_path = docs_directory / "benchmark_results.md"
    report_path.write_text(report, encoding="utf-8")
    print(f"Saved benchmark results to {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
