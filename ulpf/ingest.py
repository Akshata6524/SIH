"""FastAPI ingestion pipeline for perimeter device logs."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import socket
import sqlite3
import threading
from contextlib import asynccontextmanager, closing
from email.parser import BytesParser
from email.policy import default as email_policy
from pathlib import Path
from typing import Any, AsyncGenerator, Mapping

import yaml
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, RedirectResponse, Response

from ulpf import autogen, detector, exporters, normalizer, parser_engine, quality, vault

LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVENTS_JSONL_PATH = PROJECT_ROOT / "data" / "events.jsonl"
CONFIG_DIR = parser_engine.CONFIG_DIR
CONFIGS: list[dict[str, Any]] = []
_CONFIG_LOCK = threading.RLock()
_UDP_SOCKET: socket.socket | None = None
_UDP_THREAD: threading.Thread | None = None
_UDP_STOP = threading.Event()


def reload_configs() -> int:
    """Reload source YAML files and return the number of loaded configs."""
    global CONFIGS
    loaded = parser_engine.load_configs(CONFIG_DIR)
    with _CONFIG_LOCK:
        CONFIGS = loaded
    return len(loaded)


def _current_configs() -> list[dict[str, Any]]:
    with _CONFIG_LOCK:
        if not CONFIGS:
            CONFIGS.extend(parser_engine.load_configs(CONFIG_DIR))
        return CONFIGS


def _ensure_event_schema(connection: sqlite3.Connection) -> None:
    """Create event storage on an existing pipeline database connection."""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            raw_event_id TEXT NOT NULL,
            event_json TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_raw_event_id ON events(raw_event_id)"
    )


def _connect_events() -> sqlite3.Connection:
    """Open the database shared with the raw vault and ensure event storage exists."""
    vault.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(vault.DB_PATH))
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                raw_event_id TEXT NOT NULL,
                event_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_raw_event_id ON events(raw_event_id)"
        )
        connection.commit()
    except Exception:
        connection.close()
        raise
    return connection


def _store_event(
    event: dict[str, Any],
    connection: sqlite3.Connection | None = None,
) -> None:
    """Persist one event in SQLite and append its JSON representation to JSONL."""
    event_json = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
    if connection is None:
        with closing(_connect_events()) as events_connection:
            with events_connection:
                events_connection.execute(
                    """
                    INSERT INTO events (event_id, raw_event_id, event_json)
                    VALUES (?, ?, ?)
                    """,
                    (event["event_id"], event["raw_event_id"], event_json),
                )
    else:
        connection.execute(
            """
            INSERT INTO events (event_id, raw_event_id, event_json)
            VALUES (?, ?, ?)
            """,
            (event["event_id"], event["raw_event_id"], event_json),
        )

    EVENTS_JSONL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with EVENTS_JSONL_PATH.open("a", encoding="utf-8", newline="\n") as output_file:
        output_file.write(event_json + "\n")


def process_line(
    raw_text: str,
    source_ip: str | None = None,
) -> dict[str, Any]:
    """Process one log request and commit its raw and normalized records."""
    vault.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(vault.DB_PATH))) as connection:
        connection.row_factory = sqlite3.Row
        vault.ensure_schema(connection)
        _ensure_event_schema(connection)
        try:
            event = _process_line(raw_text, source_ip, connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return event


def _process_line(
    raw_text: str,
    source_ip: str | None,
    database_connection: sqlite3.Connection,
) -> dict[str, Any]:
    """Shared pipeline implementation; benchmark callers control commit cadence."""
    raw_event_id, raw_sha256 = vault.save_raw(
        raw_text, source_ip, connection=database_connection
    )
    guessed_format = detector.detect_format(raw_text)

    try:
        config = detector.identify_source(raw_text, _current_configs())
        if config is None:
            event = normalizer.normalize_generic(
                {"raw_text": raw_text}, raw_event_id, raw_sha256
            )
            event["source"]["format"] = guessed_format
            extracted: dict[str, Any] = event["vendor_extras"]
        else:
            extracted = parser_engine.parse(raw_text, config)
            event = normalizer.normalize(
                extracted,
                dict(config),
                raw_event_id,
                raw_sha256,
                device_ip=source_ip,
            )
    except Exception as error:
        LOGGER.exception("Could not parse log line; preserving it as a generic event")
        event = normalizer.normalize_generic(
            {"raw_text": raw_text}, raw_event_id, raw_sha256
        )
        event["source"]["format"] = guessed_format
        event["vendor_extras"]["_processing_error"] = str(error)
        extracted = event["vendor_extras"]

    parse_score, parse_status = quality.compute_quality(extracted, event)
    event["parse_score"] = parse_score
    event["parse_status"] = parse_status
    _store_event(event, connection=database_connection)
    return event


def _get_event(event_id: str) -> dict[str, Any] | None:
    with closing(_connect_events()) as connection:
        row = connection.execute(
            "SELECT event_json FROM events WHERE event_id = ?", (event_id,)
        ).fetchone()
    return json.loads(row["event_json"]) if row is not None else None


def _query_events(
    limit: int, source: str | None, action: str | None, category: str | None
) -> list[dict[str, Any]]:
    with closing(_connect_events()) as connection:
        rows = connection.execute("SELECT event_json FROM events ORDER BY rowid DESC").fetchall()

    selected: list[dict[str, Any]] = []
    source_query = source.casefold() if source is not None else None
    for row in rows:
        event = json.loads(row["event_json"])
        event_source = event.get("source", {})
        source_values = (
            str(value).casefold()
            for value in event_source.values()
            if value is not None
        ) if isinstance(event_source, Mapping) else iter(())
        if source_query is not None and source_query not in source_values:
            continue
        if action is not None and event.get("action") != action:
            continue
        if category is not None and event.get("category") != category:
            continue
        selected.append(event)
        if len(selected) >= limit:
            break
    return selected


def _udp_listener() -> None:
    global _UDP_SOCKET
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.bind(("0.0.0.0", 5140))
        udp_socket.settimeout(0.5)
        _UDP_SOCKET = udp_socket
        LOGGER.info("UDP syslog listener active on port 5140")
        while not _UDP_STOP.is_set():
            try:
                payload, address = udp_socket.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                process_line(payload.decode("utf-8", errors="replace"), address[0])
            except Exception:
                LOGGER.exception("Could not ingest UDP syslog datagram from %s", address[0])
    except OSError:
        if not _UDP_STOP.is_set():
            LOGGER.exception("UDP syslog listener could not start on port 5140")
    finally:
        _UDP_SOCKET = None
        udp_socket.close()


def _start_udp_listener() -> None:
    global _UDP_THREAD
    if os.getenv("ULPF_UDP_ENABLED", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return
    _UDP_STOP.clear()
    _UDP_THREAD = threading.Thread(
        target=_udp_listener,
        name="ulpf-udp-syslog",
        daemon=True,
    )
    _UDP_THREAD.start()


def _stop_udp_listener() -> None:
    _UDP_STOP.set()
    if _UDP_SOCKET is not None:
        _UDP_SOCKET.close()
    if _UDP_THREAD is not None:
        _UDP_THREAD.join(timeout=2)


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    reload_configs()
    _start_udp_listener()
    try:
        yield
    finally:
        _stop_udp_listener()


app = FastAPI(title="Universal Log Pre-processing Framework", lifespan=_lifespan)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    """Send browser visits to the interactive API documentation."""
    return RedirectResponse(url="/docs")


@app.get("/health")
def health() -> dict[str, Any]:
    """Report API health and the number of currently loaded source configs."""
    return {"status": "ok", "configs_loaded": len(_current_configs())}


@app.post("/ingest")
async def ingest(request: Request) -> Any:
    """Ingest a single log line or a JSON list of log lines."""
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        try:
            body = await request.json()
        except ValueError as error:
            raise HTTPException(status_code=400, detail="Request body is not valid JSON") from error
    else:
        try:
            body = (await request.body()).decode("utf-8")
        except UnicodeDecodeError as error:
            raise HTTPException(status_code=400, detail="Log body must be UTF-8 text") from error

    if isinstance(body, str):
        try:
            return process_line(body, request.client.host if request.client else None)
        except Exception as error:
            LOGGER.exception("Could not ingest a log line")
            raise HTTPException(status_code=500, detail="Could not persist log line") from error
    if not isinstance(body, list):
        raise HTTPException(status_code=422, detail="Body must be a log string or a list of strings")

    results: list[dict[str, Any]] = []
    for index, line in enumerate(body):
        if not isinstance(line, str):
            results.append({"index": index, "error": "Log line must be a string"})
            continue
        try:
            event = process_line(line, request.client.host if request.client else None)
        except Exception as error:
            LOGGER.exception("Could not ingest log line at index %d", index)
            results.append({"index": index, "error": str(error)})
        else:
            results.append(event)
    return results


@app.post("/upload")
async def upload(request: Request) -> dict[str, int]:
    """Upload a .log or .txt file and process each line independently."""
    content_type = request.headers.get("content-type", "")
    body = await request.body()
    filename: str | None = None
    payload = body

    if content_type.lower().startswith("multipart/form-data"):
        message_bytes = (
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii")
            + body
        )
        message = BytesParser(policy=email_policy).parsebytes(message_bytes)
        if message.is_multipart():
            for part in message.iter_parts():
                candidate = part.get_filename()
                if candidate is not None:
                    filename = candidate
                    payload = part.get_payload(decode=True) or b""
                    break
        if filename is None:
            raise HTTPException(status_code=400, detail="Upload must include a file")
    else:
        filename = request.query_params.get("filename")
        if filename is None:
            raise HTTPException(
                status_code=400,
                detail="Provide a multipart file or a filename query parameter",
            )

    if Path(filename).suffix.lower() not in {".log", ".txt"}:
        raise HTTPException(status_code=400, detail="Only .log and .txt files are supported")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HTTPException(status_code=400, detail="Uploaded file must be UTF-8 text") from error

    counts = {"processed": 0, "success": 0, "partial": 0, "failed": 0}
    client_ip = request.client.host if request.client else None
    for line in text.splitlines():
        try:
            event = process_line(line, client_ip)
        except Exception:
            LOGGER.exception("Could not ingest uploaded log line")
            counts["failed"] += 1
            continue
        counts["processed"] += 1
        counts[event["parse_status"]] += 1
    return counts


@app.get("/events")
def list_events(
    limit: int = 100,
    source: str | None = None,
    action: str | None = None,
    category: str | None = None,
) -> list[dict[str, Any]]:
    """List recent events with optional source, action, and category filters."""
    if limit < 1 or limit > 10000:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 10000")
    return _query_events(limit, source, action, category)


@app.get("/export")
def export_event_list(
    format: str = Query("json", alias="format"),
    limit: int = 1000,
    source: str | None = None,
    action: str | None = None,
) -> Any:
    """Export recent events as CEF, OCSF, JSON, or Parquet."""
    if limit < 1 or limit > 10000:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 10000")
    export_format = format.lower()
    if export_format not in {"cef", "ocsf", "json", "parquet"}:
        raise HTTPException(
            status_code=422,
            detail="format must be one of cef, ocsf, json, or parquet",
        )
    events = _query_events(limit, source, action, None)
    if export_format == "cef":
        return Response(
            content=exporters.export_events(events, "cef"),
            media_type="text/plain",
        )
    if export_format in {"ocsf", "json"}:
        return exporters.export_events(events, export_format)

    parquet_path = PROJECT_ROOT / "data" / "export.parquet"
    try:
        exporters.to_parquet(events, str(parquet_path))
    except ImportError as error:
        LOGGER.exception("Parquet export dependencies are unavailable")
        raise HTTPException(status_code=500, detail=str(error)) from error
    return FileResponse(
        path=parquet_path,
        media_type="application/vnd.apache.parquet",
        filename="export.parquet",
    )


@app.get("/export/{event_id}")
def export_single_event(
    event_id: str,
    format: str = Query(..., alias="format"),
) -> Any:
    """Export one event as CEF or OCSF."""
    export_format = format.lower()
    if export_format not in {"cef", "ocsf"}:
        raise HTTPException(status_code=422, detail="format must be cef or ocsf")
    event = _get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    converted = exporters.export_events([event], export_format)
    if export_format == "cef":
        return Response(content=converted, media_type="text/plain")
    return converted[0]


@app.get("/events/{event_id}")
def get_event(event_id: str) -> dict[str, Any]:
    """Return one normalized event by its event ID."""
    event = _get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.get("/raw/{raw_event_id}")
def get_raw_event(raw_event_id: str) -> dict[str, Any]:
    """Return the exact stored text and report whether its digest verifies."""
    record = vault.get_raw(raw_event_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Raw event not found")
    actual_sha256 = hashlib.sha256(record["raw_text"].encode("utf-8")).hexdigest()
    return {
        "raw_event_id": record["raw_event_id"],
        "raw_text": record["raw_text"],
        "raw_sha256": record["raw_sha256"],
        "verified": hmac.compare_digest(actual_sha256, record["raw_sha256"]),
    }


@app.get("/stats")
def get_stats() -> dict[str, Any]:
    """Return event counts by source and action plus average quality by source."""
    with closing(_connect_events()) as connection:
        rows = connection.execute("SELECT event_json FROM events").fetchall()

    source_counts: dict[str, int] = {}
    action_counts: dict[str, int] = {}
    source_scores: dict[str, list[float]] = {}
    for row in rows:
        event = json.loads(row["event_json"])
        event_source = event.get("source", {})
        source_name = str(event_source.get("vendor", "unknown"))
        action_name = str(event.get("action", "unknown"))
        source_counts[source_name] = source_counts.get(source_name, 0) + 1
        action_counts[action_name] = action_counts.get(action_name, 0) + 1
        source_scores.setdefault(source_name, []).append(float(event.get("parse_score", 0.0)))

    average_scores = {
        source: sum(scores) / len(scores) for source, scores in source_scores.items()
    }
    return {
        "total_events": len(rows),
        "per_source": source_counts,
        "per_action": action_counts,
        "average_parse_score_per_source": average_scores,
    }


@app.post("/reload-configs")
def reload_configs_endpoint() -> dict[str, int]:
    """Reload YAML source configurations without restarting the service."""
    try:
        count = reload_configs()
    except Exception as error:
        LOGGER.exception("Could not reload parser configs")
        raise HTTPException(status_code=500, detail="Could not reload parser configs") from error
    return {"loaded": count}


@app.post("/autogen")
async def autogen_config(request: Request) -> dict[str, Any]:
    """Generate a source config from samples and optionally save and load it."""
    try:
        body = await request.json()
    except ValueError as error:
        raise HTTPException(status_code=400, detail="Request body is not valid JSON") from error
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="Request body must be a JSON object")

    samples = body.get("samples")
    name = body.get("name")
    vendor = body.get("vendor")
    product = body.get("product")
    save = body.get("save", False)
    if not isinstance(samples, list) or not all(isinstance(line, str) for line in samples):
        raise HTTPException(status_code=422, detail="'samples' must be a list of strings")
    if not all(isinstance(value, str) and value.strip() for value in (name, vendor, product)):
        raise HTTPException(
            status_code=422,
            detail="'name', 'vendor', and 'product' must be non-empty strings",
        )
    if not isinstance(save, bool):
        raise HTTPException(status_code=422, detail="'save' must be a boolean")

    try:
        config = autogen.generate_config(samples, name, vendor, product)
        confidence = autogen.confidence_report(samples, config)
        saved_path: str | None = None
        if save:
            path = autogen.save_config(config, CONFIG_DIR)
            saved_path = path.name
            reload_configs()
    except (ValueError, OSError, yaml.YAMLError) as error:
        LOGGER.exception("Could not generate or save parser config")
        raise HTTPException(status_code=400, detail=str(error)) from error
    except Exception as error:
        LOGGER.exception("Could not generate parser config")
        raise HTTPException(status_code=500, detail="Could not generate parser config") from error

    return {
        "config": config,
        "yaml": yaml.safe_dump(config, sort_keys=False, allow_unicode=True),
        "confidence": confidence,
        "saved": save,
        "path": saved_path,
    }