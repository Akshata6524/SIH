"""SQLite-backed storage for original, unmodified log events."""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, TypedDict


DB_PATH = Path(__file__).resolve().parent.parent / "data" / "raw_vault.sqlite3"


class RawRecord(TypedDict):
    """A raw event as stored in the vault."""

    raw_event_id: str
    raw_sha256: str
    received_at: str
    source_ip: str | None
    raw_text: str


@contextmanager
def _connection() -> Generator[sqlite3.Connection, None, None]:
    """Open the vault database and ensure its table exists."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(DB_PATH))) as connection:
        connection.row_factory = sqlite3.Row
        with connection:
            ensure_schema(connection)
            yield connection


def ensure_schema(connection: sqlite3.Connection) -> None:
    """Create the raw-event table on an existing database connection."""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS raw_events (
            raw_event_id TEXT PRIMARY KEY,
            raw_sha256 TEXT NOT NULL,
            received_at TEXT NOT NULL,
            source_ip TEXT,
            raw_text TEXT NOT NULL
        )
        """
    )


def save_raw(
    text: str,
    source_ip: str | None,
    connection: sqlite3.Connection | None = None,
) -> tuple[str, str]:
    """Store an unchanged log line and return its UUID and SHA-256 digest."""
    raw_event_id = str(uuid.uuid4())
    raw_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    received_at = (
        datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )

    if connection is None:
        with _connection() as vault_connection:
            vault_connection.execute(
                """
                INSERT INTO raw_events (
                    raw_event_id, raw_sha256, received_at, source_ip, raw_text
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (raw_event_id, raw_sha256, received_at, source_ip, text),
            )
    else:
        connection.execute(
            """
            INSERT INTO raw_events (
                raw_event_id, raw_sha256, received_at, source_ip, raw_text
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (raw_event_id, raw_sha256, received_at, source_ip, text),
        )

    return raw_event_id, raw_sha256


def get_raw(raw_event_id: str) -> RawRecord | None:
    """Return a stored raw event, or ``None`` when its ID is not present."""
    with _connection() as connection:
        row = connection.execute(
            """
            SELECT raw_event_id, raw_sha256, received_at, source_ip, raw_text
            FROM raw_events
            WHERE raw_event_id = ?
            """,
            (raw_event_id,),
        ).fetchone()

    if row is None:
        return None
    return {
        "raw_event_id": row["raw_event_id"],
        "raw_sha256": row["raw_sha256"],
        "received_at": row["received_at"],
        "source_ip": row["source_ip"],
        "raw_text": row["raw_text"],
    }
