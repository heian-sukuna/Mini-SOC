"""A SQLite-backed system-of-record for alert triage and incidents.

The JSONL store stays the append-only ingestion log; this store holds the *mutable* triage
state the JSONL can't. :meth:`TriageStore.sync_from_jsonl` pulls new alerts in (idempotent,
keyed by a stable :func:`alert_uid`), assigning each ``status = "new"``. From there an
analyst can acknowledge, work, and close alerts, attach notes, and group related alerts
into incidents — all queryable.

Design notes:

* Stable identity. An alert's ``uid`` is a hash of ``(rule_id, group_value, timestamp,
  mode)`` so re-syncing the same JSONL never creates duplicates and never clobbers triage
  state already set on an alert.
* Thread-safety. FastAPI serves sync endpoints from a threadpool, so each operation opens
  its own short-lived connection rather than sharing one across threads.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from minisoc.alerting.sinks import read_jsonl
from minisoc.core.config import REPO_ROOT, Config

__all__ = ["TriageStore", "STATUSES", "OPEN_STATUSES", "alert_uid", "triage_db_path"]

# The alert lifecycle. The two closed states record the analyst's verdict — the single
# most valuable datum a SOC produces, and what false-positive tuning is measured against.
STATUSES = (
    "new",
    "acknowledged",
    "in_progress",
    "closed_true_positive",
    "closed_false_positive",
)
OPEN_STATUSES = ("new", "acknowledged", "in_progress")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event_get(event: dict[str, Any], dotted: str) -> Any:
    """Resolve a dotted ECS path (e.g. ``"source.ip"``) in a nested event dict."""
    cursor: Any = event
    for part in dotted.split("."):
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(part)
    return cursor


def _span_seconds(start: str | None, end: str | None) -> float | None:
    """Seconds between two ISO timestamps, or ``None`` if either is missing/unparseable."""
    try:
        return (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()
    except (TypeError, ValueError):
        return None


def alert_uid(record: dict[str, Any]) -> str:
    """A stable short id for an alert record (so re-syncing is idempotent)."""
    key = "|".join(
        str(record.get(f)) for f in ("rule_id", "group_value", "timestamp", "mode")
    )
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def triage_db_path(config: Config) -> Path:
    """Resolve the triage SQLite path from config (with a sensible default)."""
    if config.triage.get("db"):
        return Path(config.triage["db"])
    generated = config.paths.get("generated_dir", REPO_ROOT / "data" / "generated")
    return generated / "triage.db"


class TriageStore:
    """SQLite store for alert lifecycle, notes, and incidents.

    Args:
        path: Path to the SQLite database file. ``":memory:"`` works for tests.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        # An in-memory DB only lives as long as its connection, so hold one open.
        self._mem = sqlite3.connect(self._path) if self._path == ":memory:" else None
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = self._mem or sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        with conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    uid TEXT PRIMARY KEY,
                    rule_id TEXT, rule_title TEXT, severity TEXT,
                    timestamp TEXT, source TEXT, group_value TEXT, mode TEXT,
                    occurrences INTEGER, description TEXT,
                    enrichment TEXT, data TEXT,
                    status TEXT NOT NULL DEFAULT 'new',
                    assignee TEXT,
                    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
                    first_seen TEXT, last_updated TEXT
                );
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_uid TEXT NOT NULL REFERENCES alerts(uid) ON DELETE CASCADE,
                    author TEXT, body TEXT NOT NULL, created_at TEXT NOT NULL
                );
                """
            )
        if self._mem is None:
            conn.close()

    # -- ingestion ---------------------------------------------------------------------

    def ingest_record(self, record: dict[str, Any]) -> str:
        """Upsert one JSONL alert record. Returns its uid.

        New alerts land as ``new``. Existing alerts keep their triage state but refresh
        their occurrence count / evidence (a still-firing alert may have grown).
        """
        uid = alert_uid(record)
        now = _now()
        conn = self._connect()
        with conn:
            existing = conn.execute("SELECT uid FROM alerts WHERE uid = ?", (uid,)).fetchone()
            if existing:
                conn.execute(
                    "UPDATE alerts SET occurrences = ?, data = ?, last_updated = ? WHERE uid = ?",
                    (record.get("occurrences", 1), json.dumps(record), now, uid),
                )
            else:
                conn.execute(
                    """INSERT INTO alerts (uid, rule_id, rule_title, severity, timestamp,
                       source, group_value, mode, occurrences, description, enrichment,
                       data, status, first_seen, last_updated)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'new',?,?)""",
                    (
                        uid, record.get("rule_id"), record.get("rule_title"),
                        record.get("severity"), record.get("timestamp"),
                        record.get("source"),
                        None if record.get("group_value") is None else str(record["group_value"]),
                        record.get("mode", "simulation"), record.get("occurrences", 1),
                        record.get("description", ""),
                        json.dumps(record.get("enrichment") or {}),
                        json.dumps(record), now, now,
                    ),
                )
        if self._mem is None:
            conn.close()
        return uid

    def sync_from_jsonl(self, path: str | Path) -> int:
        """Ingest every record from a JSONL store. Returns the count of *new* alerts."""
        before = self.count()
        for record in read_jsonl(path):
            self.ingest_record(record)
        return self.count() - before

    # -- triage operations -------------------------------------------------------------

    def set_status(self, uid: str, status: str, *, assignee: str | None = None) -> bool:
        """Set an alert's lifecycle status (and optionally its assignee)."""
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r}; expected one of {STATUSES}")
        conn = self._connect()
        with conn:
            cur = conn.execute(
                "UPDATE alerts SET status = ?, assignee = COALESCE(?, assignee), last_updated = ? WHERE uid = ?",
                (status, assignee, _now(), uid),
            )
            changed = cur.rowcount > 0
        if self._mem is None:
            conn.close()
        return changed

    def add_note(self, uid: str, body: str, *, author: str = "analyst") -> int:
        """Attach a note to an alert. Returns the note id."""
        conn = self._connect()
        with conn:
            cur = conn.execute(
                "INSERT INTO notes (alert_uid, author, body, created_at) VALUES (?,?,?,?)",
                (uid, author, body, _now()),
            )
            note_id = cur.lastrowid
        if self._mem is None:
            conn.close()
        return note_id

    def create_incident(self, title: str) -> int:
        """Open a new incident. Returns its id."""
        conn = self._connect()
        with conn:
            cur = conn.execute(
                "INSERT INTO incidents (title, created_at) VALUES (?, ?)", (title, _now())
            )
            incident_id = cur.lastrowid
        if self._mem is None:
            conn.close()
        return incident_id

    def assign_to_incident(self, uids: list[str], incident_id: int) -> int:
        """Attach alerts to an incident. Returns how many were updated."""
        conn = self._connect()
        with conn:
            count = 0
            for uid in uids:
                cur = conn.execute(
                    "UPDATE alerts SET incident_id = ?, last_updated = ? WHERE uid = ?",
                    (incident_id, _now(), uid),
                )
                count += cur.rowcount
        if self._mem is None:
            conn.close()
        return count

    def group_into_incident(self, uids: list[str], title: str) -> int:
        """Create an incident and attach the given alerts. Returns the incident id."""
        incident_id = self.create_incident(title)
        self.assign_to_incident(uids, incident_id)
        return incident_id

    # -- queries -----------------------------------------------------------------------

    def count(self) -> int:
        """Total alerts in the store."""
        conn = self._connect()
        n = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        if self._mem is None:
            conn.close()
        return n

    def list_alerts(
        self, *, status: str | None = None, open_only: bool = False, incident_id: int | None = None
    ) -> list[dict[str, Any]]:
        """List alerts (newest first), optionally filtered by status/incident."""
        clauses, params = [], []
        if status:
            clauses.append("status = ?")
            params.append(status)
        elif open_only:
            clauses.append(f"status IN ({','.join('?' * len(OPEN_STATUSES))})")
            params.extend(OPEN_STATUSES)
        if incident_id is not None:
            clauses.append("incident_id = ?")
            params.append(incident_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        conn = self._connect()
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY timestamp DESC, first_seen DESC", params
        ).fetchall()
        if self._mem is None:
            conn.close()
        return [self._row_to_alert(r) for r in rows]

    def pivot(self, field: str, value: str) -> list[dict[str, Any]]:
        """Find every alert whose evidence involves ``field == value``.

        The heart of the investigation view: from one alert, pivot on a source IP or a
        username to surface every *other* detection that touched the same entity. An alert
        matches when its ``group_value`` equals ``value`` or any of its triggering events
        carries ``field`` (a dotted ECS path, e.g. ``"source.ip"``) equal to ``value``.

        Returns the matching alerts (newest first), each already shaped like
        :meth:`list_alerts` output.
        """
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC, first_seen DESC"
        ).fetchall()
        if self._mem is None:
            conn.close()

        matches: list[dict[str, Any]] = []
        for row in rows:
            alert = self._row_to_alert(row)
            events = (alert.get("data") or {}).get("events") or []
            if str(alert.get("group_value")) == value or any(
                str(_event_get(ev, field)) == value for ev in events
            ):
                matches.append(alert)
        return matches

    def get_alert(self, uid: str) -> dict[str, Any] | None:
        """Return one alert with its notes, or ``None``."""
        conn = self._connect()
        row = conn.execute("SELECT * FROM alerts WHERE uid = ?", (uid,)).fetchone()
        notes = conn.execute(
            "SELECT author, body, created_at FROM notes WHERE alert_uid = ? ORDER BY id", (uid,)
        ).fetchall()
        if self._mem is None:
            conn.close()
        if row is None:
            return None
        alert = self._row_to_alert(row)
        alert["notes"] = [dict(n) for n in notes]
        return alert

    def list_incidents(self) -> list[dict[str, Any]]:
        """List incidents with their member alert counts."""
        conn = self._connect()
        rows = conn.execute(
            """SELECT i.id, i.title, i.status, i.created_at, COUNT(a.uid) AS alert_count
               FROM incidents i LEFT JOIN alerts a ON a.incident_id = i.id
               GROUP BY i.id ORDER BY i.id DESC"""
        ).fetchall()
        if self._mem is None:
            conn.close()
        return [dict(r) for r in rows]

    def stats(self) -> dict[str, Any]:
        """Counts by status, plus open/total and incident count — the triage KPIs."""
        conn = self._connect()
        by_status = {
            r["status"]: r["n"]
            for r in conn.execute("SELECT status, COUNT(*) AS n FROM alerts GROUP BY status")
        }
        incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        if self._mem is None:
            conn.close()
        total = sum(by_status.values())
        open_count = sum(by_status.get(s, 0) for s in OPEN_STATUSES)
        return {
            "total": total,
            "open": open_count,
            "by_status": {s: by_status.get(s, 0) for s in STATUSES if by_status.get(s)},
            "incidents": incidents,
        }

    def metrics(self) -> dict[str, Any]:
        """Resolution KPIs: MTTR and the true/false-positive verdict split.

        MTTR (mean time to resolve) is the average span from an alert first appearing
        (``first_seen``) to its move into a closed state (``last_updated``), over alerts
        currently in a ``closed_*`` status. The verdict split — what fraction of closed
        alerts were false positives — is the headline number SOC tuning is judged by.
        """
        conn = self._connect()
        rows = conn.execute(
            """SELECT status, first_seen, last_updated FROM alerts
               WHERE status IN ('closed_true_positive', 'closed_false_positive')"""
        ).fetchall()
        if self._mem is None:
            conn.close()

        spans: list[float] = []
        true_pos = false_pos = 0
        for r in rows:
            if r["status"] == "closed_true_positive":
                true_pos += 1
            else:
                false_pos += 1
            span = _span_seconds(r["first_seen"], r["last_updated"])
            if span is not None:
                spans.append(span)

        resolved = true_pos + false_pos
        mttr = sum(spans) / len(spans) if spans else None
        return {
            "resolved": resolved,
            "closed_true_positive": true_pos,
            "closed_false_positive": false_pos,
            "false_positive_rate": (false_pos / resolved) if resolved else 0.0,
            "mttr_seconds": mttr,
        }

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> dict[str, Any]:
        alert = dict(row)
        alert["enrichment"] = json.loads(alert.get("enrichment") or "{}")
        # `data` holds the full original record (with evidence events) for the pivot view.
        if alert.get("data"):
            alert["data"] = json.loads(alert["data"])
        return alert
