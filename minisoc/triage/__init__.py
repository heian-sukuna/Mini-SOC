"""Alert triage & case management — the workflow layer that makes minisoc a SOC.

Detection produces a *stream* of alerts. A SOC turns that stream into *work*: each alert
gets a lifecycle (new → acknowledged → in-progress → closed as a true or false positive),
analyst notes, and grouping of related alerts into an **incident**.

The append-only JSONL store is great for ingestion but can't hold mutable state. This
package adds a queryable **SQLite** system-of-record (:class:`~minisoc.triage.store.
TriageStore`) that syncs new alerts in from the JSONL store and then tracks their triage
state. The CLI (`minisoc triage`) and the dashboard both drive it.
"""

from __future__ import annotations

from minisoc.triage.store import STATUSES, TriageStore, alert_uid, triage_db_path

__all__ = ["TriageStore", "STATUSES", "alert_uid", "triage_db_path"]
