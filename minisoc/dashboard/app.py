"""The minisoc dashboard — a FastAPI app serving one static page + a small JSON API.

The page is for portfolio screenshots, not a product: it lists alerts (severity-colored)
with their rule, source, group, occurrences, and time, shows counts by severity and
source, and has buttons to trigger any scenario and watch detections appear live.

Data comes from the JSONL alert store written by the pipeline. The HTTP layer is a thin
shell over plain functions (:func:`load_alerts`, :func:`compute_stats`,
:func:`list_scenarios`, :func:`trigger_scenario`) so the logic is unit-testable without an
HTTP client.
"""

from __future__ import annotations

import ipaddress
import secrets
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

from minisoc.alerting.sinks import read_jsonl
from minisoc.core.config import Config
from minisoc.core.pipeline import Pipeline
from minisoc.core.runner import run_scenario
from minisoc.detections.coverage import mitre_coverage
from minisoc.scenarios.registry import SCENARIOS, scenario_names, store_path
from minisoc.triage import STATUSES, TriageStore, triage_db_path

__all__ = [
    "create_app",
    "load_alerts",
    "compute_stats",
    "compute_metrics",
    "navigator_layer",
    "risk_board",
    "alert_pivots",
    "list_scenarios",
    "coverage_summary",
    "trigger_scenario",
    "synced_store",
]

_INDEX_HTML = Path(__file__).parent / "static" / "index.html"
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class RunRequest(BaseModel):
    """Body of ``POST /api/run``."""

    scenario: str
    fresh: bool = False


class StatusRequest(BaseModel):
    """Body of ``POST /api/triage/{uid}/status``."""

    status: str
    assignee: str | None = None


class NoteRequest(BaseModel):
    """Body of ``POST /api/triage/{uid}/note``."""

    body: str
    author: str = "analyst"


class IncidentRequest(BaseModel):
    """Body of ``POST /api/incidents`` — group alerts into a new incident."""

    title: str
    uids: list[str] = []


def synced_store(config: Config, store: TriageStore) -> TriageStore:
    """Pull any new alerts from the JSONL store into the triage store, then return it."""
    store.sync_from_jsonl(store_path(config))
    return store


def load_alerts(config: Config) -> list[dict[str, Any]]:
    """Return all stored alerts (newest first) from the JSONL store."""
    records = read_jsonl(store_path(config))
    records.reverse()  # store is append-order; show most recent first
    for record in records:
        # Records written before alerts carried a mode came from scenario runs.
        record.setdefault("mode", "simulation")
    return records


def compute_stats(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute dashboard summary counts from stored alert records.

    Args:
        alerts: Decoded alert records (as from :func:`load_alerts`).

    Returns:
        ``{"total", "by_severity", "by_source", "by_mode"}`` where the breakdowns are
        dicts of ``label -> count``. ``by_severity`` is ordered most-to-least severe;
        ``by_mode`` separates the training side (simulation/replay) from live alerts.
    """
    by_severity = Counter(a.get("severity", "unknown") for a in alerts)
    by_source = Counter(a.get("source") or "unknown" for a in alerts)
    by_mode = Counter(a.get("mode", "simulation") for a in alerts)
    ordered_sev = dict(
        sorted(by_severity.items(), key=lambda kv: _SEVERITY_ORDER.get(kv[0], 9))
    )
    return {
        "total": len(alerts),
        "by_severity": ordered_sev,
        "by_source": dict(by_source.most_common()),
        "by_mode": dict(by_mode.most_common()),
    }


def _is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def _alert_source_ips(record: dict[str, Any]) -> list[str]:
    """Best-effort source IPs for an alert: the group value if it's an IP, else the
    ``source.ip`` of each evidence event."""
    if _is_ip(record.get("group_value")):
        return [str(record["group_value"])]
    ips = []
    for event in record.get("events") or []:
        ip = (event.get("source") or {}).get("ip")
        if ip and _is_ip(ip):
            ips.append(ip)
    return ips


def compute_metrics(alerts: list[dict[str, Any]], triage_metrics: dict[str, Any] | None = None) -> dict[str, Any]:
    """Compute the SOC operational metrics shown on the dashboard.

    Args:
        alerts: Decoded alert records (as from :func:`load_alerts`).
        triage_metrics: Optional resolution KPIs from
            :meth:`~minisoc.triage.TriageStore.metrics` (MTTR, verdict split).

    Returns:
        ``{"volume", "top_sources", "by_severity", "mttr_seconds",
        "false_positive_rate", "resolved"}``. ``volume`` is a date-bucketed
        ``[{"bucket", "count"}]`` timeline; ``top_sources`` is the busiest source IPs.
    """
    by_day: Counter[str] = Counter()
    by_ip: Counter[str] = Counter()
    for record in alerts:
        ts = record.get("timestamp") or ""
        by_day[ts[:10]] += 1  # YYYY-MM-DD bucket
        for ip in _alert_source_ips(record):
            by_ip[ip] += 1

    by_severity = Counter(a.get("severity", "unknown") for a in alerts)
    triage_metrics = triage_metrics or {}
    return {
        "volume": [{"bucket": b, "count": c} for b, c in sorted(by_day.items()) if b],
        "top_sources": [{"ip": ip, "count": c} for ip, c in by_ip.most_common(10)],
        "by_severity": dict(
            sorted(by_severity.items(), key=lambda kv: _SEVERITY_ORDER.get(kv[0], 9))
        ),
        "mttr_seconds": triage_metrics.get("mttr_seconds"),
        "false_positive_rate": triage_metrics.get("false_positive_rate", 0.0),
        "resolved": triage_metrics.get("resolved", 0),
    }


def risk_board(alerts: list[dict[str, Any]], pipeline: Pipeline, *, limit: int = 10) -> dict[str, Any]:
    """Top risk entities computed from stored alerts via the configured risk engine.

    Returns ``{"enabled", "threshold", "entities": [...]}``. When risk is disabled in
    config the board is empty and ``enabled`` is ``False``.
    """
    engine = pipeline.risk
    if engine is None:
        return {"enabled": False, "threshold": None, "entities": []}
    return {
        "enabled": True,
        "threshold": engine.threshold,
        "entities": engine.leaderboard(alerts, limit=limit),
    }


def navigator_layer(pipeline: Pipeline) -> dict[str, Any]:
    """Export rule coverage as a MITRE ATT&CK Navigator layer (importable JSON).

    Each covered technique becomes a scored, colored cell; the comment lists the rules
    that cover it. Drop the file into https://mitre-attack.github.io/attack-navigator/ to
    see the heatmap a SOC uses to show its detection footprint.
    """
    coverage = coverage_summary(pipeline)
    techniques = [
        {
            "techniqueID": t["technique"],
            "score": len(t["rules"]),
            "color": "#2e7d32",
            "comment": ", ".join(r["id"] for r in t["rules"]),
            "enabled": True,
        }
        for t in coverage["techniques"]
    ]
    return {
        "name": "minisoc coverage",
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "14"},
        "domain": "enterprise-attack",
        "description": "Detection coverage exported from minisoc rule tags.",
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#2e7d32"], "minValue": 0, "maxValue": 3},
    }


_PIVOT_FIELDS = ("source.ip", "user.name", "destination.ip")


def alert_pivots(alert: dict[str, Any]) -> list[dict[str, str]]:
    """Distinct pivotable entities (source IP, user, destination IP) in an alert.

    Each is a ``{"field", "value"}`` an analyst can pivot on to find related detections.
    Reads the alert's evidence events (nested ECS dicts) plus its group value.
    """
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(field: str, value: Any) -> None:
        if value is None:
            return
        key = (field, str(value))
        if key not in seen:
            seen.add(key)
            found.append({"field": field, "value": str(value)})

    data = alert.get("data") if isinstance(alert.get("data"), dict) else alert
    for event in data.get("events") or []:
        for field in _PIVOT_FIELDS:
            cursor: Any = event
            for part in field.split("."):
                cursor = cursor.get(part) if isinstance(cursor, dict) else None
            add(field, cursor)
    if _is_ip(alert.get("group_value")):
        add("source.ip", alert["group_value"])
    return found


def list_scenarios() -> list[dict[str, str]]:
    """Return the available scenarios as ``{name, source}`` records."""
    return [{"name": name, "source": SCENARIOS[name][1]} for name in scenario_names()]


def coverage_summary(pipeline: Pipeline) -> dict[str, list]:
    """Return the MITRE ATT&CK technique coverage rollup for the loaded rules."""
    return mitre_coverage(pipeline.tagged_rules())


def _build_auth_guard(config: Config):
    """Return a FastAPI dependency enforcing HTTP Basic auth, per ``dashboard.auth`` config.

    When no ``user``/``password`` is configured the dependency is a no-op (open local
    dashboard) and a warning is logged — the security audit's accepted default. When set,
    every request must present matching Basic credentials (compared with
    ``secrets.compare_digest`` to avoid timing leaks).
    """
    security = HTTPBasic(auto_error=False)
    auth = (config.dashboard or {}).get("auth") or {}
    user, password = str(auth.get("user") or ""), str(auth.get("password") or "")
    enabled = bool(user and password)
    if not enabled:
        print(
            "minisoc: dashboard auth is OFF (set dashboard.auth.user/password in config "
            "before exposing `minisoc serve` beyond localhost)",
            file=sys.stderr,
        )

    def guard(credentials: HTTPBasicCredentials | None = Depends(security)) -> None:
        if not enabled:
            return
        ok = credentials is not None and secrets.compare_digest(
            credentials.username, user
        ) and secrets.compare_digest(credentials.password, password)
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or missing credentials",
                headers={"WWW-Authenticate": "Basic"},
            )

    return guard


def trigger_scenario(name: str, config: Config, *, fresh: bool, pipeline: Pipeline) -> dict[str, Any]:
    """Run a scenario and return a JSON-friendly summary of the result.

    Args:
        name: Registered scenario name.
        config: Loaded configuration.
        fresh: Whether to truncate the store before running.
        pipeline: A reused :class:`Pipeline` (rules loaded once).

    Returns:
        A summary dict with the scenario, counts, and the deduplicated alerts.

    Raises:
        KeyError: If ``name`` is not a registered scenario.
    """
    result = run_scenario(name, config, fresh=fresh, store=True, pipeline=pipeline)
    return {
        "scenario": result.scenario,
        "source": result.source,
        "lines_generated": result.lines_generated,
        "raw_alert_count": result.raw_alert_count,
        "deduped_count": result.deduped_count,
        "alerts": [a.to_dict() for a in result.alerts],
    }


def create_app(config: Config) -> FastAPI:
    """Build the FastAPI dashboard application.

    Args:
        config: Loaded configuration (store path, alert window).

    Returns:
        A configured :class:`FastAPI` app. A single :class:`Pipeline` is created once and
        reused across scenario triggers.
    """
    # An app-level dependency gates every route (incl. the page) behind Basic auth when
    # credentials are configured; otherwise it's a no-op for a local dev dashboard.
    guard = _build_auth_guard(config)
    app = FastAPI(
        title="minisoc dashboard", docs_url=None, redoc_url=None,
        dependencies=[Depends(guard)],
    )
    pipeline = Pipeline(config)
    store = TriageStore(triage_db_path(config))

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(_INDEX_HTML)

    @app.get("/api/risk")
    def api_risk() -> dict[str, Any]:
        return risk_board(load_alerts(config), pipeline)

    @app.get("/api/scenarios")
    def api_scenarios() -> list[dict[str, str]]:
        return list_scenarios()

    @app.get("/api/alerts")
    def api_alerts() -> list[dict[str, Any]]:
        return load_alerts(config)

    @app.get("/api/stats")
    def api_stats() -> dict[str, Any]:
        return compute_stats(load_alerts(config))

    @app.get("/api/coverage")
    def api_coverage() -> dict[str, list]:
        return coverage_summary(pipeline)

    @app.get("/api/metrics")
    def api_metrics() -> dict[str, Any]:
        triage = synced_store(config, store).metrics()
        return compute_metrics(load_alerts(config), triage)

    @app.get("/api/coverage/navigator")
    def api_navigator() -> dict[str, Any]:
        return navigator_layer(pipeline)

    @app.post("/api/run")
    def api_run(req: RunRequest) -> dict[str, Any]:
        if req.scenario not in SCENARIOS:
            raise HTTPException(status_code=404, detail=f"unknown scenario: {req.scenario}")
        return trigger_scenario(req.scenario, config, fresh=req.fresh, pipeline=pipeline)

    # -- triage / case management ------------------------------------------------------

    @app.get("/api/triage/alerts")
    def api_triage_alerts(status: str | None = None, open_only: bool = False) -> list[dict[str, Any]]:
        return synced_store(config, store).list_alerts(status=status, open_only=open_only)

    @app.get("/api/triage/stats")
    def api_triage_stats() -> dict[str, Any]:
        return synced_store(config, store).stats()

    @app.get("/api/triage/alerts/{uid}")
    def api_triage_alert(uid: str) -> dict[str, Any]:
        alert = synced_store(config, store).get_alert(uid)
        if alert is None:
            raise HTTPException(status_code=404, detail=f"unknown alert: {uid}")
        # Attach the raw triggering events and the entities worth pivoting on.
        alert["events"] = (alert.get("data") or {}).get("events") or []
        alert["pivots"] = alert_pivots(alert)
        return alert

    @app.get("/api/pivot")
    def api_pivot(field: str, value: str) -> dict[str, Any]:
        if field not in _PIVOT_FIELDS:
            raise HTTPException(status_code=400, detail=f"non-pivotable field: {field}")
        matches = synced_store(config, store).pivot(field, value)
        return {"field": field, "value": value, "count": len(matches), "matches": matches}

    @app.post("/api/triage/alerts/{uid}/status")
    def api_set_status(uid: str, req: StatusRequest) -> dict[str, Any]:
        if req.status not in STATUSES:
            raise HTTPException(status_code=400, detail=f"unknown status: {req.status}")
        if not synced_store(config, store).set_status(uid, req.status, assignee=req.assignee):
            raise HTTPException(status_code=404, detail=f"unknown alert: {uid}")
        return {"uid": uid, "status": req.status}

    @app.post("/api/triage/alerts/{uid}/note")
    def api_add_note(uid: str, req: NoteRequest) -> dict[str, Any]:
        note_id = synced_store(config, store).add_note(uid, req.body, author=req.author)
        return {"uid": uid, "note_id": note_id}

    @app.get("/api/incidents")
    def api_incidents() -> list[dict[str, Any]]:
        return synced_store(config, store).list_incidents()

    @app.post("/api/incidents")
    def api_create_incident(req: IncidentRequest) -> dict[str, Any]:
        incident_id = synced_store(config, store).group_into_incident(req.uids, req.title)
        return {"incident_id": incident_id, "title": req.title, "alerts": len(req.uids)}

    return app
