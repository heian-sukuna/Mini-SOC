"""Alert output sinks.

A *sink* is anywhere an alert can go. minisoc ships two:

* :class:`ConsoleSink` — a pretty rich table for the analyst running the CLI.
* :class:`JsonlSink` — an append-only JSON-Lines file that acts as the persistent alert
  store. The dashboard (a later phase) reads from this file.

All sinks implement :class:`AlertSink.emit`, so the pipeline can fan an alert batch out to
any combination of them.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from minisoc.alerting.alert import Alert

__all__ = ["AlertSink", "ConsoleSink", "JsonlSink", "read_jsonl"]


_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
}


def _format_enrichment(enrichment: dict) -> str:
    """Render an alert's enrichment summary as a short human phrase."""
    parts: list[str] = []
    if enrichment.get("ioc"):
        feed = enrichment["ioc"]
        parts.append(f"[red]IOC match[/red] ({feed})" if isinstance(feed, str) else "[red]IOC match[/red]")
    if enrichment.get("country"):
        geo = enrichment["country"]
        if enrichment.get("as_org"):
            geo += f" / {enrichment['as_org']}"
        parts.append(geo)
    if "trusted" in enrichment:
        parts.append("trusted asset" if enrichment["trusted"] else "[yellow]untrusted asset[/yellow]")
    if enrichment.get("asset"):
        parts.append(str(enrichment["asset"]))
    if enrichment.get("role"):
        parts.append(f"role={enrichment['role']}")
    return " · ".join(parts)


class AlertSink(ABC):
    """Base class for alert output destinations."""

    @abstractmethod
    def emit(self, alerts: list[Alert]) -> None:
        """Send a batch of alerts to this sink."""
        raise NotImplementedError


class ConsoleSink(AlertSink):
    """Renders alerts as a colored rich table on the terminal.

    Args:
        console: The rich :class:`~rich.console.Console` to print to.
    """

    def __init__(self, console: Console) -> None:
        self._console = console

    def emit(self, alerts: list[Alert]) -> None:
        if not alerts:
            self._console.print(Panel("[green]No alerts fired.[/green]", title="minisoc"))
            return

        table = Table(title=f"{len(alerts)} alert(s)", header_style="bold")
        table.add_column("Severity")
        table.add_column("Rule")
        table.add_column("Source")
        table.add_column("Group")
        table.add_column("Seen", justify="right")
        table.add_column("Latest")

        for alert in alerts:
            style = _SEVERITY_STYLE.get(alert.severity, "white")
            seen = str(alert.occurrences) + ("x" if alert.occurrences > 1 else "")
            table.add_row(
                f"[{style}]{alert.severity.upper()}[/{style}]",
                f"{alert.rule_title}\n[dim]{alert.rule_id}[/dim]",
                alert.source or "-",
                str(alert.group_value or "-"),
                seen,
                alert.timestamp.strftime("%Y-%m-%d %H:%M:%S") if alert.timestamp else "-",
            )
        self._console.print(table)

        for alert in alerts:
            if alert.enrichment:
                self._console.print(
                    f"[dim]{alert.rule_id} context:[/dim] {_format_enrichment(alert.enrichment)}"
                )
            if alert.description:
                self._console.print(f"[dim]{alert.rule_id}:[/dim] {alert.description.strip()}")


class JsonlSink(AlertSink):
    """Appends alerts to a JSON-Lines file (the persistent alert store).

    One JSON object per line (via :meth:`Alert.to_dict`). Append-only so the store
    accumulates across runs — which is what the dashboard reads.

    Args:
        path: Destination ``.jsonl`` file. Parent directories are created as needed.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        """The store file path."""
        return self._path

    def reset(self) -> None:
        """Truncate the store (used for clean demo runs)."""
        if self._path.exists():
            self._path.unlink()

    def emit(self, alerts: list[Alert]) -> None:
        if not alerts:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as handle:
            for alert in alerts:
                handle.write(json.dumps(alert.to_dict()) + "\n")


def read_jsonl(path: str | Path) -> list[dict]:
    """Read an alert JSONL store back into a list of dicts.

    Tolerates a missing file (returns ``[]``) and skips malformed lines, so a partially
    written store never breaks a reader (e.g. the dashboard).

    Args:
        path: Path to the JSONL store.

    Returns:
        The decoded alert records, in file order.
    """
    path = Path(path)
    if not path.exists():
        return []
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records
