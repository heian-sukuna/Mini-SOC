"""``minisoc`` command-line entry point.

Subcommands:

* ``minisoc run --scenario <name>`` — generate malicious logs for a scenario, run the
  detection pipeline, deduplicate, print alerts, and append them to the JSONL store.
* ``minisoc replay <file>...`` — run real/recorded logs (public datasets, lab captures)
  through the same pipeline, with ``--expect benign|attack`` validation verdicts.
* ``minisoc watch <file>...`` — live mode: tail real log files and alert continuously.
* ``minisoc coverage`` — MITRE ATT&CK technique coverage across the loaded rules.
* ``minisoc list`` — show available scenarios and loaded rules.
* ``minisoc serve`` — launch the dashboard (FastAPI) which reads the store and can trigger
  scenarios from the browser.

Scenario running is delegated to :func:`minisoc.core.runner.run_scenario`, the same code
path the dashboard uses.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table

from minisoc.alerting.sinks import ConsoleSink
from minisoc.core.config import load_config
from minisoc.core.pipeline import Pipeline
from minisoc.core.replay import replay_files
from minisoc.core.runner import run_scenario
from minisoc.detections.coverage import mitre_coverage
from minisoc.parsers import access_log, auth_log, sysmon
from minisoc.scenarios.registry import SCENARIOS, scenario_names


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="minisoc",
        description="A lightweight, self-contained SIEM-style detection lab.",
    )
    parser.add_argument("--config", type=Path, default=None, help="path to config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run an attack scenario through the pipeline")
    run.add_argument(
        "--scenario",
        required=True,
        choices=scenario_names(),
        help="which attack scenario to generate and detect",
    )
    run.add_argument(
        "--fresh",
        action="store_true",
        help="truncate the JSONL alert store before this run (clean demo)",
    )
    run.add_argument(
        "--no-store",
        action="store_true",
        help="do not append alerts to the JSONL store (console output only)",
    )
    run.set_defaults(func=_cmd_run)

    replay = sub.add_parser(
        "replay", help="run real/recorded log files through the pipeline"
    )
    replay.add_argument("paths", nargs="+", type=Path, help="log file(s) to replay")
    replay.add_argument(
        "--source",
        choices=[auth_log.LOG_SOURCE, access_log.LOG_SOURCE, sysmon.LOG_SOURCE],
        default=None,
        help="force a parser for all files (default: auto-detect per file)",
    )
    replay.add_argument(
        "--expect",
        choices=["benign", "attack"],
        default=None,
        help="benign = alerts are false positives; attack = alerts are hits",
    )
    replay.add_argument(
        "--year", type=int, default=None, help="year for year-less auth.log timestamps"
    )
    replay.add_argument(
        "--store", action="store_true", help="append alerts to the JSONL store"
    )
    replay.add_argument(
        "--fresh", action="store_true", help="with --store, truncate the store first"
    )
    replay.set_defaults(func=_cmd_replay)

    watch = sub.add_parser(
        "watch", help="tail real log files and run detections continuously (live mode)"
    )
    watch.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="log file(s) to tail (default: the 'live: sources:' list in config)",
    )
    watch.add_argument(
        "--source",
        choices=[auth_log.LOG_SOURCE, access_log.LOG_SOURCE, sysmon.LOG_SOURCE],
        default=None,
        help="force a parser for all files (default: auto-detect per file)",
    )
    watch.add_argument(
        "--interval",
        type=float,
        default=None,
        help="seconds between polls (default: config live.poll_interval)",
    )
    watch.add_argument(
        "--from-start",
        action="store_true",
        help="also process lines already in the files (default: new lines only)",
    )
    watch.add_argument(
        "--no-store",
        action="store_true",
        help="do not append alerts to the JSONL store (console output only)",
    )
    watch.set_defaults(func=_cmd_watch)

    listing = sub.add_parser("list", help="list available scenarios and loaded rules")
    listing.set_defaults(func=_cmd_list)

    coverage = sub.add_parser("coverage", help="show MITRE ATT&CK technique coverage")
    coverage.set_defaults(func=_cmd_coverage)

    efficacy = sub.add_parser(
        "efficacy", help="score detection precision/recall/FP-rate against a labeled corpus"
    )
    efficacy.add_argument(
        "--dir", type=Path, default=None,
        help="labeled corpus directory (default: datasets/efficacy)",
    )
    efficacy.add_argument(
        "--json", type=Path, default=None, metavar="PATH",
        help="also write the full report as JSON to PATH",
    )
    efficacy.set_defaults(func=_cmd_efficacy)

    triage = sub.add_parser("triage", help="triage alerts: list, status, notes, incidents")
    triage.add_argument("--all", action="store_true", help="list all alerts, not just open ones")
    triage.add_argument("--status", default=None, help="filter the listing by status")
    triage.add_argument("--show", metavar="UID", default=None, help="show one alert with its notes")
    triage.add_argument(
        "--set-status", nargs=2, metavar=("UID", "STATUS"), default=None,
        help="set an alert's status (new/acknowledged/in_progress/closed_true_positive/closed_false_positive)",
    )
    triage.add_argument(
        "--note", nargs=2, metavar=("UID", "TEXT"), default=None, help="attach a note to an alert"
    )
    triage.add_argument("--incident", metavar="TITLE", default=None, help="group alerts into a new incident")
    triage.add_argument(
        "--uid", action="append", default=[], help="alert uid for --incident (repeatable)"
    )
    triage.set_defaults(func=_cmd_triage)

    sigma = sub.add_parser("sigma", help="analyze/import upstream SigmaHQ rules")
    sigma.add_argument(
        "--dir", type=Path, default=None,
        help="directory of upstream Sigma rules (default: config sigma_rules_dir or examples/sigma)",
    )
    sigma.add_argument(
        "--verbose", action="store_true", help="list every skipped rule and its reason(s)"
    )
    sigma.set_defaults(func=_cmd_sigma)

    serve = sub.add_parser("serve", help="launch the dashboard web app")
    serve.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8000, help="bind port (default 8000)")
    serve.set_defaults(func=_cmd_serve)

    return parser


def _cmd_run(args: argparse.Namespace, console: Console) -> int:
    config = load_config(args.config)

    result = run_scenario(
        args.scenario, config, fresh=args.fresh, store=not args.no_store
    )

    console.print(
        f"[bold]minisoc[/bold] generated [cyan]{result.lines_generated}[/cyan] log "
        f"line(s) -> [dim]{result.log_path}[/dim]"
    )
    console.print(f"Loaded [cyan]{result.rule_count}[/cyan] rule(s).")
    if result.deduped_count != result.raw_alert_count:
        console.print(
            f"Deduplicated [cyan]{result.raw_alert_count}[/cyan] -> "
            f"[cyan]{result.deduped_count}[/cyan] alert(s) (window {config.alert_window})."
        )

    ConsoleSink(console).emit(result.alerts)

    from minisoc.alerting.notify import build_notification_sinks

    for sink in build_notification_sinks(config):
        sink.emit(result.alerts)

    if result.stored:
        from minisoc.scenarios.registry import store_path

        console.print(
            f"[dim]Appended {result.deduped_count} alert(s) to {store_path(config)}[/dim]"
        )
    return 0


def _cmd_replay(args: argparse.Namespace, console: Console) -> int:
    config = load_config(args.config)

    result = replay_files(
        args.paths,
        config,
        source=args.source,
        expect=args.expect,
        year=args.year,
        store=args.store,
        fresh=args.fresh,
    )

    sources = ", ".join(sorted({src for _, src in result.files}))
    console.print(
        f"[bold]minisoc[/bold] replayed [cyan]{len(result.files)}[/cyan] file(s) "
        f"([dim]{sources}[/dim]): [cyan]{result.lines_read}[/cyan] line(s) -> "
        f"[cyan]{result.events_parsed}[/cyan] parsed event(s)."
    )

    ConsoleSink(console).emit(result.alerts)

    # Color the verdict by what it means: a clean benign run / a caught attack is good.
    good = (args.expect == "benign" and result.false_positives == 0) or (
        args.expect == "attack" and result.alert_count > 0
    )
    style = "bold green" if good else "bold yellow" if args.expect else "bold"
    console.print(f"[{style}]{result.verdict}[/{style}]")

    if result.stored:
        from minisoc.scenarios.registry import store_path

        console.print(
            f"[dim]Appended {result.alert_count} alert(s) to {store_path(config)}[/dim]"
        )
    return 0


def _cmd_watch(args: argparse.Namespace, console: Console) -> int:
    from minisoc.alerting.sinks import JsonlSink
    from minisoc.core.live import FileTail, LiveMonitor
    from minisoc.core.replay import detect_source
    from minisoc.scenarios.registry import store_path

    config = load_config(args.config)

    if args.paths:
        entries = [{"path": p, "source": args.source} for p in args.paths]
    else:
        entries = [
            {"path": e["path"], "source": e["source"] or args.source}
            for e in config.live_sources
        ]
    if not entries:
        console.print(
            "[bold red]error:[/bold red] nothing to watch — pass log file path(s) or "
            "add a 'live: sources:' section to config.yaml"
        )
        return 1

    tails = []
    for entry in entries:
        path = Path(entry["path"])
        source = entry["source"]
        if source is None:
            if not path.exists():
                console.print(
                    f"[bold red]error:[/bold red] {path} does not exist yet; "
                    "pass --source (or set it in config) to watch a file that will appear later"
                )
                return 1
            source = detect_source(path)
        tails.append(FileTail(path, source, from_start=args.from_start))

    from minisoc.alerting.notify import build_notification_sinks

    sinks = [ConsoleSink(console)]
    if not args.no_store:
        sinks.append(JsonlSink(store_path(config)))
    notifiers = build_notification_sinks(config)
    sinks.extend(notifiers)

    monitor = LiveMonitor(config, tails, sinks=sinks)
    interval = args.interval if args.interval is not None else config.live_poll_interval

    console.print(
        f"[bold]minisoc[/bold] live mode — [cyan]{monitor.pipeline.rule_count}[/cyan] "
        f"rule(s) loaded, polling every [cyan]{interval:g}s[/cyan] (Ctrl-C to stop)."
    )
    for tail in tails:
        console.print(f"  watching [cyan]{tail.path}[/cyan] as [dim]{tail.source}[/dim]")
    if notifiers:
        console.print(f"[dim]{len(notifiers)} notification channel(s) armed.[/dim]")
    if args.no_store:
        console.print("[dim]Alerts will not be persisted (--no-store).[/dim]")
    else:
        console.print(
            f"[dim]Alerts append to {store_path(config)} — "
            "open `minisoc serve` to watch them on the dashboard.[/dim]"
        )

    try:
        monitor.run(interval)
    except KeyboardInterrupt:
        console.print(
            f"\n[bold]minisoc[/bold] live mode stopped: read "
            f"[cyan]{monitor.lines_read}[/cyan] line(s) -> "
            f"[cyan]{monitor.events_parsed}[/cyan] event(s), emitted "
            f"[cyan]{monitor.alerts_emitted}[/cyan] alert(s)."
        )
    return 0


def _cmd_coverage(args: argparse.Namespace, console: Console) -> int:
    config = load_config(args.config)
    pipeline = Pipeline(config)
    rollup = mitre_coverage(pipeline.tagged_rules())

    table = Table(title="MITRE ATT&CK coverage", header_style="bold")
    table.add_column("Technique")
    table.add_column("Rules")
    table.add_column("Reference", overflow="fold")
    for tech in rollup["techniques"]:
        rule_lines = "\n".join(
            f"{r['id']} ({r['severity']})" for r in tech["rules"]
        )
        table.add_row(tech["technique"], rule_lines, tech["url"])
    console.print(table)

    if rollup["untagged"]:
        console.print(
            f"[yellow]Untagged rules (no ATT&CK technique):[/yellow] "
            f"{', '.join(rollup['untagged'])}"
        )
    else:
        console.print("[green]All rules carry an ATT&CK technique tag.[/green]")
    return 0


def _cmd_efficacy(args: argparse.Namespace, console: Console) -> int:
    import json as _json

    from minisoc.core.config import REPO_ROOT
    from minisoc.efficacy import evaluate, load_cases

    corpus_dir = args.dir or REPO_ROOT / "datasets" / "efficacy"
    if not corpus_dir.exists():
        console.print(f"[red]error:[/red] corpus directory not found: {corpus_dir}")
        return 1

    config = load_config(args.config)
    cases = load_cases(corpus_dir)
    if not cases:
        console.print(f"[yellow]no cases found under {corpus_dir}[/yellow]")
        return 1
    report = evaluate(cases, config)

    def _pct(x: float) -> str:
        return f"{x * 100:.1f}%"

    table = Table(title="Detection efficacy (per rule)", header_style="bold", box=box.SIMPLE_HEAD)
    table.add_column("Rule", no_wrap=True)
    for col in ("TP", "FP", "FN"):
        table.add_column(col, justify="right")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("F1", justify="right")
    for r in report.rules:
        if not (r.tested or r.fp):
            continue  # skip rules with no signal at all (kept in the JSON export)
        fp_style = "red" if r.fp else None
        table.add_row(
            r.rule_id, str(r.tp),
            f"[red]{r.fp}[/red]" if r.fp else "0", str(r.fn),
            _pct(r.precision), _pct(r.recall), f"{r.f1:.2f}",
            style=fp_style,
        )
    console.print(table)

    # Headline rollup.
    summary = Table.grid(padding=(0, 2))
    summary.add_row("Cases", f"{report.case_count} ({report.attack_cases} attack, {report.benign_cases} benign)")
    summary.add_row("Micro precision / recall / F1",
                    f"{_pct(report.micro_precision)} / {_pct(report.micro_recall)} / {report.micro_f1:.2f}")
    summary.add_row("Benign false-positive rate",
                    f"{_pct(report.benign_fp_rate)}  ({report.fp_per_1k_lines:.2f} FP / 1k benign lines)")
    console.print(summary)

    if report.misses:
        console.print("[red]Missed detections:[/red] " +
                      ", ".join(f"{c}→{r}" for c, r in report.misses))
    if report.untested_rules:
        console.print("[yellow]Untested rules (no attack case):[/yellow] " +
                      ", ".join(report.untested_rules))
    if not report.misses and report.benign_false_positives == 0:
        console.print("[green]No misses and no benign false positives across the corpus.[/green]")

    if args.json:
        args.json.write_text(_json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        console.print(f"Wrote JSON report to [cyan]{args.json}[/cyan]")
    # Non-zero exit on any miss or benign FP, so this is CI-usable as a quality gate.
    return 0 if not report.misses and report.benign_false_positives == 0 else 2


def _cmd_triage(args: argparse.Namespace, console: Console) -> int:
    from minisoc.scenarios.registry import store_path
    from minisoc.triage import STATUSES, TriageStore, triage_db_path

    config = load_config(args.config)
    store = TriageStore(triage_db_path(config))
    new = store.sync_from_jsonl(store_path(config))
    if new:
        console.print(f"[dim]synced {new} new alert(s) from the store[/dim]")

    if args.set_status:
        uid, status = args.set_status
        if status not in STATUSES:
            console.print(f"[bold red]error:[/bold red] unknown status {status!r}; choose from {', '.join(STATUSES)}")
            return 1
        ok = store.set_status(uid, status)
        console.print(f"{'set' if ok else '[yellow]no such alert:[/yellow]'} {uid} -> {status}")
        return 0 if ok else 1

    if args.note:
        uid, text = args.note
        store.add_note(uid, text)
        console.print(f"noted on {uid}")
        return 0

    if args.incident:
        if not args.uid:
            console.print("[bold red]error:[/bold red] --incident needs at least one --uid")
            return 1
        incident_id = store.group_into_incident(args.uid, args.incident)
        console.print(f"created incident #{incident_id} [bold]{args.incident}[/bold] with {len(args.uid)} alert(s)")
        return 0

    if args.show:
        alert = store.get_alert(args.show)
        if alert is None:
            console.print(f"[yellow]no such alert:[/yellow] {args.show}")
            return 1
        console.print(
            f"[bold]{alert['rule_title']}[/bold] [dim]{alert['uid']}[/dim]\n"
            f"  severity={alert['severity']}  status=[cyan]{alert['status']}[/cyan]  "
            f"source={alert['source']}  group={alert['group_value']}\n"
            f"  when={alert['timestamp']}  occurrences={alert['occurrences']}"
        )
        if alert.get("enrichment"):
            console.print(f"  context: {alert['enrichment']}")
        for note in alert.get("notes", []):
            console.print(f"  [dim]note ({note['author']} @ {note['created_at']}):[/dim] {note['body']}")
        return 0

    # Default: list alerts.
    alerts = store.list_alerts(status=args.status, open_only=not args.all and not args.status)
    stats = store.stats()
    table = Table(
        title=f"{stats['open']} open / {stats['total']} total alert(s), {stats['incidents']} incident(s)",
        header_style="bold",
    )
    table.add_column("UID", no_wrap=True)
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Rule", no_wrap=True)
    table.add_column("Group")
    table.add_column("When")
    for a in alerts:
        table.add_row(
            a["uid"], a["severity"], a["status"], a["rule_id"],
            str(a["group_value"] or "-"), (a["timestamp"] or "-")[:19],
        )
    console.print(table)
    console.print(
        "[dim]ack:[/dim] minisoc triage --set-status <uid> acknowledged   "
        "[dim]close:[/dim] --set-status <uid> closed_true_positive"
    )
    return 0


def _cmd_sigma(args: argparse.Namespace, console: Console) -> int:
    from minisoc.core.config import REPO_ROOT
    from minisoc.detections.sigma_import import import_sigma_dir

    config = load_config(args.config)
    rules_dir = args.dir or config.sigma_rules_dir or (REPO_ROOT / "examples" / "sigma")
    if not Path(rules_dir).exists():
        console.print(f"[bold red]error:[/bold red] no such directory: {rules_dir}")
        return 1

    report = import_sigma_dir(rules_dir)
    console.print(
        f"[bold]minisoc[/bold] analyzed [cyan]{report.total}[/cyan] upstream Sigma rule(s) "
        f"in [dim]{rules_dir}[/dim]: [green]{report.loaded_count} importable[/green], "
        f"[yellow]{len(report.skipped)} skipped[/yellow]."
    )

    if report.loaded:
        table = Table(title="Importable", header_style="bold")
        table.add_column("Id", no_wrap=True)
        table.add_column("Title", no_wrap=True)
        table.add_column("Level")
        for rule in report.loaded:
            table.add_row(rule.id, rule.title, rule.level)
        console.print(table)

    if report.skipped:
        table = Table(title="Skipped (unsupported features)", header_style="bold")
        table.add_column("File", no_wrap=True)
        table.add_column("Reason(s)", overflow="fold")
        for result in report.skipped:
            reasons = "; ".join(result.reasons) if args.verbose else result.reasons[0]
            table.add_row(Path(result.path).name, reasons)
        console.print(table)

    console.print(
        "[dim]Point a real clone at this: minisoc sigma --dir ~/sigma/rules/windows/process_creation[/dim]"
    )
    return 0


def _cmd_list(args: argparse.Namespace, console: Console) -> int:
    config = load_config(args.config)
    pipeline = Pipeline(config)

    scenarios = Table(title="Scenarios", header_style="bold")
    scenarios.add_column("Name")
    scenarios.add_column("Log source")
    for name in scenario_names():
        scenarios.add_row(name, SCENARIOS[name][1])
    console.print(scenarios)

    rules = Table(title=f"{pipeline.rule_count} rule(s)", header_style="bold")
    rules.add_column("Id")
    rules.add_column("Title")
    rules.add_column("Severity")
    rules.add_column("Kind")
    for rule in pipeline.rules:
        rules.add_row(rule.id, rule.title, rule.level, "detection")
    for corr in pipeline.correlations:
        rules.add_row(corr.id, corr.title, corr.level, f"correlation ({corr.type})")
    console.print(rules)
    return 0


def _cmd_serve(args: argparse.Namespace, console: Console) -> int:
    import uvicorn

    from minisoc.dashboard.app import create_app

    config = load_config(args.config)
    app = create_app(config)
    console.print(
        f"[bold]minisoc[/bold] dashboard on "
        f"[cyan]http://{args.host}:{args.port}[/cyan]  (Ctrl-C to stop)"
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


# (command, what it does) rows for the top-level `minisoc --help` overview table.
_HELP_ROWS = [
    ("minisoc list", "Show all scenarios and all rules (with severity and kind)"),
    ("minisoc run --scenario <name>", "Generate attack logs, run detection, print + store alerts"),
    ("minisoc run --scenario <name> --fresh", "Same, but clear the alert store first (clean demo)"),
    ("minisoc run --scenario <name> --no-store", "Console output only, nothing persisted"),
    ("minisoc replay <file>...", "Run real/recorded logs through the pipeline (auto-detects source)"),
    ("minisoc replay <file> --expect benign", "False-positive test: count alerts on a benign corpus"),
    ("minisoc watch <file>...", "Live mode: tail real logs and alert continuously (Ctrl-C stops)"),
    ("minisoc coverage", "Show MITRE ATT&CK technique coverage across the rules"),
    ("minisoc efficacy", "Score detection precision/recall/FP-rate against the labeled corpus"),
    ("minisoc sigma --dir <path>", "Analyze/import upstream SigmaHQ rules (reports what's compatible)"),
    ("minisoc triage", "Triage stored alerts: list open, set status, add notes, group incidents"),
    ("minisoc serve", "Launch the dashboard at http://127.0.0.1:8000 (--port to change)"),
    ("minisoc --config <file> <cmd>", "Use an alternate config instead of config/config.yaml"),
    ("pytest", "Run the test suite (from the repo root)"),
]


def _print_help(console: Console) -> None:
    """Print the top-level command overview as a table."""
    console.print(
        "[bold]minisoc[/bold] — a lightweight, self-contained SIEM-style detection lab.\n"
    )
    table = Table(box=box.SQUARE, show_lines=True, header_style="bold")
    table.add_column("Command", no_wrap=True)
    table.add_column("What it does")
    for command, description in _HELP_ROWS:
        table.add_row(command, description)
    console.print(table)
    console.print(
        "\nScenario names: [cyan]minisoc list[/cyan] · "
        "per-command options: [cyan]minisoc <command> --help[/cyan]"
    )


def main(argv: list[str] | None = None) -> int:
    """Console entry point. Returns a process exit code."""
    args_list = sys.argv[1:] if argv is None else list(argv)
    console = Console()
    # A bare `minisoc` or top-level `-h`/`--help` gets the command overview table;
    # `minisoc <command> --help` keeps argparse's detailed flag help.
    if not args_list or args_list[0] in ("-h", "--help"):
        _print_help(console)
        return 0
    parser = _build_parser()
    args = parser.parse_args(args_list)
    try:
        return args.func(args, console)
    except Exception as exc:  # pragma: no cover - top-level guard
        console.print(f"[bold red]error:[/bold red] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
