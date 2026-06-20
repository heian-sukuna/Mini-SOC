# minisoc Still work in progress

A lightweight, **self-contained SIEM-style detection lab** — a blue-team portfolio
project. Raw logs → normalization → a Sigma-compatible detection engine → alerting → a
web dashboard. It ships with attack-scenario generators so anyone who clones the repo can
run one command and watch detections fire on realistic malicious log data.

No external services. Runs entirely on a single Linux box.

> **Status: Phase 5 complete.** 3 parsers (Linux `auth.log`, nginx/apache access logs,
> Sysmon JSON), 9 detection rules — including a **temporal correlation** (brute force
> followed by a successful login → critical) — 8 attack scenarios, an alerting layer with
> windowed deduplication + a persistent JSONL alert store, and a FastAPI dashboard that
> triggers scenarios from the browser and shows alerts live. **Now with a live side:**
> `replay` for recorded logs (with benign/attack validation verdicts), `watch` for
> tailing real logs continuously, ATT&CK `coverage` reporting, and a dashboard that
> separates simulation from live alerts — 114 passing tests.

## Architecture

```
 log file ──▶ parser ──▶ normalized Event (ECS-aligned) ──▶ detection engine ──▶ Alert ──▶ dedup ──▶ sinks
 (auth.log)  (per source) (@timestamp, event.action,         (Sigma-subset:        (windowed)  (CLI / JSONL
                            source.ip, user.name, …)           selections+condition              store → dashboard)
                                                               + windowed count)
 scenarios ──▶ emit realistic malicious log lines into the same formats parsers read
```

The CLI and the dashboard drive scenarios through **one shared runner**
(`core/runner.py`), so a scenario triggered from the browser produces identical alerts to
one run in the terminal.

Package layout:

```
minisoc/
  core/        event schema, config loader, pipeline + shared scenario runner
  parsers/     one module per log source -> normalized events   [auth.log, access.log, sysmon]
  detections/  the Sigma-subset engine + rule loader; rules/ holds YAML rules
  scenarios/   attack simulators that EMIT logs (never run real attacks) + registry
  alerting/    Alert model, windowed Deduplicator, sinks (rich console + JSONL store)
  dashboard/   FastAPI app + one static HTML page  -> `minisoc serve`
  cli/         argparse entry point -> `minisoc`
tests/         pytest (parser + rule, match & non-match; runner; dashboard)
config/        config.yaml
data/generated/ scenario output + the JSONL alert store land here
```

## Install

Requires Python 3.12+ (Arch/CachyOS: `python` is 3.12+; Kali/Debian/Ubuntu ship
3.13). On Debian-based systems (Kali, Ubuntu) the stdlib `venv` support lives in a
separate `python3-venv` package — the quick-install script installs it for you; for
a manual install see the note below.

### Quick install (recommended)

After cloning, run the bundled setup script. It finds a suitable Python, creates
the virtualenv, installs the package with its dev dependencies, runs a smoke test,
and prints the activation line for your shell:

```bash
git clone <repo> Mini-SOC && cd Mini-SOC
./install.sh
```

Flags:

| Flag | Effect |
|------|--------|
| `--symlink`  | Also link `minisoc` into `~/.local/bin` so it runs without activating the venv |
| `--recreate` | Delete and rebuild `.venv` from scratch |
| `--no-test`  | Skip the post-install `pytest` smoke check |
| `--help`     | Show usage |

The script is safe to re-run — an existing `.venv` is reused unless you pass
`--recreate`.

### Manual install

If you'd rather set it up by hand:

```bash
git clone <repo> Mini-SOC && cd Mini-SOC
# Debian/Kali/Ubuntu only: install venv support first (matches your Python version)
#   sudo apt install python3-venv        # or e.g. python3.13-venv
python -m venv .venv && source .venv/bin/activate    # fish: source .venv/bin/activate.fish
pip install -e ".[dev]"
```

On Debian-based systems `python -m venv` fails with *"ensurepip is not available"*
until `python3-venv` is installed; the `./install.sh` path handles this automatically.

Either path installs the `minisoc` console command inside the venv.

### Use `minisoc` from anywhere (optional)

To run `minisoc` from any directory without activating the venv, symlink it onto
your PATH (`./install.sh --symlink` does this for you):

```bash
ln -sf "$PWD/.venv/bin/minisoc" ~/.local/bin/minisoc
```

The script's shebang points at the venv's interpreter, so it works without
activation. All paths (config, rules, `data/generated/`) resolve relative to the
repo root regardless of where you invoke it — running `minisoc run ...` from
`~/Downloads` still writes logs and alerts under `Mini-SOC/data/generated/`.
(Requires `~/.local/bin` on your PATH — it is by default on most setups.)

## Quickstart

List what's available, then run any scenario through the full pipeline:

```bash
minisoc --help                        # command overview table
minisoc list                          # 8 scenarios + loaded rules
minisoc run --scenario ssh-bruteforce
```

You'll see minisoc generate `auth.log` lines into `data/generated/auth.log`, load the
detection rules, and print a fired **SSH Brute Force** alert (severity HIGH) for the
attacker IP that exceeded 5 failed logins in 5 minutes.

Other scenarios: `ssh-bruteforce-success` (the brute force that *worked* — fires the
critical correlation), `sudo-privesc` (auth logs), `web-shell`, `dir-traversal`, `sqli`
(access logs), `port-scan`, `log-tampering` (Sysmon).

### Dashboard

Launch the web UI and drive everything from the browser:

```bash
minisoc serve                 # http://127.0.0.1:8000
```

The page shows a severity-colored alert feed (newest first) with counts by severity,
source, and **origin**, and a button per scenario — click one to generate logs, run
detections, and watch the alert appear (the feed live-polls every 3 seconds). The
**fresh** checkbox clears the alert store before a run for a clean demo. The dashboard
reads the same JSONL store the CLI writes, so alerts run from the terminal show up here
too. The origin tabs (**all / live / simulation / replay**) split the training side from
real detections.

## Two sides: training and live

minisoc is built to be both a teaching tool and a deployable one — so SOC personnel can
learn it on safe simulations and then operate the *same* engine on real logs.

- **Training side — `minisoc run`.** Synthetic attack scenarios that emit log lines into
  the formats the parsers read. Deterministic, browser-triggerable, safe. Alerts are
  tagged `simulation`.
- **Live / deployable side:**
  - **`minisoc replay <file>...`** runs real or recorded logs (public datasets, lab
    captures) through the pipeline, with `--expect benign|attack` to print a
    false-positive rate or a DETECTED/MISSED verdict. Alerts are tagged `replay`.
  - **`minisoc watch <file>...`** tails real log files and runs detections continuously,
    handling rotation/truncation and not re-alerting while the same pattern keeps
    matching. Alerts are tagged `live` and land on the dashboard in real time.

Every layer except the log *source* is shared between the two sides, so a detection an
analyst practiced in simulation behaves identically on real traffic.

```bash
minisoc run --scenario ssh-bruteforce                 # training: synthetic attack
minisoc replay /var/log/nginx/access.log --expect benign   # false-positive test on real logs
minisoc watch /tmp/auth-live.log --source auth.log    # live: tail real logs, alert continuously
minisoc coverage                                       # MITRE ATT&CK technique coverage
```

Configure default files for live mode under a `live:` section in `config/config.yaml`.
The full methodology — public datasets (loghub, EVTX-ATTACK-SAMPLES, Mordor, BOTS),
false-positive testing, running real attacks in an isolated CachyOS lab (podman/libvirt
with hydra/nmap/Atomic Red Team), ATT&CK tagging, and a pySigma cross-check — is in
[`docs/validation.md`](docs/validation.md).

## Tests

```bash
pytest
```

Every parser and every rule has a matching-event test and a non-matching-event test
(to prove rules don't false-positive).

## Detections & scenarios

Nine rules ship in `minisoc/detections/rules/`, each paired with a scenario that emits the
matching logs so you can fire it end-to-end. Run any with `minisoc run --scenario <name>`.

| Scenario | Log source | Rule | Severity | ATT&CK |
| --- | --- | --- | --- | --- |
| `ssh-bruteforce` | auth.log | SSH Brute Force | high | T1110 |
| `ssh-bruteforce-success` | auth.log | SSH Brute Force → Successful Login *(temporal correlation)* | **critical** | T1110, T1078 |
| `sudo-privesc` | auth.log | Sudo Privilege Escalation to Root | high | T1548.003 |
| `sqli` | access.log | SQL Injection Attempt | high | T1190 |
| `dir-traversal` | access.log | Directory Traversal Attempt | medium | T1083 |
| `web-shell` | access.log | Web Shell Access | high | T1505.003 |
| `port-scan` / `firewall-port-scan` | sysmon / firewall | Port Scan | medium | T1046 |
| `log-tampering` | sysmon | Log Clearing / Tampering | high | T1070.001 |

The `ssh-bruteforce-success` correlation is the headline detection: a windowed brute force
followed by an accepted login for the same source — "the brute force that worked." See full
ATT&CK technique coverage with `minisoc coverage`.

## Detection rules

Rules live in `minisoc/detections/rules/` as Sigma-subset YAML. The engine supports
`logsource` matching, named `detection:` selections, field modifiers
(`contains`/`startswith`/`endswith`/`re`), a `condition:` with `and`/`or`/`not` and
`1 of`/`all of`, a windowed `| count() by <field> <op> <n>` aggregation, and **temporal
correlation rules** (`correlation:` documents with `type: temporal`/`temporal_ordered`,
`rules:`, `group-by:`, `timespan:`) that chain other rules' firings — rules referenced by
a correlation are suppressed from alerting unless listed in `generate:`.
