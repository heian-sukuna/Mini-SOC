"""Tests for risk-based alerting: scoring, entity attribution, dilution, thresholds."""

from __future__ import annotations

from datetime import datetime, timedelta

from minisoc.alerting.alert import Alert
from minisoc.core.event import Event
from minisoc.core.pipeline import Pipeline
from minisoc.parsers.auth_log import parse_auth_log
from minisoc.parsers.firewall import parse_firewall
from minisoc.risk import RISK_BY_SEVERITY, RiskEngine, score_for_severity
from minisoc.scenarios import network_attacks, ssh_bruteforce
from tests.util import make_config as _config

_RISK = {"enabled": True, "threshold": 100, "window": "24h"}


def _alert(rule_id, severity, *, ip=None, user=None, host=None, ts=None):
    extra = {}
    ev = Event(log_source="x", source_ip=ip, user_name=user, host_name=host, timestamp=ts)
    return Alert(rule_id=rule_id, rule_title=rule_id, severity=severity, events=[ev],
                 group_value=ip, timestamp=ts)


def test_severity_scores_are_ordered():
    assert score_for_severity("critical") > score_for_severity("high")
    assert score_for_severity("high") > score_for_severity("medium") > score_for_severity("low")
    assert score_for_severity("nonsense") == RISK_BY_SEVERITY["medium"]


def test_single_signal_below_threshold_does_not_fire():
    engine = RiskEngine(threshold=100)
    # One high (60) signal alone is under 100.
    notables = engine.assess([_alert("r1", "high", ip="1.2.3.4")])
    assert notables == []


def test_accumulated_signals_cross_threshold_and_bundle_contributors():
    engine = RiskEngine(threshold=100)
    now = datetime(2026, 6, 12, 10, 0, 0)
    alerts = [
        _alert("port-scan", "medium", ip="9.9.9.9", ts=now),                    # 30
        _alert("brute-force", "high", ip="9.9.9.9", ts=now + timedelta(minutes=1)),  # 60
        _alert("priv-esc", "high", ip="9.9.9.9", ts=now + timedelta(minutes=2)),     # 60
    ]
    notables = engine.assess(alerts)
    risk = [n for n in notables if n.risk.get("object") == "source.ip"]
    assert len(risk) == 1
    notable = risk[0]
    assert notable.rule_id == "risk-notable"
    assert notable.group_value == "9.9.9.9"
    assert notable.risk["score"] == 150               # 30 + 60 + 60
    assert {c["rule_id"] for c in notable.risk["contributors"]} == {"port-scan", "brute-force", "priv-esc"}


def test_severity_scales_with_score():
    engine = RiskEngine(threshold=100)
    # 4 high signals on one IP = 240 >= 2*threshold -> critical.
    alerts = [_alert(f"r{i}", "high", ip="5.5.5.5") for i in range(4)]
    notable = next(n for n in engine.assess(alerts) if n.risk["object"] == "source.ip")
    assert notable.severity == "critical"


def test_spray_dilutes_so_it_does_not_mint_a_notable_per_target():
    # One alert whose evidence sprays 10 usernames must not raise 10 user notables; the
    # diluted per-user score stays well under threshold, while the single IP accumulates.
    engine = RiskEngine(threshold=100)
    events = [Event(log_source="x", source_ip="7.7.7.7", user_name=f"user{i}") for i in range(10)]
    spray = Alert(rule_id="brute", rule_title="brute", severity="critical",
                  events=events, group_value="7.7.7.7")
    notables = engine.assess([spray, _alert("scan", "high", ip="7.7.7.7")])
    objects = {n.risk["object"] for n in notables}
    assert "user.name" not in objects        # no per-user notable from the spray
    # The IP still accrues (90 undivided + 60) and crosses.
    assert any(n.risk["object"] == "source.ip" and n.group_value == "7.7.7.7" for n in notables)


def test_per_rule_risk_score_override_is_used():
    engine = RiskEngine(threshold=100, rule_scores={"weak-but-noisy": 5})
    # Despite being 'critical', the override makes each contribute only 5 -> never fires alone.
    alerts = [_alert("weak-but-noisy", "critical", ip="3.3.3.3") for _ in range(3)]
    assert engine.assess(alerts) == []


def test_window_bounds_accumulation():
    engine = RiskEngine(threshold=100, window="5m")
    base = datetime(2026, 6, 12, 10, 0, 0)
    # Two high signals an hour apart never share a 5-minute window -> no crossing.
    alerts = [
        _alert("a", "high", ip="4.4.4.4", ts=base),
        _alert("b", "high", ip="4.4.4.4", ts=base + timedelta(hours=1)),
    ]
    assert [n for n in engine.assess(alerts) if n.risk["object"] == "source.ip"] == []


def test_disabled_when_not_configured():
    assert RiskEngine.from_config(_config_stub({}), []) is None
    assert RiskEngine.from_config(_config_stub({"enabled": True}), []) is not None


class _config_stub:
    def __init__(self, risk):
        self.risk = risk


# -- pipeline integration ----------------------------------------------------------------


def test_pipeline_emits_risk_notable_for_multi_signal_attacker(tmp_path):
    config = _config(tmp_path, risk=_RISK)
    pipeline = Pipeline(config)
    scanner = "45.155.205.7"
    start = datetime(2026, 6, 12, 10, 0, 0)
    fw = list(parse_firewall(network_attacks.generate_port_scan(start=start)))
    ssh = list(parse_auth_log(
        [l.replace("192.0.2.66", scanner) for l in ssh_bruteforce.generate_with_success()],
        year=2026,
    ))
    alerts = pipeline.run_events(fw + ssh)
    risk_notables = [a for a in alerts if a.rule_id == "risk-notable"]
    ip_notable = next(a for a in risk_notables if a.risk["object"] == "source.ip")
    assert ip_notable.group_value == scanner
    # port scan + brute force + success all rolled into the one attacker entity.
    assert ip_notable.risk["score"] >= 100
    assert ip_notable.risk["signals"] >= 3


def test_pipeline_without_risk_config_emits_no_notables(tmp_path):
    pipeline = Pipeline(_config(tmp_path))  # risk disabled by default
    ssh = list(parse_auth_log(ssh_bruteforce.generate_with_success(), year=2026))
    alerts = pipeline.run_events(ssh)
    assert all(a.rule_id != "risk-notable" for a in alerts)
