"""Tests for the enrichment layer: IOC matching, GeoIP, asset/identity, and wiring."""

from __future__ import annotations

import ipaddress

from minisoc.core.config import REPO_ROOT, load_config
from minisoc.core.event import Event
from minisoc.core.pipeline import Pipeline
from minisoc.enrichment.assets import Asset, AssetInventory, IdentityDirectory
from minisoc.enrichment.enricher import Enricher
from minisoc.enrichment.geoip import GeoIP, GeoRecord
from minisoc.enrichment.ioc import IOCFeed
from tests.util import make_config as _config

_INTEL = REPO_ROOT / "config" / "intel"


def _net(cidr):
    return ipaddress.ip_network(cidr)


def test_ioc_feed_matches_ip_and_cidr():
    feed = IOCFeed([_net("203.0.113.0/24"), _net("198.51.100.66/32")])
    assert feed.match("203.0.113.7") is True       # inside the CIDR
    assert feed.match("198.51.100.66") is True      # exact host
    assert feed.match("8.8.8.8") is False
    assert feed.match(None) is False


def test_geoip_longest_prefix_and_private_skip():
    geo = GeoIP([(_net("45.155.205.0/24"), GeoRecord("RU", "Russia", 64501, "AS-RU"))])
    rec = geo.lookup("45.155.205.9")
    assert rec is not None and rec.country_iso == "RU" and rec.as_org == "AS-RU"
    assert geo.lookup("10.0.0.5") is None           # private -> no geo
    assert geo.lookup("8.8.8.8") is None             # public but not in table


def test_assets_and_identities():
    inv = AssetInventory([(_net("10.0.0.0/24"), Asset("corp-lan", trusted=True))])
    assert inv.lookup("10.0.0.5") == Asset("corp-lan", trusted=True)
    assert inv.lookup("203.0.113.5") is None         # unknown -> untrusted
    ids = IdentityDirectory({"root": "admin"})
    assert ids.role("root") == "admin"
    assert ids.role("nobody") is None


def test_enricher_annotates_event_extra():
    enricher = Enricher(
        ioc=IOCFeed([_net("45.155.205.0/24")]),
        geoip=GeoIP([(_net("45.155.205.0/24"), GeoRecord("RU", "Russia", 64501, "AS-RU"))]),
        assets=AssetInventory([(_net("10.0.0.0/24"), Asset("corp-lan", trusted=True))]),
        identities=IdentityDirectory({"root": "admin"}),
    )
    event = Event(source_ip="45.155.205.7", user_name="root")
    enricher.enrich([event])
    assert event.extra["threat.matched"] is True
    assert event.extra["source.geo.country_iso_code"] == "RU"
    assert event.extra["source.as.organization"] == "AS-RU"
    assert event.extra["source.asset.trusted"] is False   # 45.155.205.7 is not a known asset
    assert event.extra["user.role"] == "admin"


def test_enricher_inert_when_unconfigured():
    event = Event(source_ip="203.0.113.7")
    Enricher().enrich([event])
    assert event.extra == {}


def test_from_config_loads_bundled_intel():
    enricher = Enricher.from_config(
        type("C", (), {"enrichment": {
            "enabled": True,
            "blocklist": _INTEL / "blocklist.txt",
            "geoip": _INTEL / "geoip.csv",
            "assets": _INTEL / "assets.yaml",
        }})()
    )
    event = Event(source_ip="45.155.205.7", user_name="victim")
    enricher.enrich([event])
    assert event.extra["threat.matched"] is True       # in blocklist.txt
    assert event.extra["source.geo.country_iso_code"] == "RU"
    assert event.extra["user.role"] == "standard"


def test_pipeline_alert_carries_enrichment(tmp_path):
    # A brute force from a blocklisted, geo-located IP -> the alert is enriched.
    config = _config(tmp_path)
    config.enrichment = {
        "enabled": True,
        "blocklist": _INTEL / "blocklist.txt",
        "geoip": _INTEL / "geoip.csv",
        "assets": _INTEL / "assets.yaml",
    }
    lines = [
        f"Jun 12 10:0{i}:00 web01 sshd[100]: Failed password for root "
        f"from 45.155.205.7 port 5000{i} ssh2"
        for i in range(6)
    ]
    pipeline = Pipeline(config)
    alerts = pipeline.run_events(pipeline.parse_lines(lines, "auth.log", year=2026))
    brute = next(a for a in alerts if a.rule_id == "ssh-bruteforce-001")
    assert brute.enrichment.get("ioc") == "local-blocklist"
    assert brute.enrichment.get("country") == "RU"
    assert brute.enrichment.get("trusted") is False
    assert "enrichment" in brute.to_dict()


# -- robustness: malformed intel files must not crash the load --------------------------


def test_geoip_csv_tolerates_malformed_asn(tmp_path):
    # A non-numeric ASN previously crashed the whole feed load; now the bad row is skipped.
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text(
        "cidr,country_iso,country_name,asn,as_org\n"
        "45.155.205.0/24,RU,Russia,ASBAD,Bad-ASN-Org\n"   # malformed ASN -> skipped
        "8.8.8.0/24,US,United States,15169,Google\n"       # good row -> loaded
    )
    geo = GeoIP.from_csv(csv_path)
    assert geo.lookup("8.8.8.8").country_iso == "US"
    assert geo.lookup("45.155.205.7") is None              # bad row was not loaded


def test_geoip_csv_tolerates_malformed_cidr(tmp_path):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("not-a-cidr,US,USA,1,Org\n8.8.8.0/24,US,USA,15169,Google\n")
    geo = GeoIP.from_csv(csv_path)
    assert geo.lookup("8.8.8.8").country_iso == "US"


def test_ioc_feed_skips_malformed_indicators(tmp_path):
    path = tmp_path / "blocklist.txt"
    path.write_text("# comment\n203.0.113.0/24\nnonsense\n999.999.0.0/16\n")
    feed = IOCFeed.from_file(path)
    assert feed.match("203.0.113.7") is True
    assert feed.match("8.8.8.8") is False
