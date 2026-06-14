"""The enrichment layer: context added to events *before* detection.

A raw event is just "a failed login from 203.0.113.7". Enrichment turns it into "a
failed login from 203.0.113.7 — a blocklisted IP in Russia, hitting an untrusted asset":

* :mod:`~minisoc.enrichment.ioc` — match ``source.ip`` against a local threat-intel
  blocklist (IPs / CIDRs).
* :mod:`~minisoc.enrichment.geoip` — attach country and ASN from an offline table.
* :mod:`~minisoc.enrichment.assets` — map IPs to known assets (trusted/untrusted) and
  usernames to roles.

:class:`~minisoc.enrichment.enricher.Enricher` ties them together. It writes ECS-aligned
keys (``threat.matched``, ``source.geo.country_iso_code``, ``source.asset.trusted``,
``user.role``, …) into each event's ``extra`` dict, so existing rules can match on them
and the new context flows straight into alert evidence. Every rule gets richer for free,
and GeoIP unlocks the impossible-travel detection in
:mod:`minisoc.detections.behavioral`.
"""

from __future__ import annotations

from minisoc.enrichment.enricher import Enricher

__all__ = ["Enricher"]
