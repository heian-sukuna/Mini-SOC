"""The :class:`Enricher` — annotate events with threat-intel, geo, and asset context.

Runs between parsing and detection: for every event it looks up the source IP against the
IOC feed, GeoIP table, and asset inventory, and the username against the identity
directory, then writes ECS-aligned keys into the event's ``extra`` dict:

==============================  ===========================================
key                             meaning
==============================  ===========================================
``threat.matched``              ``True`` when ``source.ip`` is on a blocklist
``threat.feed``                 the feed that matched
``source.geo.country_iso_code`` ISO country of ``source.ip``
``source.geo.country_name``     country name
``source.as.number``            ASN of ``source.ip``
``source.as.organization``      AS org name
``source.asset.name``           hostname of the source asset (if known)
``source.asset.trusted``        whether the source is trusted infrastructure
``user.role``                   role of ``user.name`` (admin/developer/…)
==============================  ===========================================

Because rules resolve dotted keys through :meth:`Event.get`, a rule can now match e.g.
``threat.matched: true``; and because alert evidence serializes ``extra``, the context
rides along into the alert store and dashboard. :meth:`enrich_alert` additionally folds a
compact summary onto the alert itself for the console/dashboard one-liner.
"""

from __future__ import annotations

from minisoc.core.event import Event
from minisoc.enrichment.assets import AssetInventory, IdentityDirectory, load_assets
from minisoc.enrichment.geoip import GeoIP
from minisoc.enrichment.ioc import IOCFeed

__all__ = ["Enricher"]


class Enricher:
    """Annotates events (and summarizes alerts) with intel/geo/asset context.

    Args:
        ioc: Threat-intel feed for ``source.ip`` matching.
        geoip: Offline GeoIP/ASN table.
        assets: Asset inventory for ``source.ip``.
        identities: Username -> role directory.
    """

    def __init__(
        self,
        *,
        ioc: IOCFeed | None = None,
        geoip: GeoIP | None = None,
        assets: AssetInventory | None = None,
        identities: IdentityDirectory | None = None,
    ) -> None:
        self._ioc = ioc
        self._geoip = geoip
        self._assets = assets
        self._identities = identities

    @property
    def active(self) -> bool:
        """Whether any enrichment source is configured (else enrich is a no-op)."""
        return any(bool(s) for s in (self._ioc, self._geoip, self._assets, self._identities))

    @classmethod
    def from_config(cls, config) -> "Enricher":
        """Build an :class:`Enricher` from the ``enrichment:`` config section.

        Honors ``enabled: false`` (returns an inert enricher) and resolves the
        ``blocklist`` / ``geoip`` / ``assets`` paths. Missing files degrade to empty
        sources, so enrichment never breaks a run.
        """
        section = config.enrichment or {}
        if not section.get("enabled", True):
            return cls()
        ioc = IOCFeed.from_file(section["blocklist"]) if section.get("blocklist") else None
        geoip = GeoIP.from_csv(section["geoip"]) if section.get("geoip") else None
        assets = identities = None
        if section.get("assets"):
            assets, identities = load_assets(section["assets"])
        return cls(ioc=ioc, geoip=geoip, assets=assets, identities=identities)

    def enrich(self, events: list[Event]) -> list[Event]:
        """Annotate each event in place and return the same list."""
        if not self.active:
            return events
        for event in events:
            self._enrich_event(event)
        return events

    def _enrich_event(self, event: Event) -> None:
        ip = event.source_ip
        if self._ioc and self._ioc.match(ip):
            event.extra["threat.matched"] = True
            event.extra["threat.feed"] = self._ioc.name
        if self._geoip:
            geo = self._geoip.lookup(ip)
            if geo is not None:
                event.extra["source.geo.country_iso_code"] = geo.country_iso
                event.extra["source.geo.country_name"] = geo.country_name
                if geo.asn is not None:
                    event.extra["source.as.number"] = geo.asn
                if geo.as_org:
                    event.extra["source.as.organization"] = geo.as_org
        if self._assets and ip:
            asset = self._assets.lookup(ip)
            if asset is not None:
                event.extra["source.asset.name"] = asset.hostname
                event.extra["source.asset.trusted"] = asset.trusted
            else:
                # An IP that matches no known asset is, by definition, untrusted.
                event.extra["source.asset.trusted"] = False
        if self._identities:
            role = self._identities.role(event.user_name)
            if role is not None:
                event.extra["user.role"] = role

    def enrich_alert(self, alert) -> None:
        """Fold a compact enrichment summary onto an alert (for display).

        Reads the already-annotated evidence events and sets :attr:`Alert.enrichment`
        to the most relevant facts: the triggering IP's threat/geo/asset status and the
        account's role. Only present facts are included.
        """
        event = next((e for e in alert.events if e.source_ip), alert.events[0] if alert.events else None)
        if event is None:
            return
        summary: dict[str, object] = {}
        if event.extra.get("threat.matched"):
            summary["ioc"] = event.extra.get("threat.feed", True)
        if event.extra.get("source.geo.country_iso_code"):
            summary["country"] = event.extra["source.geo.country_iso_code"]
        if event.extra.get("source.as.organization"):
            summary["as_org"] = event.extra["source.as.organization"]
        if "source.asset.trusted" in event.extra:
            summary["trusted"] = event.extra["source.asset.trusted"]
        if event.extra.get("source.asset.name"):
            summary["asset"] = event.extra["source.asset.name"]
        if event.extra.get("user.role"):
            summary["role"] = event.extra["user.role"]
        if summary:
            alert.enrichment = summary
