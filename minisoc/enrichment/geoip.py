"""Offline GeoIP / ASN lookup from a CIDR table.

No external service and no binary database: :class:`GeoIP` reads a small CSV of
``cidr,country_iso,country_name,asn,as_org`` rows and resolves an IP to the
longest-prefix match. Private / reserved addresses resolve to ``None`` (the enricher
treats those as LAN and adds no geo). This is enough to power the impossible-travel
detection and to label "a login from Russia" on an alert; swap in a real MaxMind /
IPinfo export in the same five-column shape for production-grade accuracy.
"""

from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass
from pathlib import Path

__all__ = ["GeoRecord", "GeoIP"]

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class GeoRecord:
    """Geo/ASN facts for an IP range.

    Attributes:
        country_iso: ISO 3166-1 alpha-2 code (e.g. ``"RU"``).
        country_name: Human-readable country name.
        asn: Autonomous System number, or ``None`` if unknown.
        as_org: Autonomous System organization name, or ``None``.
    """

    country_iso: str
    country_name: str
    asn: int | None = None
    as_org: str | None = None


class GeoIP:
    """Resolves IPs to :class:`GeoRecord` via a list of ``(network, record)`` rows.

    Args:
        table: ``(network, GeoRecord)`` pairs. :meth:`lookup` returns the record of the
            most specific (longest-prefix) matching network.
    """

    def __init__(self, table: list[tuple[_Network, GeoRecord]]) -> None:
        # Longest prefix first so the first containing match is the most specific.
        self._table = sorted(table, key=lambda row: row[0].prefixlen, reverse=True)

    def __bool__(self) -> bool:
        return bool(self._table)

    @classmethod
    def from_csv(cls, path: str | Path) -> "GeoIP":
        """Load a ``cidr,country_iso,country_name,asn,as_org`` CSV (missing file -> empty).

        Comment lines (starting ``#``) and a leading ``cidr,...`` header row are skipped.
        Malformed rows are ignored rather than raised.
        """
        path = Path(path)
        if not path.exists():
            return cls([])
        table: list[tuple[_Network, GeoRecord]] = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            row = next(csv.reader([raw]))
            if not row or row[0].strip().lower() == "cidr":
                continue
            try:
                network = ipaddress.ip_network(row[0].strip(), strict=False)
                asn = int(row[3]) if len(row) > 3 and row[3].strip() else None
            except ValueError:
                continue  # malformed CIDR or non-numeric ASN -> skip the row, don't crash
            org = row[4].strip() if len(row) > 4 and row[4].strip() else None
            table.append(
                (
                    network,
                    GeoRecord(
                        country_iso=row[1].strip() if len(row) > 1 else "",
                        country_name=row[2].strip() if len(row) > 2 else "",
                        asn=asn,
                        as_org=org,
                    ),
                )
            )
        return cls(table)

    def lookup(self, ip: str | None) -> GeoRecord | None:
        """Return the :class:`GeoRecord` for ``ip``, or ``None`` if private/unknown."""
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
            return None
        for network, record in self._table:
            if addr in network:
                return record
        return None
