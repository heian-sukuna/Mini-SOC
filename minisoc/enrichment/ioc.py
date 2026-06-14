"""Threat-intel IOC matching: is this IP on a known-bad list?

A :class:`IOCFeed` holds a set of IP networks (bare IPs become /32 or /128) loaded from a
simple text blocklist. :meth:`IOCFeed.match` answers whether a source IP falls inside any
of them. This is the cheapest, highest-signal enrichment there is — an alert that says
"and this IP is on a known-bad list" is far more credible than a bare count.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

__all__ = ["IOCFeed"]

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class IOCFeed:
    """A set of blocklisted IP networks with a membership test.

    Args:
        networks: The blocklisted networks (bare IPs are stored as host networks).
        name: A label for the feed, surfaced on matches (e.g. ``"local-blocklist"``).
    """

    def __init__(self, networks: list[_Network], *, name: str = "local-blocklist") -> None:
        self._networks = list(networks)
        self.name = name

    def __bool__(self) -> bool:
        """A feed with no indicators is falsy (so the enricher can skip it)."""
        return bool(self._networks)

    @classmethod
    def from_file(cls, path: str | Path, *, name: str = "local-blocklist") -> "IOCFeed":
        """Load a blocklist file: one IP or CIDR per line, ``#`` comments allowed.

        A missing file yields an empty feed rather than raising — a deployment that has
        not configured threat intel should still run.
        """
        path = Path(path)
        if not path.exists():
            return cls([], name=name)
        networks: list[_Network] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                continue  # skip malformed indicators rather than crash the load
        return cls(networks, name=name)

    def match(self, ip: str | None) -> bool:
        """Return whether ``ip`` falls inside any blocklisted network."""
        if not ip or not self._networks:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._networks)
