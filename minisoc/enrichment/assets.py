"""Asset & identity context: who/what is behind an IP or username.

Two small directories loaded from ``assets.yaml``:

* :class:`AssetInventory` maps an IP (via CIDR) to a known :class:`Asset` — a hostname
  and a ``trusted`` flag. A source that matches nothing is, by definition, untrusted.
* :class:`IdentityDirectory` maps a username to a role (``admin``/``developer``/…), so a
  privileged account standing out in an alert is obvious.

Together they turn "172.19.0.1 / victim" into "soc-lab-net / a standard account", or flag
"admin login from an untrusted asset".
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

__all__ = ["Asset", "AssetInventory", "IdentityDirectory"]

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Asset:
    """A known asset.

    Attributes:
        hostname: The asset's name.
        trusted: Whether it is owned/managed infrastructure.
    """

    hostname: str
    trusted: bool = True


class AssetInventory:
    """Resolves an IP to a known :class:`Asset` via CIDR membership.

    Args:
        table: ``(network, Asset)`` rows; the longest-prefix match wins.
    """

    def __init__(self, table: list[tuple[_Network, Asset]]) -> None:
        self._table = sorted(table, key=lambda row: row[0].prefixlen, reverse=True)

    def __bool__(self) -> bool:
        return bool(self._table)

    def lookup(self, ip: str | None) -> Asset | None:
        """Return the :class:`Asset` for ``ip``, or ``None`` if unknown (untrusted)."""
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for network, asset in self._table:
            if addr in network:
                return asset
        return None


class IdentityDirectory:
    """Maps usernames to roles.

    Args:
        roles: ``username -> role`` mapping (case-insensitive lookup).
    """

    def __init__(self, roles: dict[str, str]) -> None:
        self._roles = {k.lower(): v for k, v in roles.items()}

    def __bool__(self) -> bool:
        return bool(self._roles)

    def role(self, user: str | None) -> str | None:
        """Return the role for ``user``, or ``None`` if unlisted."""
        if not user:
            return None
        return self._roles.get(user.lower())


def load_assets(path: str | Path) -> tuple[AssetInventory, IdentityDirectory]:
    """Load ``assets.yaml`` into an :class:`AssetInventory` + :class:`IdentityDirectory`.

    A missing or malformed file yields empty directories rather than raising, so
    enrichment degrades gracefully when asset context is not configured.
    """
    path = Path(path)
    data: dict[str, Any] = {}
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    table: list[tuple[_Network, Asset]] = []
    for entry in data.get("hosts") or []:
        try:
            network = ipaddress.ip_network(str(entry["cidr"]), strict=False)
        except (ValueError, KeyError, TypeError):
            continue
        table.append(
            (network, Asset(hostname=str(entry.get("hostname", "")), trusted=bool(entry.get("trusted", True))))
        )

    roles = {str(k): str(v) for k, v in (data.get("identities") or {}).items()}
    return AssetInventory(table), IdentityDirectory(roles)
