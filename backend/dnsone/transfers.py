"""Zone transfers to customers' own secondaries (Zone → Transfers).

A zone lists the addresses (or networks) allowed to transfer it, and optionally a TSIG key. Customers'
secondaries transfer through dnsdist on port 53, like any other query, so nothing else has to be opened:

  dnsdist   lets AXFR/IXFR of a zone through to BIND only from the zone's addresses, and refuses every
            other transfer (runtime.py writes the list into dnsdist's settings file);
  BIND      with a key, transfers the zone only to requests signed with it: dnsdist forwards from
            127.0.0.1, so the address check is dnsdist's and the key check is BIND's (zonegen.py writes
            the key and the zone's allow-transfer into zones.conf), and notifies the single addresses
            marked for it when the zone changes (also-notify, signed with the key when there is one).

Transfers go through the primary only: a replica's dnsdist refuses them.
"""

from __future__ import annotations

import ipaddress

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import ddns, validation
from .models import Zone, ZoneTransfer

MAX_PER_ZONE = 20
ALGORITHMS = ("hmac-sha256", "hmac-sha512", "hmac-sha384", "hmac-sha224", "hmac-sha1")


def clean_address(raw: str, field: str = "address") -> str:
    """An address ('192.0.2.53') or a network ('192.0.2.0/28'); a whole address family is refused."""
    net = ipaddress.ip_network(validation.network(raw, field))
    if net.prefixlen == 0:
        raise validation.ValidationError(field, "List the secondaries' addresses; everyone may not transfer a zone.")
    if net.num_addresses == 1:
        return str(net.network_address)
    return str(net)


def is_single(address: str) -> bool:
    return "/" not in address


def key_name(zone: str) -> str:
    """The zone's transfer key name, unique on the server (BIND's key names are global)."""
    return f"transfer.{zone}."


def set_key(zone: Zone, enabled: bool, algorithm: str = "hmac-sha256", secret: str = "") -> bool:
    """Turns the zone's transfer key on (a new or given secret) or off. Returns True if it changed."""
    if not enabled:
        changed = zone.xfr_key_name is not None
        zone.xfr_key_name = zone.xfr_key_algorithm = zone.xfr_key_secret = None
        return changed
    if algorithm not in ALGORITHMS:
        raise validation.ValidationError("algorithm", f"Choose one of {', '.join(ALGORITHMS)}.")
    zone.xfr_key_name = key_name(zone.name)
    zone.xfr_key_algorithm = algorithm
    zone.xfr_key_secret = ddns.clean_secret(secret) if secret.strip() else ddns.new_secret()
    return True


def entries(db: Session, zone_id: int) -> list[ZoneTransfer]:
    return list(db.scalars(select(ZoneTransfer).where(ZoneTransfer.zone_id == zone_id).order_by(ZoneTransfer.id)))


def server_view(db: Session, names: list[str]) -> dict[str, dict]:
    """What zones.conf and dnsdist need for the served zones that allow transfers or have a key:
    {zone: {"key": (name, algorithm, secret) or None, "notify": [(address, port)], "networks": [...]}}."""
    if not names:
        return {}
    out: dict[str, dict] = {}
    for zone in db.scalars(select(Zone).where(Zone.name.in_(names), Zone.xfr_key_name.is_not(None))):
        out[zone.name] = {"key": (zone.xfr_key_name, zone.xfr_key_algorithm, zone.xfr_key_secret), "notify": [], "networks": []}
    rows = db.execute(select(Zone.name, Zone.xfr_key_name, Zone.xfr_key_algorithm, Zone.xfr_key_secret, ZoneTransfer.address,
                             ZoneTransfer.notify, ZoneTransfer.notify_port)
                      .join(ZoneTransfer, ZoneTransfer.zone_id == Zone.id).where(Zone.name.in_(names)).order_by(Zone.name, ZoneTransfer.id))
    for name, kname, kalg, ksecret, address, notify, port in rows:
        entry = out.setdefault(name, {"key": (kname, kalg, ksecret) if kname else None, "notify": [], "networks": []})
        entry["networks"].append(address if "/" in address else f"{address}/{128 if ':' in address else 32}")
        if notify and is_single(address):
            entry["notify"].append((address, int(port)))
    return out
