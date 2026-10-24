"""Zone templates: the records a new zone starts with (or that are added to an existing one).

A template lists records like the zone editor does, relative to the zone ('@', 'www', 'mail'), and may
use variables in names and values: {zone} is the zone's name, and the template declares its own
({ip}, {mx}, ...) with a label and an optional default, asked for when it is used. It may also give
the name servers, the zone contact and the default TTL that the new-zone form starts with.

Records without variables are fully checked when the template is saved; the others when it is used,
with the values filled in, by the same validation as every record.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy.orm import Session

from . import validation
from .models import ZoneTemplate

VARIABLE = re.compile(r"\{([a-z][a-z0-9_]{0,31})\}")
NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
SAMPLE_ZONE = "example.com"
MAX_RECORDS = 500


@dataclass
class Rendered:
    name: str
    type: str
    value: str
    ttl: int | None
    priority: int | None
    comment: str

    def key(self) -> tuple:
        return (self.name, self.type, self.priority, self.value)


def _fill(text: str, zone: str, values: dict[str, str]) -> str:
    return VARIABLE.sub(lambda m: zone if m.group(1) == "zone" else values.get(m.group(1), m.group(0)), text)


def clean(data: dict) -> dict:
    """Validates a template as entered in the console; returns the fields to store."""
    variables, names = [], set()
    for i, v in enumerate(data.get("variables") or []):
        name = str(v.get("name") or "").strip().lower()
        if not NAME.match(name) or name == "zone":
            raise validation.ValidationError(f"variables.{i}.name", "Use a lower-case name such as ip or mail_host ('zone' is built in).")
        if name in names:
            raise validation.ValidationError(f"variables.{i}.name", f"{name} is listed twice.")
        names.add(name)
        variables.append({"name": name, "label": str(v.get("label") or name).strip()[:128], "default": str(v.get("default") or "").strip()[:253]})
    records = []
    raw_records = data.get("records") or []
    if len(raw_records) > MAX_RECORDS:
        raise validation.ValidationError("records", f"A template holds at most {MAX_RECORDS} records.")
    for i, r in enumerate(raw_records):
        name, value = str(r.get("name") or "@").strip(), str(r.get("value") or "").strip()
        rtype = str(r.get("type") or "").strip().upper()
        if rtype not in validation.RECORD_TYPES:
            raise validation.ValidationError(f"records.{i}.type", f"Choose one of: {', '.join(validation.RECORD_TYPES)}.")
        used = set(VARIABLE.findall(name + " " + value)) - {"zone"}
        unknown = used - names
        if unknown:
            raise validation.ValidationError(f"records.{i}.value", f"Declare the variable {', '.join(sorted(unknown))} first.")
        priority = r.get("priority")
        priority = int(priority) if priority not in (None, "") else None
        ttl = validation.ttl(int(r["ttl"]) if r.get("ttl") not in (None, "") else None, f"records.{i}.ttl")
        if not used:
            try:
                validation.record(SAMPLE_ZONE, _fill(name, SAMPLE_ZONE, {}), rtype, _fill(value, SAMPLE_ZONE, {}), priority)
            except validation.ValidationError as exc:
                raise validation.ValidationError(f"records.{i}.{exc.field}", f"Record {i + 1} ({name} {rtype}): {exc.message}") from None
        records.append({"name": name, "type": rtype, "value": value, "ttl": ttl, "priority": priority, "comment": str(r.get("comment") or "")[:255]})
    nameservers = []
    for i, ns in enumerate(data.get("nameservers") or []):
        ns = ns if isinstance(ns, dict) else {"host": ns}
        host = str(ns.get("host") or "").strip()
        if not host:
            continue
        if "{" not in host:
            validation.absolute_name(host, SAMPLE_ZONE, f"nameservers.{i}.host")
        address = str(ns.get("address") or "").strip()[:45]
        nameservers.append({"host": host[:253], "address": address or None})
    ttl = data.get("default_ttl")
    return {
        "name": str(data.get("name") or "").strip()[:64], "description": str(data.get("description") or "").strip()[:255],
        "default_ttl": validation.ttl(int(ttl), "default_ttl") if ttl not in (None, "") else None,
        "soa_rname": str(data.get("soa_rname") or "").strip()[:253], "nameservers": nameservers[:10], "variables": variables, "records": records,
    }


def values_for(template: ZoneTemplate, given: dict[str, str]) -> dict[str, str]:
    """Each declared variable's value: the one given, else its default; a missing one is an error."""
    out = {}
    for v in template.variables or []:
        value = str(given.get(v["name"]) or "").strip() or v.get("default") or ""
        if not value:
            raise validation.ValidationError(f"variables.{v['name']}", f"Enter {v.get('label') or v['name']}.")
        out[v["name"]] = value
    return out


def render(template: ZoneTemplate, zone: str, given: dict[str, str]) -> list[Rendered]:
    """The template's records for `zone`, validated and normalised."""
    values = values_for(template, given)
    out = []
    for i, r in enumerate(template.records or []):
        try:
            name, rtype, value, priority = validation.record(zone, _fill(r["name"], zone, values), r["type"], _fill(r["value"], zone, values), r.get("priority"))
        except validation.ValidationError as exc:
            used = VARIABLE.findall(r["name"] + " " + r["value"])
            field = f"variables.{used[0]}" if used and used[0] != "zone" else "template_id"
            raise validation.ValidationError(field, f"Template record {r['name']} {r['type']}: {exc.message}") from None
        out.append(Rendered(name, rtype, value, r.get("ttl"), priority, r.get("comment") or ""))
    return out


def fill_text(text: str, zone: str, values: dict[str, str]) -> str:
    return _fill(text, zone, values)


def out(t: ZoneTemplate) -> dict:
    from .security import iso
    return {"id": t.id, "name": t.name, "description": t.description, "default_ttl": t.default_ttl, "soa_rname": t.soa_rname,
            "nameservers": t.nameservers or [], "variables": t.variables or [], "records": t.records or [], "created_by": t.created_by,
            "updated_at": iso(t.updated_at)}


def get(db: Session, template_id: int) -> ZoneTemplate:
    template = db.get(ZoneTemplate, template_id)
    if template is None:
        raise validation.ValidationError("template_id", "This template no longer exists.")
    return template
