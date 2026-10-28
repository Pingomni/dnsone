"""DNS name and record validation.

Everything that reaches a zone file passes through here first, and the rules match what
`named-checkzone -k fail` enforces, so an operator sees a field error instead of a failed publish.
named-checkzone still validates every file before it goes live.

Conventions:
- Zone names: lower-case A-labels without the trailing dot ("example.com").
- Owner names: relative to the zone ("@", "www", "_dmarc", "*.dev").
- Target names in RDATA: absolute with the trailing dot ("mail.example.com."). On input, "@" is the
  apex, a single label without a dot is relative to the zone ("mail"), and anything with a dot is
  absolute ("mail.example.net" or "mail.example.net.").
"""

from __future__ import annotations

import ipaddress
import re

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import idna

MIN_TTL = 60
MAX_TTL = 604800
MAX_TXT = 4000

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "PTR", "DS", "TLSA", "SSHFP", "NAPTR", "HTTPS", "SVCB", "ALIAS")
PRIORITY_TYPES = ("MX", "SRV")

SOA_BOUNDS = {
    "soa_refresh": (300, 86400),
    "soa_retry": (60, 86400),
    "soa_expire": (86400, 2419200),
    "soa_minimum": (60, 86400),
}

_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CAA_TAG = re.compile(r"^[a-z0-9]{1,15}$")


class ValidationError(ValueError):
    """A field-level problem; `field` names the input the operator has to fix."""

    def __init__(self, field: str, message: str):
        super().__init__(message)
        self.field = field
        self.message = message


def _to_ascii(name: str, field: str) -> str:
    """Lower-cases and converts internationalised labels to punycode (UTS #46)."""
    name = name.strip()
    if not name:
        raise ValidationError(field, "Enter a name.")
    if name.isascii():
        return name.lower()
    try:
        return idna.encode(name, uts46=True, transitional=False).decode("ascii")
    except idna.IDNAError as exc:
        raise ValidationError(field, f"{name!r} is not a valid internationalised name ({exc}).") from None


def _check_labels(labels: list[str], field: str, hostname: bool, allow_wildcard: bool) -> None:
    for i, label in enumerate(labels):
        if label == "*" and allow_wildcard and i == 0:
            continue
        if not label:
            raise ValidationError(field, "Names cannot contain empty labels (two dots in a row).")
        if len(label) > 63:
            raise ValidationError(field, f"The label {label[:20]}… is longer than 63 characters.")
        pattern = _HOST_LABEL if hostname else _LABEL
        if not pattern.match(label):
            if hostname:
                raise ValidationError(field, f"{label!r} is not a valid host name label: use letters, digits and hyphens, not at the start or end.")
            raise ValidationError(field, f"{label!r} is not a valid label: use letters, digits, hyphens and underscores.")


def zone_name(raw: str, field: str = "name") -> str:
    """A zone apex such as example.com or 2.0.192.in-addr.arpa."""
    name = _to_ascii(raw, field).rstrip(".")
    if len(name) > 253:
        raise ValidationError(field, "Zone names are at most 253 characters.")
    labels = name.split(".")
    if len(labels) < 2:
        raise ValidationError(field, "Enter a full domain such as example.com, not a single label.")
    _check_labels(labels, field, hostname=False, allow_wildcard=False)
    return name


def absolute_name(raw: str, zone: str, field: str, hostname: bool = True) -> str:
    """A target name in RDATA, returned absolute with the trailing dot."""
    value = raw.strip()
    if value == "@":
        return f"{zone}."
    value = _to_ascii(value, field)
    if value.endswith("."):
        fqdn = value[:-1]
    elif "." in value:
        fqdn = value
    else:
        fqdn = f"{value}.{zone}"
    if len(fqdn) > 253:
        raise ValidationError(field, "Names are at most 253 characters.")
    _check_labels(fqdn.split("."), field, hostname=hostname, allow_wildcard=False)
    if len(fqdn.split(".")) < 2:
        raise ValidationError(field, "Enter a full host name such as mail.example.com.")
    return f"{fqdn}."


def owner_name(raw: str, zone: str, field: str = "name") -> str:
    """An owner name, returned relative to the zone ("@" for the apex)."""
    value = raw.strip()
    if value in ("", "@"):
        return "@"
    value = _to_ascii(value, field)
    if value.endswith("."):
        fqdn = value[:-1]
        if fqdn == zone:
            return "@"
        if not fqdn.endswith(f".{zone}"):
            raise ValidationError(field, f"{fqdn} is outside the zone {zone}.")
        value = fqdn[: -(len(zone) + 1)]
    elif value == zone:
        return "@"
    elif value.endswith(f".{zone}"):
        # Pasted as a full name without the dot: treat it as absolute, as people mean.
        value = value[: -(len(zone) + 1)]
    if len(value) + 1 + len(zone) > 253:
        raise ValidationError(field, "The full name would be longer than 253 characters.")
    _check_labels(value.split("."), field, hostname=False, allow_wildcard=True)
    return value


def _host_owner(name: str, field: str = "name") -> None:
    """Owners of A, AAAA and MX records must be host names (BIND check-names)."""
    if name == "@":
        return
    _check_labels(name.split("."), field, hostname=True, allow_wildcard=True)


def ttl(value: int | None, field: str = "ttl", allow_none: bool = True) -> int | None:
    if value is None:
        if allow_none:
            return None
        raise ValidationError(field, "Enter a TTL.")
    if not MIN_TTL <= int(value) <= MAX_TTL:
        raise ValidationError(field, f"TTL must be between {MIN_TTL} and {MAX_TTL} seconds.")
    return int(value)


def mailbox(raw: str, zone: str, field: str = "soa_rname") -> str:
    """SOA RNAME: accepts hostmaster@example.com or hostmaster.example.com, returns the DNS form."""
    value = raw.strip()
    if "@" in value and value != "@":
        local, _, domain = value.partition("@")
        if not local or not domain:
            raise ValidationError(field, "Enter an email address such as hostmaster@example.com.")
        if not re.fullmatch(r"[A-Za-z0-9_+-]+", local):
            raise ValidationError(field, "Use only letters, digits, '_', '+' and '-' before the @ (no dots).")
        domain_fqdn = absolute_name(domain, zone, field, hostname=True)
        return f"{local.lower()}.{domain_fqdn}"
    return absolute_name(value, zone, field, hostname=False)


def _txt(raw: str) -> str:
    value = raw.strip()
    # One fully quoted string: drop the quotes people copy from other panels.
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"' and '"' not in value[1:-1].replace('\\"', ""):
        value = value[1:-1].replace('\\"', '"')
    if not value:
        raise ValidationError("value", "Enter the TXT text.")
    if len(value.encode("utf-8")) > MAX_TXT:
        raise ValidationError("value", f"TXT text is at most {MAX_TXT} bytes.")
    if any(ord(c) < 32 and c != "\t" for c in value):
        raise ValidationError("value", "TXT text cannot contain line breaks or control characters.")
    return value


def _caa(raw: str) -> str:
    match = re.fullmatch(r'\s*(\d{1,3})\s+([A-Za-z0-9]+)\s+(?:"([^"]*)"|(\S+))\s*', raw)
    if not match:
        raise ValidationError("value", 'Use: flags tag "value", for example 0 issue "letsencrypt.org".')
    flags, tag, quoted, bare = match.groups()
    if int(flags) > 255:
        raise ValidationError("value", "CAA flags must be 0–255 (usually 0, or 128 for critical).")
    tag = tag.lower()
    if not _CAA_TAG.match(tag):
        raise ValidationError("value", "The CAA tag is 1–15 letters or digits (issue, issuewild, iodef).")
    content = quoted if quoted is not None else bare
    if any(ord(c) < 32 or ord(c) > 126 for c in content):
        raise ValidationError("value", "The CAA value must be printable ASCII.")
    return f'{int(flags)} {tag} "{content}"'


# Digest lengths in bytes by algorithm number, so a truncated paste is caught before a publish.
_DS_DIGESTS = {1: 20, 2: 32, 4: 48}
_TLSA_DIGESTS = {1: 32, 2: 64}
_SSHFP_DIGESTS = {1: 20, 2: 32}

_FORMATS = {
    "DS": "key-tag algorithm digest-type digest, for example 12345 13 2 1F3C…",
    "TLSA": "usage selector matching-type data, for example 3 1 1 0C72AC70…",
    "SSHFP": "algorithm fingerprint-type fingerprint, for example 4 2 123456789ABC…",
    "NAPTR": 'order preference "flags" "service" "regexp" replacement, for example 100 10 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .',
    "HTTPS": "priority target [parameters], for example 1 . alpn=h2,h3",
    "SVCB": "priority target [parameters], for example 1 svc.example.net alpn=h2",
}


def _parsed(zone: str, rtype: str, value: str) -> dns.rdata.Rdata:
    try:
        return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rtype), value, origin=None)
    except (dns.exception.DNSException, ValueError) as exc:
        reason = str(exc).rstrip(".") or exc.__class__.__name__
        raise ValidationError("value", f"Not a valid {rtype} record ({reason}). Use: {_FORMATS[rtype]}") from None


def _target(rd: dns.rdata.Rdata, zone: str, hostname: bool) -> dns.name.Name:
    """A target name from parsed RDATA, made absolute with DNSOne's rule (a dot means absolute)."""
    name = rd.target if hasattr(rd, "target") else rd.replacement
    if name == dns.name.root:
        return name
    text = name.to_text(omit_final_dot=True) + ("." if name.is_absolute() else "")
    return dns.name.from_text(absolute_name(text, zone, "value", hostname=hostname))


def _structured(zone: str, owner: str, rtype: str, value: str) -> str:
    """DS, TLSA, SSHFP, NAPTR, HTTPS and SVCB, parsed by dnspython and written back in canonical form."""
    rd = _parsed(zone, rtype, value)
    if rtype == "DS":
        if owner == "@":
            raise ValidationError("name", "A DS record belongs at a delegated child zone (e.g. customer), not at this zone's apex: give the DS records of this zone to its parent's registrar.")
        want = _DS_DIGESTS.get(rd.digest_type)
        if want and len(rd.digest) != want:
            raise ValidationError("value", f"A digest of type {rd.digest_type} is {want * 2} hex characters; this one has {len(rd.digest) * 2}.")
    elif rtype == "TLSA":
        labels = owner.split(".")
        if len(labels) < 2 or not re.fullmatch(r"_\d{1,5}", labels[0]) or labels[1] not in ("_tcp", "_udp", "_sctp"):
            raise ValidationError("name", "TLSA names start with _port._protocol, for example _443._tcp.www or _25._tcp.mail.")
        if rd.usage > 3 or rd.selector > 1 or rd.mtype > 2:
            raise ValidationError("value", "TLSA usage is 0–3, selector 0–1 and matching type 0–2.")
        want = _TLSA_DIGESTS.get(rd.mtype)
        if want and len(rd.cert) != want:
            raise ValidationError("value", f"Matching type {rd.mtype} is a {want * 8}-bit hash: {want * 2} hex characters.")
    elif rtype == "SSHFP":
        _host_owner(owner)
        want = _SSHFP_DIGESTS.get(rd.fp_type)
        if want and len(rd.fingerprint) != want:
            raise ValidationError("value", f"Fingerprint type {rd.fp_type} is {want * 2} hex characters; this one has {len(rd.fingerprint) * 2}.")
    elif rtype == "NAPTR":
        if rd.flags and not re.fullmatch(rb"[A-Za-z0-9]*", rd.flags):
            raise ValidationError("value", "NAPTR flags are letters and digits, for example \"u\" or \"s\".")
        if rd.regexp and rd.replacement != dns.name.root:
            raise ValidationError("value", 'A NAPTR record has either a regexp or a replacement: use "" or . for the other.')
        rd = rd.replace(replacement=_target(rd, zone, hostname=False))
    elif rtype in ("HTTPS", "SVCB"):
        rd = rd.replace(target=_target(rd, zone, hostname=False))
    return rd.to_text()


def record(zone: str, name: str, rtype: str, value: str, priority: int | None) -> tuple[str, str, str, int | None]:
    """Validates and normalises one record. Returns (name, type, value, priority)."""
    rtype = rtype.strip().upper()
    if rtype not in RECORD_TYPES:
        raise ValidationError("type", f"Choose one of: {', '.join(RECORD_TYPES)}.")
    owner = owner_name(name, zone)
    value = (value or "").strip()
    if not value and rtype != "TXT":
        raise ValidationError("value", "Enter a value.")

    if rtype in PRIORITY_TYPES:
        if priority is None:
            raise ValidationError("priority", f"{rtype} records need a priority (0–65535).")
        if not 0 <= int(priority) <= 65535:
            raise ValidationError("priority", "Priority must be between 0 and 65535.")
        priority = int(priority)
    else:
        priority = None

    if rtype == "A":
        _host_owner(owner)
        try:
            value = str(ipaddress.IPv4Address(value))
        except ValueError:
            raise ValidationError("value", "Enter an IPv4 address such as 192.0.2.10.") from None
    elif rtype == "AAAA":
        _host_owner(owner)
        try:
            value = ipaddress.IPv6Address(value).compressed
        except ValueError:
            raise ValidationError("value", "Enter an IPv6 address such as 2001:db8::10.") from None
    elif rtype == "ALIAS":
        # Published as the target's A/AAAA records (zonegen), so it may sit at the apex.
        value = absolute_name(value, zone, "value", hostname=False)
        if value == (f"{zone}." if owner == "@" else f"{owner}.{zone}."):
            raise ValidationError("value", "An ALIAS cannot point to itself.")
    elif rtype == "CNAME":
        if owner == "@":
            raise ValidationError("type", "A CNAME cannot be at the zone apex: it would hide the SOA and NS records. Use A/AAAA records instead.")
        value = absolute_name(value, zone, "value", hostname=False)
        if value == f"{owner}.{zone}.":
            raise ValidationError("value", "A CNAME cannot point to itself.")
    elif rtype == "MX":
        _host_owner(owner)
        value = "." if value == "." else absolute_name(value, zone, "value", hostname=True)
        if value == "." and priority != 0:
            raise ValidationError("priority", 'A null MX (".") must have priority 0.')
    elif rtype == "NS":
        if owner.startswith("*"):
            raise ValidationError("name", "NS records cannot be wildcards.")
        value = absolute_name(value, zone, "value", hostname=True)
    elif rtype == "PTR":
        value = absolute_name(value, zone, "value", hostname=False)
    elif rtype == "TXT":
        value = _txt(value)
    elif rtype == "SRV":
        labels = owner.split(".")
        if len(labels) < 2 or not labels[0].startswith("_") or not labels[1].startswith("_"):
            raise ValidationError("name", "SRV names start with _service._protocol, for example _sip._tcp.")
        parts = value.split()
        if len(parts) != 3:
            raise ValidationError("value", "Use: weight port target, for example 5 5060 sip.example.com.")
        weight, port, target = parts
        if not (weight.isdigit() and 0 <= int(weight) <= 65535):
            raise ValidationError("value", "SRV weight must be 0–65535.")
        if not (port.isdigit() and 0 <= int(port) <= 65535):
            raise ValidationError("value", "SRV port must be 0–65535.")
        target = "." if target == "." else absolute_name(target, zone, "value", hostname=True)
        value = f"{int(weight)} {int(port)} {target}"
    elif rtype == "CAA":
        value = _caa(value)
    else:
        value = _structured(zone, owner, rtype, value)

    return owner, rtype, value, priority


def conflict(name: str, rtype: str, others: set[str]) -> str | None:
    """Why a record of `rtype` cannot join the enabled records of `others` types at `name`, or None.

    A CNAME stands alone at its name. An ALIAS is published as A/AAAA records, so it cannot share
    its name with a CNAME, A or AAAA record, or another ALIAS.
    """
    if rtype == "CNAME" and others:
        return f"{name} already has {', '.join(sorted(others))} records; a CNAME must be the only record at its name."
    if rtype != "CNAME" and "CNAME" in others:
        return f"{name} has a CNAME; no other records can share its name."
    if rtype == "ALIAS" and others & {"A", "AAAA", "ALIAS"}:
        return f"{name} already has {', '.join(sorted(others & {'A', 'AAAA', 'ALIAS'}))} records; an ALIAS publishes the target's addresses there itself."
    if rtype in ("A", "AAAA") and "ALIAS" in others:
        return f"{name} has an ALIAS, which publishes its addresses; remove the ALIAS to set them by hand."
    return None


def rpz_pattern(raw: str, field: str = "pattern") -> str:
    """'example.com' or '*.example.com', lower-case A-labels without the trailing dot."""
    value = raw.strip().rstrip(".")
    wildcard = value.startswith("*.")
    base = value[2:] if wildcard else value
    base = _to_ascii(base, field)
    if len(base) > 240:
        raise ValidationError(field, "Domain is too long.")
    labels = base.split(".")
    if len(labels) < 2 and not wildcard:
        raise ValidationError(field, "Enter a domain such as ads.example.com, or *.example.com for everything below it.")
    _check_labels(labels, field, hostname=False, allow_wildcard=False)
    return f"*.{base}" if wildcard else base


def walled_garden_target(raw: str, field: str = "walled_garden_target") -> str:
    """A host name (answered with a CNAME) or an IPv4/IPv6 address (answered with A/AAAA)."""
    value = raw.strip().rstrip(".")
    if not value:
        raise ValidationError(field, "Enter the host name or IP address of the block page.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    name = _to_ascii(value, field)
    labels = name.split(".")
    if len(labels) < 2:
        raise ValidationError(field, "Enter a full host name or an IP address.")
    _check_labels(labels, field, hostname=True, allow_wildcard=False)
    return name


# Python-only syntax: dnsdist matches with POSIX extended regular expressions, the query log with
# Python's re, so a rule may only use what both read the same way.
# A group containing *, + or {n,} that is itself repeated: catastrophic backtracking in Python's re.
_NESTED_REPETITION = re.compile(r"\((?:[^()\\]|\\.)*(?:[*+]|\{\d*,\d*\})(?:[^()\\]|\\.)*\)(?:[*+]|\{\d*,\d*\})")
_REGEX_UNSUPPORTED = re.compile(r"\\[dDwWsSbBAZzGQE0-9]|\(\?|[*+?}]\?|\\[pPNx]")


def regex_pattern(raw: str, field: str = "pattern") -> str:
    """A POSIX extended regular expression matched against the query name (no trailing dot)."""
    value = raw.strip()
    if not value:
        raise ValidationError(field, "Enter a regular expression, e.g. ^ads?[0-9]*\\. or (^|\\.)doubleclick\\.net$")
    if len(value) > 253:
        raise ValidationError(field, "Keep the expression under 254 characters.")
    if not value.isascii() or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ValidationError(field, "Use plain ASCII characters only.")
    if _NESTED_REPETITION.search(value):
        raise ValidationError(field, "Repetition inside a repeated group, such as ([a-z]+)+, is not allowed: it can take very long to match.")
    if _REGEX_UNSUPPORTED.search(value):
        raise ValidationError(field, "Use POSIX syntax: [0-9] instead of \\d, [a-z0-9_] instead of \\w; no (?…) groups, lazy quantifiers or back-references.")
    try:
        compiled = re.compile(value, re.IGNORECASE)
    except re.error as exc:
        raise ValidationError(field, f"Not a valid regular expression: {exc}.") from None
    if compiled.search("") is not None and compiled.search("x.invalid") is not None and compiled.search("a.b.c.example") is not None:
        raise ValidationError(field, "This expression matches every name; it would block everything.")
    return value


def network(raw: str, field: str = "network") -> str:
    """An address or subnet in canonical CIDR form; a single address becomes /32 or /128."""
    value = raw.strip()
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValidationError(field, f"{value or 'This'} is not an IP address or subnet (e.g. 192.0.2.0/24 or 2001:db8::/48).") from None
    return str(net)


USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


def username(raw: str) -> str:
    value = raw.strip().lower()
    if not USERNAME.match(value):
        raise ValidationError("username", "2–64 characters: lower-case letters, digits, '.', '_' and '-'.")
    return value


def password(raw: str, field: str = "password") -> str:
    if len(raw) < 12:
        raise ValidationError(field, "Use at least 12 characters.")
    if len(raw) > 256:
        raise ValidationError(field, "Use at most 256 characters.")
    return raw


def email(raw: str) -> str:
    value = raw.strip()
    if value and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        raise ValidationError("email", "Enter a valid email address, or leave it empty.")
    return value[:254]
