"""Decoder for PowerDNS protobuf messages (dnsmessage.proto), the Recursor's query log stream.

Only the fields DNSOne uses are decoded; the wire format is parsed directly (varint, length-
delimited, fixed32/64) so no generated code or protobuf runtime is needed. Field numbers follow
https://github.com/PowerDNS/dnsmessage/blob/master/dnsmessage.proto.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

RESPONSE_TYPE = 2  # PBDNSMessage.Type.DNSResponseType

# PBDNSMessage.PolicyKind
POLICY_KINDS = {1: "noaction", 2: "drop", 3: "nxdomain", 4: "nodata", 5: "truncate", 6: "custom"}


class DecodeError(ValueError):
    pass


def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(buf):
            raise DecodeError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise DecodeError("varint too long")


def fields(buf: bytes):
    """Yields (field number, wire type, value) for one message; value is int or bytes."""
    pos = 0
    while pos < len(buf):
        key, pos = _varint(buf, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _varint(buf, pos)
        elif wire == 1:
            value, pos = int.from_bytes(buf[pos:pos + 8], "little"), pos + 8
        elif wire == 2:
            length, pos = _varint(buf, pos)
            value, pos = buf[pos:pos + length], pos + length
        elif wire == 5:
            value, pos = int.from_bytes(buf[pos:pos + 4], "little"), pos + 4
        else:
            raise DecodeError(f"unsupported wire type {wire}")
        if pos > len(buf):
            raise DecodeError("truncated field")
        yield number, wire, value


@dataclass
class Answer:
    """One answered query, as the Recursor saw it (after dnsdist's PROXY header)."""

    time: float
    client: str
    qname: str
    qtype: int
    rcode: int
    policy: str
    policy_kind: str
    latency_ms: float | None


def decode(buf: bytes) -> Answer | None:
    """The answer in one message, or None for messages that are not responses."""
    msg_type = 0
    client = ""
    time_sec = time_usec = 0
    qname, qtype = "", 0
    rcode = 0
    policy = policy_kind = ""
    q_sec = q_usec = None
    for number, _, value in fields(buf):
        if number == 1:
            msg_type = value
        elif number == 6 and isinstance(value, bytes) and len(value) in (4, 16):
            client = str(ipaddress.ip_address(value))
        elif number == 9:
            time_sec = value
        elif number == 10:
            time_usec = value
        elif number == 12 and isinstance(value, bytes):
            for n, _, v in fields(value):
                if n == 1 and isinstance(v, bytes):
                    qname = v.decode("utf-8", "replace").rstrip(".").lower() or "."
                elif n == 2:
                    qtype = v
        elif number == 13 and isinstance(value, bytes):
            for n, _, v in fields(value):
                if n == 1:
                    rcode = v
                elif n == 3 and isinstance(v, bytes):
                    policy = v.decode("utf-8", "replace")
                elif n == 5:
                    q_sec = v
                elif n == 6:
                    q_usec = v
                elif n == 10:
                    policy_kind = POLICY_KINDS.get(v, "")
    if msg_type != RESPONSE_TYPE:
        return None
    t = time_sec + time_usec / 1e6
    latency = None
    if q_sec is not None:
        latency = max(0.0, (t - (q_sec + (q_usec or 0) / 1e6)) * 1000)
    return Answer(time=t, client=client, qname=qname, qtype=qtype, rcode=rcode, policy=policy, policy_kind=policy_kind, latency_ms=latency)
