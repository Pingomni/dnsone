# SPDX-License-Identifier: Elastic-2.0
# DNSOne Pro (LICENSE-PRO): on with a licence key, Settings → License.
"""Query log export (Settings → Query log export): to a SIEM or log store, besides DNSOne's own log.

  syslog  dnsone-querylog sends every answer it classifies (or only blocked ones) as an RFC 5424
          message over UDP or TCP, as JSON or key=value text, with the same verdict (ok, blocked,
          allowed, legal) and the client's group. Privacy levels apply: hidden domains and clients
          stay hidden, and level 3 (totals only) exports nothing.
  dnstap  dnsdist streams every query and/or response in dnstap (Frame Streams over TCP or a Unix
          socket), the standard binary format collectors such as dnstap-receiver, Vector or
          go-dnscollector read. It carries the DNS messages only (no verdict, no group), and is not
          filtered by privacy level: it is for operators who need the raw stream.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import validation
from .models import Setting

log = logging.getLogger(__name__)

KEY = "querylog.export"
FACILITIES = {f"local{i}": 16 + i for i in range(8)}
SEVERITY_INFO = 6
SEVERITY_NOTICE = 5
QUEUE_LIMIT = 50_000
DEFAULT = {
    "syslog": {"enabled": False, "host": "", "port": 514, "protocol": "udp", "format": "json", "facility": "local5", "only": "all"},
    "dnstap": {"enabled": False, "target": "", "queries": True, "responses": True},
}


def get(db: Session) -> dict:
    row = db.get(Setting, KEY)
    value = dict(row.value) if row else {}
    return {section: {**DEFAULT[section], **(value.get(section) or {})} for section in DEFAULT}


def _host(raw: str, field: str) -> str:
    value = raw.strip()
    if not value:
        raise validation.ValidationError(field, "Enter the collector's address or host name.")
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return validation.walled_garden_target(value, field)


def store(db: Session, data: dict) -> dict:
    sl, tap = {**DEFAULT["syslog"], **(data.get("syslog") or {})}, {**DEFAULT["dnstap"], **(data.get("dnstap") or {})}
    out = {"syslog": dict(DEFAULT["syslog"]), "dnstap": dict(DEFAULT["dnstap"])}
    s = out["syslog"]
    s["enabled"] = bool(sl.get("enabled"))
    if s["enabled"] or sl.get("host"):
        s["host"] = _host(str(sl.get("host") or ""), "syslog.host")
    port = int(sl.get("port") or 514)
    if not 1 <= port <= 65535:
        raise validation.ValidationError("syslog.port", "Enter a port between 1 and 65535.")
    s["port"] = port
    for key, allowed in (("protocol", ("udp", "tcp")), ("format", ("json", "text")), ("facility", tuple(FACILITIES)), ("only", ("all", "blocked"))):
        value = str(sl.get(key) or DEFAULT["syslog"][key])
        if value not in allowed:
            raise validation.ValidationError(f"syslog.{key}", f"Choose one of: {', '.join(allowed)}.")
        s[key] = value
    t = out["dnstap"]
    t["enabled"] = bool(tap.get("enabled"))
    target = str(tap.get("target") or "").strip()
    if t["enabled"] or target:
        if target.startswith("/"):
            if any(c in target for c in "\"'\\\n") or len(target) > 200:
                raise validation.ValidationError("dnstap.target", "Enter a plain path to the collector's Unix socket.")
        else:
            host, _, port_text = target.rpartition(":")
            try:
                address = ipaddress.ip_address(host.strip("[]"))
            except ValueError:
                raise validation.ValidationError("dnstap.target", "Enter IP:port (e.g. 192.0.2.50:6000) or the path of a Unix socket.") from None
            if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
                raise validation.ValidationError("dnstap.target", "Enter IP:port (e.g. 192.0.2.50:6000) or the path of a Unix socket.")
            target = f"[{address}]:{port_text}" if address.version == 6 else f"{address}:{port_text}"
        t["target"] = target
    t["queries"], t["responses"] = bool(tap.get("queries", True)), bool(tap.get("responses", True))
    if t["enabled"] and not (t["queries"] or t["responses"]):
        raise validation.ValidationError("dnstap.queries", "Send queries, responses or both.")
    row = db.get(Setting, KEY)
    if row is None:
        db.add(Setting(name=KEY, value=out))
    else:
        row.value = out
    return out


def dnsdist_config(db: Session, node: str) -> dict | None:
    """The dnstap part of dnsdist's settings file, or None when off."""
    tap = get(db)["dnstap"]
    if not tap["enabled"] or not tap["target"]:
        return None
    return {"target": tap["target"], "queries": tap["queries"], "responses": tap["responses"], "identity": node}


# --------------------------------------------------------------------------- syslog (dnsone-querylog)


def format_message(cfg: dict, node: str, row: dict, group: str | None) -> bytes:
    """One RFC 5424 message. `row` is a query log row (already privacy-filtered)."""
    severity = SEVERITY_NOTICE if row["status"] in ("blocked", "legal") else SEVERITY_INFO
    pri = FACILITIES[cfg["facility"]] * 8 + severity
    ts = row["ts"].replace(tzinfo=timezone.utc) if isinstance(row["ts"], datetime) else datetime.now(timezone.utc)
    fields = {"client": row["client"], "qname": row["qname"], "qtype": row["qtype_text"], "rcode": row["rcode_text"], "status": row["status"],
              "group": group or "", "latency_ms": None if row["latency_us"] is None else round(row["latency_us"] / 1000, 1), "node": node}
    if cfg["format"] == "json":
        body = json.dumps(fields, separators=(",", ":"))
    else:
        body = " ".join(f"{k}={'' if v is None else v}" for k, v in fields.items())
    stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
    return f"<{pri}>1 {stamp} {node or '-'} dnsone - query - {body}\n".encode()


class SyslogSender:
    """Sends messages without ever slowing the collector: UDP is fire-and-forget, TCP is queued
    (oldest dropped when full) and reconnects every few seconds."""

    def __init__(self):
        self.cfg: dict | None = None
        self.sent = self.dropped = 0
        self._udp: socket.socket | None = None
        self._udp_addr = None
        self._queue: asyncio.Queue[bytes] | None = None
        self._task: asyncio.Task | None = None
        self.error: str | None = None

    def configure(self, cfg: dict | None) -> None:
        if cfg == self.cfg:
            return
        self.close()
        self.cfg = cfg
        if not cfg:
            return
        log.info("query log export: syslog %s://%s:%d (%s, %s)", cfg["protocol"], cfg["host"], cfg["port"], cfg["format"], cfg["only"])
        if cfg["protocol"] == "udp":
            try:
                info = socket.getaddrinfo(cfg["host"], cfg["port"], type=socket.SOCK_DGRAM)[0]
                self._udp = socket.socket(info[0], socket.SOCK_DGRAM)
                self._udp.setblocking(False)
                self._udp_addr = info[4]
                self.error = None
            except OSError as exc:
                self.error = f"cannot resolve {cfg['host']}: {exc}"
                log.warning("syslog export: %s", self.error)
        else:
            self._queue = asyncio.Queue(maxsize=QUEUE_LIMIT)
            self._task = asyncio.get_running_loop().create_task(self._tcp_writer(cfg))

    def wants(self, status: str) -> bool:
        return bool(self.cfg) and (self.cfg["only"] == "all" or status in ("blocked", "legal"))

    def send(self, message: bytes) -> None:
        if self._udp is not None:
            try:
                self._udp.sendto(message, self._udp_addr)
                self.sent += 1
            except (BlockingIOError, OSError):
                self.dropped += 1
        elif self._queue is not None:
            if self._queue.full():
                self._queue.get_nowait()
                self.dropped += 1
            self._queue.put_nowait(message)

    async def _tcp_writer(self, cfg: dict) -> None:
        while True:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(cfg["host"], cfg["port"]), timeout=5)
                self.error = None
                try:
                    while True:
                        message = await self._queue.get()
                        writer.write(message)
                        self.sent += 1
                        if self._queue.empty():
                            await writer.drain()
                finally:
                    writer.close()
            except asyncio.CancelledError:
                raise
            except (OSError, asyncio.TimeoutError) as exc:
                if self.error is None:
                    log.warning("syslog export to %s:%d: %s; retrying", cfg["host"], cfg["port"], exc)
                self.error = str(exc) or exc.__class__.__name__
                await asyncio.sleep(5)

    def close(self) -> None:
        if self._udp is not None:
            self._udp.close()
        if self._task is not None:
            self._task.cancel()
        self._udp = self._queue = self._task = None
        self.cfg = None

    def state(self) -> dict:
        return {"enabled": bool(self.cfg), "sent": self.sent, "dropped": self.dropped, "error": self.error}
