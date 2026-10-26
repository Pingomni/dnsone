"""dnsone-querylog: turns the Recursor's protobuf stream into the query log and top lists.

The Recursor connects to DNSONE_QUERYLOG_LISTEN (one TCP connection per worker thread) and sends
every answer as a 2-byte-length-prefixed PBDNSMessage. dnsdist forwards with the PROXY protocol,
so the client address in each message is the customer's, not dnsdist's.

Recursor 4.9 does not put the RPZ result in these messages, so each query is classified here
with the same data the Recursor's policy script uses (policy.json, written with policy.lua) and
the same RPZ files: the client's group, paused blocking, regex rules, then the group's RPZ (exact
trigger first, then the closest wildcard, as RPZ does). The result is legal (court-ordered blocking,
before everything else), blocked, allowed (an allow rule or allowlist matched) or ok (also for a
Safe Search rewrite, which answers rather than blocks).

Writes, by DNSONE_QUERYLOG_MODE:
  full       query_log rows (batched every 2 s) + hourly top lists (every minute)
  aggregate  hourly top lists only: no per-client history is kept
  off        the service exits; nothing is collected
Settings → Privacy can hide domains and/or clients, or keep totals only (privacy.py), and shorten
retention. Settings → Query log export can also send each answer to a syslog collector (logexport.py). If MySQL is slow the in-memory buffer is capped and the oldest rows are dropped, never DNS.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import signal
import struct
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import dns.rcode
import dns.rdatatype
from sqlalchemy import text

from . import logsetup, pbdns, privacy
from .edition import pro

logexport = pro("logexport")
from .config import Settings, get_settings
from .db import get_engine, new_session
from .models import Setting
from .system import utcnow

log = logging.getLogger(__name__)

FLUSH_ROWS_SECONDS = 2.0
FLUSH_STATS_SECONDS = 60.0
PRUNE_SECONDS = 300.0
BUFFER_LIMIT = 200_000
TOP_PER_MINUTE = 1000
STATS_RETENTION_DAYS = 35
DELETE_CHUNK = 50_000
CACHE_LIMIT = 200_000


class RpzMatcher:
    """The RPZ file's triggers, reloaded when the file changes."""

    def __init__(self, path: Path):
        self.path = path
        self.mtime = 0.0
        self.block: set[str] = set()
        self.allow: set[str] = set()
        self.block_wild: set[str] = set()
        self.allow_wild: set[str] = set()

    def reload_if_changed(self) -> bool:
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return False
        if mtime == self.mtime:
            return False
        block, allow, block_wild, allow_wild = set(), set(), set(), set()
        with self.path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line or line[0] in ";$@\n":
                    continue
                name, _, rdata = line.rstrip("\n").partition("\t")
                passthru = rdata.endswith("rpz-passthru.")
                if name.startswith("*."):
                    (allow_wild if passthru else block_wild).add(name[2:])
                else:
                    (allow if passthru else block).add(name)
        self.block, self.allow, self.block_wild, self.allow_wild = block, allow, block_wild, allow_wild
        self.mtime = mtime
        log.info("RPZ triggers loaded: %d block, %d allow", len(block) + len(block_wild), len(allow) + len(allow_wild))
        return True

    def classify(self, qname: str) -> str:
        if qname in self.allow:
            return "allowed"
        if qname in self.block:
            return "blocked"
        labels = qname.split(".")
        for i in range(1, len(labels)):
            parent = ".".join(labels[i:])
            if parent in self.allow_wild:
                return "allowed"
            if parent in self.block_wild:
                return "blocked"
        return "ok"


class PolicyMatcher:
    """Classifies a query as the Recursor's policy script does (deploy/recursor/dnsone.lua)."""

    def __init__(self, settings: Settings):
        self.s = settings
        self.path = settings.recursor_policy_file.with_suffix(".json")
        self.mtime = -1.0
        self.data: dict = {}
        self.zones: dict[str, RpzMatcher] = {}
        self.regex: list[tuple[re.Pattern, str, int | None]] = []
        self._groups: dict[str, int] = {}
        self._regex_hits: dict[str, tuple[tuple[str, int | None], ...]] = {}

    def reload_if_changed(self) -> bool:
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            mtime = 0.0
        changed = False
        if mtime != self.mtime:
            data = None
            if mtime:
                try:
                    data = json.loads(self.path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    log.warning("cannot read %s; keeping the previous policy data", self.path)
                    return False
            if data is None:
                # Before the first runtime apply (upgrade from 1.0): one zone for everyone.
                data = {"default_group": 0, "groups": {"0": {"blocking": True, "policies": ["dnsone"]}}, "networks": {},
                        "lengths4": [], "lengths6": [], "pause": {}, "regex": {}, "files": {"dnsone": str(self.s.rpz_file)}}
            self.data = data
            self.mtime = mtime
            self.regex = [(re.compile(r["pattern"], re.IGNORECASE), r["action"], r["group"]) for r in data.get("regex", {}).values()]
            self.zones = {name: self.zones.get(name) or RpzMatcher(Path(path)) for name, path in data.get("files", {}).items()}
            self._groups.clear()
            self._regex_hits.clear()
            changed = True
        for zone in self.zones.values():
            changed = zone.reload_if_changed() or changed
        return changed

    def group(self, client: str) -> int:
        cached = self._groups.get(client)
        if cached is not None:
            return cached
        default = self.data.get("default_group") or 0
        group = default
        try:
            address = ipaddress.ip_address(client)
            lengths = self.data.get("lengths4" if address.version == 4 else "lengths6") or []
            networks = self.data.get("networks") or {}
            for length in lengths:
                net = ipaddress.ip_network(f"{address}/{length}", strict=False)
                found = networks.get(f"{net.network_address}/{length}")
                if found is not None:
                    group = found
                    break
        except ValueError:
            pass
        if len(self._groups) > CACHE_LIMIT:
            self._groups.clear()
        self._groups[client] = group
        return group

    def _paused(self, group: int, now: float) -> bool:
        pause = self.data.get("pause") or {}
        everyone = pause.get("all")
        if everyone and now < everyone:
            return True
        until = (pause.get("groups") or {}).get(str(group))
        return bool(until and now < until)

    def _regex(self, qname: str, group: int) -> str | None:
        if not self.regex:
            return None
        hits = self._regex_hits.get(qname)
        if hits is None:
            hits = tuple((action, g) for pattern, action, g in self.regex if pattern.search(qname))
            if len(self._regex_hits) > CACHE_LIMIT:
                self._regex_hits.clear()
            self._regex_hits[qname] = hits
        verdict = None
        for action, g in hits:
            if g is None or g == group:
                if action == "allow":
                    return "allow"
                verdict = "block"
        return verdict

    def group_name(self, client: str) -> str | None:
        info = (self.data.get("groups") or {}).get(str(self.group(client)))
        return info.get("name") if info else None

    def classify(self, client: str, qname: str, now: float) -> str:
        for name in self.data.get("legal") or []:
            zone = self.zones.get(name)
            if zone is not None and zone.classify(qname) == "blocked":
                return "legal"
        group = self.group(client)
        info = (self.data.get("groups") or {}).get(str(group))
        # Safe Search rewrites come before the group's allow and block zones, paused or not.
        for name in (info or {}).get("keep") or []:
            zone = self.zones.get(name)
            if zone is not None and zone.classify(qname) != "ok":
                return "ok"
        if info is None or not info.get("blocking") or self._paused(group, now):
            return "ok"
        rx = self._regex(qname, group)
        if rx == "allow":
            return "allowed"
        # The group's zones in the Recursor's order: the allow zone, then the block zone.
        for name in info.get("policies") or []:
            zone = self.zones.get(name)
            if zone is not None:
                status = zone.classify(qname)
                if status != "ok":
                    return status
        return "blocked" if rx == "block" else "ok"


def qtype_text(qtype: int) -> str:
    try:
        return dns.rdatatype.to_text(qtype)
    except Exception:  # noqa: BLE001 - unknown numbers print as TYPEnnn
        return f"TYPE{qtype}"


def rcode_text(rcode: int) -> str:
    try:
        return dns.rcode.to_text(rcode)
    except Exception:  # noqa: BLE001
        return f"RCODE{rcode}"


class Aggregator:
    """Per-minute counters, flushed as the minute's busiest items into query_stats_hourly."""

    def __init__(self):
        self.counters: dict[tuple[datetime, str], Counter] = {}

    def add(self, hour: datetime, answer: pbdns.Answer, status: str, level: int = 0) -> None:
        def bump(dimension: str, item: str) -> None:
            key = (hour, dimension)
            counter = self.counters.get(key)
            if counter is None:
                counter = self.counters[key] = Counter()
            counter[item] += 1

        bump("status", status)
        bump("qtype", qtype_text(answer.qtype))
        bump("rcode", rcode_text(answer.rcode))
        # Privacy levels: 1 keeps no domains, 2 no clients either (privacy.py).
        if level < 2:
            bump("client", answer.client)
            if status == "blocked":
                bump("client_blocked", answer.client)
        if level < 1:
            bump("blocked" if status == "blocked" else "domain", answer.qname)

    def drain(self, node: str) -> list[dict]:
        rows = []
        for (hour, dimension), counter in self.counters.items():
            # status, qtype and rcode are small sets: keep them whole.
            items = counter.items() if dimension in ("status", "qtype", "rcode") else counter.most_common(TOP_PER_MINUTE)
            rows += [{"hour": hour, "dimension": dimension, "node": node, "item": item[:253], "hits": hits} for item, hits in items]
        self.counters = {}
        return rows


def _parse_listen(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    return host.strip("[]") or "127.0.0.1", int(port)


class Collector:
    def __init__(self, settings: Settings | None = None):
        self.s = settings or get_settings()
        self.matcher = PolicyMatcher(self.s)
        self.privacy = {"level": 0, "retention_hours": self.s.querylog_retention_hours}
        # Always there (off until configured): _read_privacy turns it on while the licence allows it.
        self.syslog = logexport.SyslogSender()
        self._export: dict | None = None
        self.aggregator = Aggregator()
        self.rows: list[dict] = []
        self.received = self.stored = self.dropped = self.bad = 0
        self.connections = 0
        self._writers: set[asyncio.StreamWriter] = set()
        self.last_message: float | None = None
        self.started = time.time()
        self._stop = asyncio.Event()

    # ------------------------------------------------------------------ input

    def handle(self, answer: pbdns.Answer) -> None:
        # dnsdist's health checks (from loopback) arrive every few seconds: proof the stream works.
        self.last_message = time.time()
        if answer.client in self.s.querylog_ignore_clients:
            return
        self.received += 1
        status = self.matcher.classify(answer.client, answer.qname, answer.time)
        ts = datetime.fromtimestamp(answer.time, timezone.utc).replace(tzinfo=None)
        level = self.privacy["level"]
        self.aggregator.add(ts.replace(minute=0, second=0, microsecond=0), answer, status, level)
        if level < 3 and self.syslog is not None and self.syslog.wants(status):
            row = {"ts": ts, "client": privacy.HIDDEN if level >= 2 else answer.client, "qname": privacy.HIDDEN if level >= 1 else answer.qname,
                   "qtype_text": qtype_text(answer.qtype), "rcode_text": rcode_text(answer.rcode), "status": status,
                   "latency_us": None if answer.latency_ms is None else int(answer.latency_ms * 1000)}
            self.syslog.send(logexport.format_message(self.syslog.cfg, self.s.node_name, row, None if level >= 2 else self.matcher.group_name(answer.client)))
        if self.s.querylog_mode == "full" and level < 3:
            if len(self.rows) >= BUFFER_LIMIT:
                del self.rows[: BUFFER_LIMIT // 10]
                self.dropped += BUFFER_LIMIT // 10
            self.rows.append({
                "node": self.s.node_name, "ts": ts, "client": privacy.HIDDEN if level >= 2 else answer.client,
                "qname": privacy.HIDDEN if level >= 1 else answer.qname[:253], "qtype": answer.qtype,
                "rcode": answer.rcode, "status": status, "latency_us": None if answer.latency_ms is None else min(int(answer.latency_ms * 1000), 4_000_000_000),
            })

    async def serve_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        self._writers.add(writer)
        try:
            while True:
                header = await reader.readexactly(2)
                (length,) = struct.unpack("!H", header)
                payload = await reader.readexactly(length)
                try:
                    answer = pbdns.decode(payload)
                except pbdns.DecodeError:
                    self.bad += 1
                    continue
                if answer is not None:
                    self.handle(answer)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self.connections -= 1
            self._writers.discard(writer)
            writer.close()

    # ------------------------------------------------------------------ output (threads: SQLAlchemy is synchronous)

    def _insert_rows(self, rows: list[dict]) -> None:
        with get_engine().begin() as conn:
            conn.execute(text(
                "INSERT INTO query_log (node, ts, client, qname, qtype, rcode, status, latency_us)"
                " VALUES (:node, :ts, :client, :qname, :qtype, :rcode, :status, :latency_us)"
            ), rows)

    def _upsert_stats(self, rows: list[dict]) -> None:
        with get_engine().begin() as conn:
            conn.execute(text(
                "INSERT INTO query_stats_hourly (hour, dimension, node, item, hits) VALUES (:hour, :dimension, :node, :item, :hits)"
                " AS new ON DUPLICATE KEY UPDATE hits = query_stats_hourly.hits + new.hits"
            ), rows)

    def _write_state(self) -> None:
        state = {
            "node": self.s.node_name, "mode": self.s.querylog_mode, "received": self.received, "stored": self.stored,
            "dropped": self.dropped, "bad": self.bad, "connections": self.connections, "privacy_level": self.privacy["level"],
            "export": self.syslog.state(),
            "last_message_at": datetime.fromtimestamp(self.last_message, timezone.utc).isoformat(timespec="seconds") if self.last_message else None,
            "updated_at": utcnow().isoformat(timespec="seconds"),
        }
        db = new_session()
        try:
            row = db.get(Setting, f"querylog.state.{self.s.node_name}"[:64])
            if row is None:
                db.add(Setting(name=f"querylog.state.{self.s.node_name}"[:64], value=state))
            else:
                row.value = state
            db.commit()
        finally:
            db.close()

    def _prune(self) -> None:
        cutoff = utcnow() - timedelta(hours=self.privacy["retention_hours"])
        with get_engine().connect() as conn:
            while conn.execute(text("DELETE FROM query_log WHERE node = :n AND ts < :c LIMIT :l"), {"n": self.s.node_name, "c": cutoff, "l": DELETE_CHUNK}).rowcount:
                conn.commit()
            conn.commit()
            boundary = conn.execute(text("SELECT id FROM query_log WHERE node = :n ORDER BY id DESC LIMIT 1 OFFSET :o"),
                                    {"n": self.s.node_name, "o": self.s.querylog_max_rows}).scalar()
            if boundary is not None:
                while conn.execute(text("DELETE FROM query_log WHERE node = :n AND id <= :b LIMIT :l"), {"n": self.s.node_name, "b": boundary, "l": DELETE_CHUNK}).rowcount:
                    conn.commit()
                conn.commit()
            conn.execute(text("DELETE FROM query_stats_hourly WHERE hour < :c"), {"c": utcnow() - timedelta(days=STATS_RETENTION_DAYS)})
            conn.commit()

    async def flush_rows(self) -> None:
        if not self.rows:
            return
        rows, self.rows = self.rows, []
        try:
            await asyncio.to_thread(self._insert_rows, rows)
            self.stored += len(rows)
        except Exception:  # noqa: BLE001 - keep collecting; the rows are lost, not DNS
            log.exception("writing %d query log rows failed", len(rows))
            self.dropped += len(rows)

    async def flush_stats(self) -> None:
        rows = self.aggregator.drain(self.s.node_name)
        try:
            if rows:
                await asyncio.to_thread(self._upsert_stats, rows)
            await asyncio.to_thread(self._write_state)
        except Exception:  # noqa: BLE001
            log.exception("writing query statistics failed")

    async def _every(self, seconds: float, job) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=seconds)
            except asyncio.TimeoutError:
                pass
            await job()

    async def _reload_rpz(self) -> None:
        await asyncio.to_thread(self.matcher.reload_if_changed)

    def _read_privacy(self) -> None:
        db = new_session()
        try:
            value = privacy.get(db, self.s)
            syslog = logexport.get(db)["syslog"] if logexport else {"enabled": False, "host": ""}
        finally:
            db.close()
        # Level 3 keeps totals only: nothing per query leaves the server either.
        self._export = syslog if syslog["enabled"] and syslog["host"] and value["level"] < 3 else None
        if value != self.privacy:
            log.info("privacy: level %d, retention %d h", value["level"], value["retention_hours"])
            self.privacy = value

    async def _reload_privacy(self) -> None:
        try:
            await asyncio.to_thread(self._read_privacy)
            self.syslog.configure(self._export)
        except Exception:  # noqa: BLE001 - keep the previous level
            log.exception("reading the privacy settings failed")

    async def _prune_job(self) -> None:
        try:
            await asyncio.to_thread(self._prune)
        except Exception:  # noqa: BLE001
            log.exception("pruning the query log failed")

    async def run(self) -> None:
        self.matcher.reload_if_changed()
        await self._reload_privacy()
        host, port = _parse_listen(self.s.querylog_listen)
        server = await asyncio.start_server(self.serve_connection, host, port, reuse_address=True)
        log.info("listening on %s:%d (mode %s, retention %d h / %d rows)", host, port, self.s.querylog_mode,
                 self.s.querylog_retention_hours, self.s.querylog_max_rows)
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._stop.set)
        jobs = [
            asyncio.create_task(self._every(FLUSH_ROWS_SECONDS, self.flush_rows)),
            asyncio.create_task(self._every(FLUSH_STATS_SECONDS, self.flush_stats)),
            asyncio.create_task(self._every(5.0, self._reload_rpz)),
            asyncio.create_task(self._every(15.0, self._reload_privacy)),
            asyncio.create_task(self._every(PRUNE_SECONDS, self._prune_job)),
        ]
        await self._stop.wait()
        # The Recursor never closes its connections, and Server.wait_closed() waits for all of them
        # (Python 3.12): close them here, or a stop would hang until systemd kills the process.
        server.close()
        for writer in list(self._writers):
            writer.close()
        try:
            await asyncio.wait_for(server.wait_closed(), timeout=5)
        except asyncio.TimeoutError:
            log.warning("connections did not close within 5 s")
        for job in jobs:
            job.cancel()
        self.syslog.close()
        await self.flush_rows()
        await self.flush_stats()
        log.info("stopped: %d received, %d stored, %d dropped", self.received, self.stored, self.dropped)


def main() -> int:
    logsetup.setup("querylog")
    settings = get_settings()
    if settings.querylog_mode == "off":
        log.info("DNSONE_QUERYLOG_MODE=off: not collecting")
        return 0
    asyncio.run(Collector(settings).run())
    return 0
