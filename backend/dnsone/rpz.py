"""RPZ ad-blocking pipeline: blocklists -> parsed domain sets -> one RPZ per client group -> Recursor.

Refreshing a blocklist downloads it (conditional GET, size-capped), parses hosts / plain-domain /
simple Adblock syntax, de-duplicates, and stores the sorted domain set in BLOCKLIST_DIR/<id>.txt.

Building writes two RPZ zones for each client group with blocking on: an allow zone (passthru
entries for allow rules and allowlist subscriptions) and a block zone (the group's blocklists and
the exact-name rules for every group plus the group's own, which win). The allow zone is loaded
first, so it wins, and without the "Blocked" extended DNS error the Recursor would otherwise attach
to allowed answers too. named-checkzone validates every file before any replaces a live one;
zones.lua tells recursor.lua which files to load, and `rec_control reload-lua-config` swaps them in
without a restart. The Recursor API then confirms every new serial. Which zone applies to
which client, regex rules and pauses are the policy script's job (runtime.py, deploy/recursor/dnsone.lua).

Every node builds its own files from the shared MySQL (Phase 2), so the build state is per node.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from . import validation
from .config import Settings, get_settings
from .db import NamedLock, new_session
from .models import Blocklist, ClientGroup, RpzRule, Setting
from .system import atomic_write, replace_keeping_previous, restore_previous, run, write_temp
from .system import utcnow
from .zonegen import next_serial

log = logging.getLogger(__name__)

DEFAULT_POLICY = {"action": "nxdomain", "walled_garden_target": "", "block_subdomains": True}
# null_ip: 0.0.0.0 / :: (what most ad-blockers answer; clients fail fast instead of retrying).
POLICY_ACTIONS = ("nxdomain", "nodata", "null_ip", "walled_garden")
DEFAULT_POLICY_NAME = "dnsone"

# Names that hosts files list for the machine itself; never blocked.
_SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
         "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"}
_HOST_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1", "0", "255.255.255.255", "fe80::1%lo0", "ff00::0", "ff02::1", "ff02::2", "ff02::3"}
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_ADBLOCK = re.compile(r"^\|\|([a-z0-9_.-]+)\^(?:\$(?:important|all|third-party|3p|document|popup))?$")


# --------------------------------------------------------------------------- parsing

def _clean(token: str) -> str | None:
    name = token.strip().strip(".").lower()
    if not name or name in _SKIP:
        return None
    if not name.isascii():
        try:
            name = validation.rpz_pattern(name)
        except validation.ValidationError:
            return None
    return name if _DOMAIN.match(name) else None


def parse_blocklist(text: str, fmt: str = "auto") -> set[str]:
    """Domains from a blocklist. Unparseable lines are skipped, not fatal."""
    domains: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#!;[":
            continue
        if fmt in ("auto", "adblock") and line.startswith("||"):
            m = _ADBLOCK.match(line.lower())
            if m and (name := _clean(m.group(1))):
                domains.add(name)
            continue
        if fmt == "adblock":
            continue
        line = line.split("#", 1)[0].strip()
        parts = line.split()
        if not parts:
            continue
        if fmt in ("auto", "hosts") and parts[0] in _HOST_IPS:
            candidates = parts[1:]
        elif fmt == "hosts":
            continue
        else:
            candidates = parts[:1] if len(parts) == 1 else []
        for token in candidates:
            if name := _clean(token):
                domains.add(name)
    return domains


# --------------------------------------------------------------------------- settings

def get_policy(db: Session) -> dict:
    row = db.get(Setting, "rpz.policy")
    return {**DEFAULT_POLICY, **(row.value if row else {})}


_NODE_FIELDS = ("serial", "state", "built_at", "built_revision", "entries", "error", "seconds", "policies", "groups")


def _node_key(settings: Settings | None = None) -> str:
    return f"rpz.node.{(settings or get_settings()).node_name}"[:64]


def get_state(db: Session, settings: Settings | None = None) -> dict:
    """The change counter (shared by all nodes) and this node's last build."""
    row = db.get(Setting, "rpz.state")
    shared = dict(row.value) if row else {"serial": 0, "state": "never"}
    node = db.get(Setting, _node_key(settings))
    # Before a node's first build of its own (upgrade from 1.0), the shared row holds its state.
    own = dict(node.value) if node else {k: shared[k] for k in _NODE_FIELDS if k in shared}
    return {"revision": int(shared.get("revision") or 0), "serial": 0, "state": "never", **own}


def _set_node_state(db: Session, state: dict, settings: Settings | None = None) -> None:
    _set(db, _node_key(settings), {k: state.get(k) for k in _NODE_FIELDS})


def _set(db: Session, name: str, value: dict) -> None:
    row = db.get(Setting, name)
    if row is None:
        db.add(Setting(name=name, value=value))
    else:
        row.value = value


def set_policy(db: Session, action: str, walled_garden_target: str, block_subdomains: bool) -> dict:
    if action not in POLICY_ACTIONS:
        raise validation.ValidationError("action", f"Choose one of: {', '.join(POLICY_ACTIONS)}.")
    target = validation.walled_garden_target(walled_garden_target) if action == "walled_garden" else ""
    value = {"action": action, "walled_garden_target": target, "block_subdomains": bool(block_subdomains)}
    _set(db, "rpz.policy", value)
    return value


# --------------------------------------------------------------------------- fetching

@dataclass
class FetchResult:
    id: int
    name: str
    status: str
    domains: int = 0
    message: str = ""


class Blocklists:
    def __init__(self, settings: Settings | None = None):
        self.s = settings or get_settings()

    def path(self, blocklist_id: int) -> Path:
        return self.s.blocklist_dir / f"{blocklist_id}.txt"

    def load(self, blocklist_id: int) -> set[str]:
        path = self.path(blocklist_id)
        if not path.exists():
            return set()
        return set(path.read_text(encoding="ascii", errors="ignore").split())

    def _download(self, bl: Blocklist) -> tuple[int, bytes, dict]:
        headers = {"User-Agent": "DNSOne blocklist fetcher"}
        # The validators are shared by every node; one without its own copy must fetch in full.
        if self.path(bl.id).exists():
            if bl.etag:
                headers["If-None-Match"] = bl.etag
            if bl.last_modified:
                headers["If-Modified-Since"] = bl.last_modified
        with httpx.Client(timeout=self.s.blocklist_timeout, follow_redirects=True, max_redirects=5) as client:
            with client.stream("GET", bl.url, headers=headers) as response:
                if response.status_code == 304:
                    return 304, b"", dict(response.headers)
                response.raise_for_status()
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > self.s.blocklist_max_bytes:
                        raise ValueError(f"the list is larger than {self.s.blocklist_max_bytes // (1024 * 1024)} MB")
                    chunks.append(chunk)
                return response.status_code, b"".join(chunks), dict(response.headers)

    def refresh(self, blocklist_id: int, force: bool = False) -> FetchResult:
        db = new_session()
        try:
            bl = db.get(Blocklist, blocklist_id)
            if bl is None:
                return FetchResult(blocklist_id, "?", "error", message="blocklist not found")
            if force:
                bl.etag = bl.last_modified = None
            bl.last_checked = utcnow()
            try:
                code, body, headers = self._download(bl)
            except (httpx.HTTPError, ValueError) as exc:
                bl.last_status, bl.last_error = "error", f"Download failed: {exc}"[:1024]
                db.commit()
                return FetchResult(bl.id, bl.name, "error", bl.domain_count, bl.last_error)
            if code == 304 and self.path(bl.id).exists():
                bl.last_status, bl.last_error = "not_modified", None
                db.commit()
                return FetchResult(bl.id, bl.name, "not_modified", bl.domain_count, "unchanged since the last download")
            digest = hashlib.sha256(body).hexdigest()
            text = body.decode("utf-8", errors="replace")
            domains = parse_blocklist(text, bl.format)
            if not domains:
                bl.last_status, bl.last_error = "error", "No domains found: check the URL and the list format. The previous copy is kept."
                db.commit()
                return FetchResult(bl.id, bl.name, "error", bl.domain_count, bl.last_error)
            atomic_write(self.path(bl.id), "\n".join(sorted(domains)) + "\n", 0o640)
            bl.domain_count = len(domains)
            bl.content_sha256 = digest
            bl.etag = headers.get("etag")
            bl.last_modified = headers.get("last-modified")
            bl.last_updated = utcnow()
            bl.last_status, bl.last_error = "ok", None
            db.commit()
            return FetchResult(bl.id, bl.name, "ok", len(domains), f"{len(domains)} domains")
        finally:
            db.close()

    def refresh_all(self) -> list[FetchResult]:
        db = new_session()
        try:
            ids = db.scalars(select(Blocklist.id).where(Blocklist.enabled.is_(True)).order_by(Blocklist.id)).all()
        finally:
            db.close()
        return [self.refresh(i) for i in ids]

    def fetch_missing(self) -> list[FetchResult]:
        """Downloads enabled lists this node has no copy of (a new replica, a lost data directory)."""
        db = new_session()
        try:
            ids = db.scalars(select(Blocklist.id).where(Blocklist.enabled.is_(True)).order_by(Blocklist.id)).all()
        finally:
            db.close()
        return [self.refresh(i, force=True) for i in ids if not self.path(i).exists()]


# --------------------------------------------------------------------------- building

def _covered(name: str, exact: set[str], wildcard: set[str]) -> bool:
    """True if `name` is whitelisted exactly or by a *.parent rule."""
    if name in exact:
        return True
    labels = name.split(".")
    return any(".".join(labels[i:]) in wildcard for i in range(1, len(labels)))


def policy_name(group: ClientGroup) -> str:
    return DEFAULT_POLICY_NAME if group.built_in else f"{DEFAULT_POLICY_NAME}-g{group.id}"


def group_zone(group: ClientGroup, settings: Settings | None = None) -> str:
    s = settings or get_settings()
    return s.rpz_zone if group.built_in else f"g{group.id}.{s.rpz_zone}"


def group_file(group: ClientGroup, settings: Settings | None = None) -> Path:
    s = settings or get_settings()
    return s.rpz_file if group.built_in else s.rpz_file.with_name(f"{s.rpz_file.stem}-g{group.id}{s.rpz_file.suffix}")


def allow_policy_name(group: ClientGroup) -> str:
    return f"{policy_name(group)}-allow"


def allow_file(group: ClientGroup, settings: Settings | None = None) -> Path:
    path = group_file(group, settings)
    return path.with_name(f"{path.stem}-allow{path.suffix}")


def group_policies(group: ClientGroup) -> list[str]:
    """The group's RPZ policies in the order the Recursor applies them."""
    return [allow_policy_name(group), policy_name(group)]


@dataclass
class ZoneFile:
    policy: str
    zone: str
    path: Path
    text: str
    # Passthru entries only: loaded first, without the "Blocked" extended DNS error.
    allow: bool


def zones_file(settings: Settings | None = None) -> Path:
    """Read by recursor.lua: which RPZ files to load, in order."""
    return (settings or get_settings()).rpz_file.with_name("zones.lua")


def blocking_groups(db: Session) -> list[ClientGroup]:
    return list(db.scalars(select(ClientGroup).where(ClientGroup.blocking.is_(True)).order_by(ClientGroup.built_in.desc(), ClientGroup.id)))


@dataclass
class BuildResult:
    ok: bool
    serial: int | None = None
    entries: int = 0
    message: str = ""


class RpzBuilder:
    def __init__(self, settings: Settings | None = None):
        self.s = settings or get_settings()
        self.lists = Blocklists(self.s)
        self._cache: dict[int, set[str]] = {}

    def _load(self, blocklist_id: int) -> set[str]:
        if blocklist_id not in self._cache:
            self._cache[blocklist_id] = self.lists.load(blocklist_id)
        return self._cache[blocklist_id]

    def _policy_rdata(self, action: str, target: str | None) -> list[str]:
        if action == "nxdomain":
            return ["CNAME\t."]
        if action == "nodata":
            return ["CNAME\t*."]
        if action == "passthru":
            return ["CNAME\trpz-passthru."]
        if action == "null_ip":
            return ["A\t0.0.0.0", "AAAA\t::"]
        # walled garden / redirect: a host name, or an address answered directly.
        if target and ":" in target:
            return [f"AAAA\t{target}"]
        if target and re.fullmatch(r"[0-9.]+", target):
            return [f"A\t{target}"]
        return [f"CNAME\t{target}."]

    def render(self, db: Session, serial: int, group: ClientGroup | None = None) -> tuple[str, str, int]:
        """The block zone and the allow zone of one group (the Default group when None), and the trigger count."""
        if group is None:
            group = db.scalar(select(ClientGroup).where(ClientGroup.built_in.is_(True)))
        policy = get_policy(db)
        default_action = policy["action"]
        default_target = policy["walled_garden_target"] or None
        if default_action == "walled_garden" and not default_target:
            default_action = "nxdomain"
        # Rules for every group, then the group's own: for the same pattern the group's rule wins.
        rules: dict[str, RpzRule] = {}
        for r in db.scalars(select(RpzRule).where(RpzRule.enabled.is_(True), RpzRule.match_type == "exact",
                                                  or_(RpzRule.group_id.is_(None), RpzRule.group_id == group.id))
                            .order_by(RpzRule.group_key)):
            rules[r.pattern] = r
        lists = [bl for bl in group.blocklists if bl.enabled]

        allow_exact = {p for p, r in rules.items() if r.action == "allow" and not p.startswith("*.")}
        allow_wild = {p[2:] for p, r in rules.items() if r.action == "allow" and p.startswith("*.")}
        for bl in lists:
            if bl.kind == "allow":
                allow_exact |= self._load(bl.id)

        # pattern -> (action, target); manual rules win over blocklists.
        entries: dict[str, tuple[str, str | None]] = {}
        for bl in lists:
            if bl.kind != "block":
                continue
            for name in self._load(bl.id):
                if not _covered(name, allow_exact, allow_wild):
                    entries[name] = (default_action, default_target)
        if policy.get("block_subdomains", True):
            for name in list(entries):
                entries.setdefault(f"*.{name}", entries[name])
        for pattern, r in rules.items():
            if r.action == "allow":
                continue
            base = pattern[2:] if pattern.startswith("*.") else pattern
            if _covered(base, allow_exact, allow_wild) and not pattern.startswith("*."):
                continue
            action = default_action if r.action == "block" else ("walled_garden" if r.action == "redirect" else r.action)
            target = default_target if r.action == "block" else r.target
            if action == "walled_garden" and not target:
                action = "nxdomain"
            entries[pattern] = (action, target)
            # Like list entries, an exact rule covers the names below it when the policy says so.
            if policy.get("block_subdomains", True) and not pattern.startswith("*."):
                entries.setdefault(f"*.{pattern}", (action, target))
        # Remove wildcard entries a whitelist covers, then add explicit passthru for the whitelist.
        for pattern in [p for p in entries if p.startswith("*.")]:
            if _covered(pattern[2:], set(), allow_wild) or pattern[2:] in allow_wild:
                del entries[pattern]
        for name in allow_exact:
            entries[name] = ("passthru", None)
        for name in allow_wild:
            entries[name] = ("passthru", None)
            entries[f"*.{name}"] = ("passthru", None)

        texts = {}
        for allow in (False, True):
            chosen = sorted((p for p, (action, _) in entries.items() if (action == "passthru") == allow), key=lambda p: p.split(".")[::-1])
            what = "allow rules and allowlists" if allow else "blocklists and rules"
            lines = [
                f"; Generated by DNSOne from MySQL {what} (group {group.name}). Do not edit.",
                f"; {len(chosen)} triggers, generated {utcnow():%Y-%m-%d %H:%M:%S} UTC",
                "$TTL 60",
                f"@\tIN\tSOA\tlocalhost. hostmaster.localhost. {serial} 3600 600 86400 60",
                "@\tIN\tNS\tlocalhost.",
            ]
            for pattern in chosen:
                action, target = entries[pattern]
                for rd in self._policy_rdata(action, target):
                    lines.append(f"{pattern}\t{rd}")
            texts[allow] = "\n".join(lines) + "\n"
        return texts[False], texts[True], len(entries)

    def _loaded_serials(self) -> dict[str, int] | None:
        if not self.s.recursor_api_key:
            return None
        try:
            response = httpx.get(f"{self.s.recursor_api_url}/api/v1/servers/localhost/rpzstatistics",
                                 headers={"X-API-Key": self.s.recursor_api_key}, timeout=3)
            response.raise_for_status()
            return {name: int(v.get("serial") or 0) for name, v in response.json().items()}
        except (httpx.HTTPError, ValueError, TypeError, AttributeError):
            return None

    def build(self, only_if_needed: bool = False) -> BuildResult:
        with NamedLock(f"dnsone:rpz:{self.s.node_name}", timeout=600):
            db = new_session()
            try:
                state = get_state(db, self.s)
                revision = state["revision"]
                if only_if_needed and state.get("state") == "ok" and int(state.get("built_revision") or 0) >= revision:
                    return BuildResult(True, state.get("serial"), state.get("entries", 0), "up to date")
                serial = next_serial(int(state.get("serial") or 0))
                started = time.monotonic()
                files, total, counts = [], 0, {}
                for group in blocking_groups(db):
                    block, allow, count = self.render(db, serial, group)
                    zone = group_zone(group, self.s)
                    files += [ZoneFile(allow_policy_name(group), f"allow.{zone}", allow_file(group, self.s), allow, True),
                              ZoneFile(policy_name(group), zone, group_file(group, self.s), block, False)]
                    counts[str(group.id)] = count
                    total += count
                result = self._install(files, serial)
                result.entries = total
                state = get_state(db, self.s)  # re-read: changes made during the build keep their revision
                state.update(
                    built_revision=revision if result.ok else state.get("built_revision", 0),
                    serial=serial if result.ok else state.get("serial"),
                    state="ok" if result.ok else "error",
                    built_at=utcnow().isoformat(timespec="seconds"),
                    entries=total if result.ok else state.get("entries", 0),
                    error=None if result.ok else result.message[:4000],
                    seconds=round(time.monotonic() - started, 1),
                    policies=[f.policy for f in files] if result.ok else state.get("policies"),
                    groups=counts if result.ok else state.get("groups"),
                )
                _set_node_state(db, state, self.s)
                db.commit()
                log.info("rpz build: ok=%s serial=%s entries=%s %s", result.ok, serial, total, result.message)
            finally:
                db.close()
        if result.ok:
            # Which group uses which of the loaded zones: the policy script's data.
            from . import runtime
            runtime.apply_in_background()
        return result

    def _install(self, files: list[ZoneFile], serial: int) -> BuildResult:
        """Checks every file, then replaces them together; any failure leaves the live files as they were."""
        checked: list[tuple[ZoneFile, Path]] = []
        for f in files:
            tmp = write_temp(f.path, f.text, 0o644)
            # -k ignore: blocklists legitimately contain names BIND's host-name rules reject (underscores).
            cmd = [self.s.named_checkzone, "-k", "ignore", "-i", "none", f.zone, str(tmp)]
            code, out = run(cmd, timeout=max(self.s.command_timeout, 300))
            if code != 0:
                tmp.unlink(missing_ok=True)
                for _, other in checked:
                    other.unlink(missing_ok=True)
                return BuildResult(False, serial, message=f"named-checkzone rejected the RPZ {f.policy}; the live files were not changed.\n{out[-3000:]}")
            checked.append((f, tmp))

        changed: set[str] | None = set()
        for f, _ in checked:
            names = self._changed_names(f.path, f.text)
            changed = None if names is None or changed is None else changed | names
        zones = zones_file(self.s)
        listing = "-- Generated by DNSOne: the RPZ files recursor.lua loads, in order. Do not edit.\nreturn {\n" + "".join(
            f'    {{ file = "{f.path}", name = "{f.policy}", blocked = {"false" if f.allow else "true"} }},\n' for f, _ in checked) + "}\n"
        replaced = [(f.path, replace_keeping_previous(tmp, f.path)) for f, tmp in checked]
        replaced.append((zones, replace_keeping_previous(write_temp(zones, listing, 0o644), zones)))

        def rollback() -> None:
            for target, previous in replaced:
                restore_previous(target, previous)

        code, out = run([*self.s.rec_control, "reload-lua-config"], timeout=self.s.command_timeout)
        if code != 0:
            rollback()
            return BuildResult(False, serial, message=f"rec_control reload-lua-config failed; previous RPZ restored.\n{out}")
        if self.s.recursor_api_key:
            wanted = {f.policy for f, _ in checked}
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                loaded = self._loaded_serials() or {}
                if all(loaded.get(name) == serial for name in wanted):
                    break
                time.sleep(0.5)
            else:
                return BuildResult(False, serial, message=f"The Recursor did not report RPZ serial {serial} for every group within 30 s; check `journalctl -u pdns-recursor`.")
        for _, previous in replaced:
            if previous is not None:
                previous.unlink(missing_ok=True)
        self._remove_stale_files({f.path for f, _ in checked})
        if changed and len(changed) <= self.WIPE_LIMIT:
            # The Recursor's packet cache would keep serving the old answer for up to 60 s.
            wipe_cache(self.s, sorted(changed))
        groups = len(checked) // 2
        return BuildResult(True, serial, message=f"RPZ serial {serial} loaded for {groups} group(s)")

    def _remove_stale_files(self, keep: set[Path]) -> None:
        """RPZ files of deleted groups, or of groups whose blocking was turned off."""
        pattern = f"{self.s.rpz_file.stem}-*{self.s.rpz_file.suffix}"
        for path in self.s.rpz_file.parent.glob(pattern):
            if path not in keep:
                path.unlink(missing_ok=True)

    WIPE_LIMIT = 1000

    def _changed_names(self, target: Path, text: str) -> set[str] | None:
        """Names whose policy changed, for a targeted cache wipe; None when there are too many."""
        if not target.exists():
            return set()
        if target.stat().st_size > 64 * 1024 * 1024:
            return None
        def triggers(body: str) -> set[str]:
            return {ln for ln in body.splitlines() if ln and ln[0] not in ";$@"}
        diff = triggers(target.read_text(encoding="utf-8", errors="replace")) ^ triggers(text)
        names = {ln.split("\t", 1)[0] for ln in diff}
        if len(names) > self.WIPE_LIMIT:
            return None
        return {f"{n[2:]}$" if n.startswith("*.") else n for n in names}


def wipe_cache(settings: Settings, names: list[str]) -> None:
    for i in range(0, len(names), 100):
        code, out = run([*settings.rec_control, "wipe-cache", *names[i : i + 100]], timeout=settings.command_timeout)
        if code != 0:
            log.warning("rec_control wipe-cache failed: %s", out)
            return


def mark_changed(db: Session) -> None:
    """Records that rules, lists, groups or the policy changed; the next build_in_background() rebuilds."""
    row = db.get(Setting, "rpz.state", with_for_update=True)
    state = dict(row.value) if row else {"serial": 0, "state": "never"}
    state["revision"] = int(state.get("revision") or 0) + 1
    _set(db, "rpz.state", state)


def build_in_background() -> None:
    try:
        RpzBuilder().build(only_if_needed=True)
    except Exception:  # noqa: BLE001 - logged; the refresh timer rebuilds
        log.exception("background RPZ build failed")


def refresh_in_background(blocklist_id: int) -> None:
    try:
        Blocklists().refresh(blocklist_id, force=True)
        db = new_session()
        try:
            mark_changed(db)
            db.commit()
        finally:
            db.close()
        RpzBuilder().build()
    except Exception:  # noqa: BLE001
        log.exception("background refresh of blocklist %s failed", blocklist_id)


def lookup(db: Session, domain: str, group_id: int | None = None, settings: Settings | None = None) -> dict:
    """Why a name would or would not be blocked for a group (Default when None): rules, lists, regexes."""
    name = validation.rpz_pattern(domain, "domain").removeprefix("*.")
    group = db.get(ClientGroup, group_id) if group_id else db.scalar(select(ClientGroup).where(ClientGroup.built_in.is_(True)))
    if group is None:
        raise validation.ValidationError("group_id", "No such group.")
    lists = Blocklists(settings)
    labels = name.split(".")
    parents = [".".join(labels[i:]) for i in range(len(labels) - 1)]
    candidates = [name] + [f"*.{p}" for p in parents[1:]]
    in_scope = or_(RpzRule.group_id.is_(None), RpzRule.group_id == group.id)
    rules = list(db.scalars(select(RpzRule).where(RpzRule.match_type == "exact", RpzRule.pattern.in_(candidates + parents), in_scope)))
    hits, allow_hits = [], []
    policy = get_policy(db)
    for bl in group.blocklists:
        if not bl.enabled:
            continue
        listed = lists.load(bl.id)
        if bl.kind == "allow":
            if name in listed:
                allow_hits.append({"blocklist": bl.name, "match": name})
        elif name in listed:
            hits.append({"blocklist": bl.name, "match": name})
        elif policy.get("block_subdomains", True):
            parent = next((p for p in parents[1:] if p in listed), None)
            if parent:
                hits.append({"blocklist": bl.name, "match": f"*.{parent}"})
    subdomains = policy.get("block_subdomains", True)
    rule_rows = [{"id": r.id, "pattern": r.pattern, "action": r.action, "enabled": r.enabled, "group_id": r.group_id} for r in rules
                 if r.pattern == name or r.pattern in candidates
                 or (subdomains and r.action != "allow" and r.pattern in parents[1:])]
    regex_rows = []
    for r in db.scalars(select(RpzRule).where(RpzRule.match_type == "regex", in_scope)):
        if re.search(r.pattern, name, re.IGNORECASE):
            regex_rows.append({"id": r.id, "pattern": r.pattern, "action": r.action, "enabled": r.enabled, "group_id": r.group_id})
    rule_rows += regex_rows
    allowed = bool(allow_hits) or any(r["action"] == "allow" and r["enabled"] for r in rule_rows)
    blocked = group.blocking and not allowed and (bool(hits) or any(r["action"] != "allow" and r["enabled"] for r in rule_rows))
    return {"domain": name, "group": {"id": group.id, "name": group.name, "blocking": group.blocking}, "blocked": blocked,
            "allowed": allowed, "rules": rule_rows, "blocklists": hits, "allowlists": allow_hits}
