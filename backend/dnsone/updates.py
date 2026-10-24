"""Software update (Settings → Overview): the latest DNSOne release on GitHub, and installing it.

The API never changes the installation itself (it does not run as root): it leaves a request file in
update_request_dir, which dnsone-update.path sees; dnsone-update.service (root) then runs
`dnsone-update --console`, which writes its progress to update_status_dir (status.json, update.log).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx

from . import __version__
from .config import get_settings

API = "https://api.github.com"
CACHE_SECONDS = 3600
ERROR_CACHE_SECONDS = 60
LOG_TAIL = 64 * 1024
REQUEST = "request"

_cache: dict = {}


class UpdateError(Exception):
    pass


def _version(text: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in text.split("."))
    except ValueError:
        return ()


def newer(version: str, than: str) -> bool:
    return _version(version) > _version(than)


def latest(refresh: bool = False) -> dict:
    """The latest release: {tag, version, notes, url, published_at}, or {error}. Cached for an hour."""
    s = get_settings()
    if not s.update_check:
        return {"error": "Checking for updates is off on this server (DNSONE_UPDATE_CHECK=0)."}
    now = time.monotonic()
    if not refresh and _cache and now - _cache["at"] < _cache["ttl"]:
        return _cache["data"]
    try:
        response = httpx.get(f"{API}/repos/{s.update_repo}/releases/latest",
                             headers={"Accept": "application/vnd.github+json"}, timeout=5, follow_redirects=True)
        if response.status_code == 404:
            data = {"error": "No DNSOne release is published yet."}
        else:
            response.raise_for_status()
            release = response.json()
            tag = str(release["tag_name"])
            data = {"tag": tag, "version": tag.removeprefix("v"), "notes": str(release.get("body") or ""),
                    "url": str(release["html_url"]), "published_at": release.get("published_at")}
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        data = {"error": f"Cannot read the latest release from GitHub ({exc.__class__.__name__})."}
    _cache.update(at=now, data=data, ttl=ERROR_CACHE_SECONDS if "error" in data else CACHE_SECONDS)
    return data


def _read(path: Path, limit: int | None = None) -> str | None:
    try:
        with path.open("rb") as f:
            if limit is not None:
                f.seek(max(0, path.stat().st_size - limit))
            return f.read().decode("utf-8", "replace")
    except OSError:
        return None


def progress() -> dict:
    """The last (or running) install: {state, from, to, started, finished, log}; state is none if there was none."""
    s = get_settings()
    raw = _read(s.update_status_dir / "status.json")
    try:
        status = json.loads(raw) if raw else {}
    except ValueError:
        status = {}
    return {
        "state": status.get("state", "none"),
        "from": status.get("from"),
        "to": status.get("to"),
        "started": status.get("started"),
        "finished": status.get("finished"),
        "log": _read(s.update_status_dir / "update.log", LOG_TAIL) or "",
    }


def requested() -> bool:
    return (get_settings().update_request_dir / REQUEST).exists()


def can_install() -> bool:
    """dnsone-update.path is set up: the request directory exists and is ours to write."""
    d = get_settings().update_request_dir
    return d.is_dir() and os.access(d, os.W_OK)


def overview(refresh: bool = False) -> dict:
    release = latest(refresh)
    return {
        "installed": __version__,
        "latest": None if "error" in release else release,
        "error": release.get("error"),
        "available": "error" not in release and newer(release["version"], __version__),
        "can_install": can_install(),
        "requested": requested(),
        "progress": progress(),
    }


def request_install(actor: str) -> dict:
    """Asks dnsone-update.service to install the latest release. Returns the release asked for."""
    if not can_install():
        raise UpdateError("Installing from the console is not set up on this server: run sudo dnsone-update once.")
    if requested() or progress()["state"] == "running":
        raise UpdateError("An update is already under way.")
    release = latest(refresh=True)
    if "error" in release:
        raise UpdateError(release["error"])
    if not newer(release["version"], __version__):
        raise UpdateError(f"DNSOne {__version__} is up to date.")
    path = get_settings().update_request_dir / REQUEST
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    except FileExistsError:
        raise UpdateError("An update is already under way.") from None
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        # Informational: dnsone-update reads nothing from it and installs the latest release.
        json.dump({"by": actor, "version": release["version"], "at": int(time.time())}, f)
    return release
