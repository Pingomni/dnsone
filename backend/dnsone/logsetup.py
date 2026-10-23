"""Logging: stderr (journald under systemd) plus a file rotated by logrotate (deploy/logrotate/dnsone)."""

from __future__ import annotations

import logging
import logging.handlers
import sys

from .config import get_settings

FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def setup(component: str) -> None:
    s = get_settings()
    root = logging.getLogger()
    if getattr(root, "_dnsone", False):
        return
    root.setLevel(s.log_level)
    stream = logging.StreamHandler(sys.stderr)
    # journald adds its own timestamp.
    stream.setFormatter(logging.Formatter(f"{component}: %(levelname)s %(name)s: %(message)s"))
    root.addHandler(stream)
    if s.log_file:
        try:
            s.log_file.parent.mkdir(parents=True, exist_ok=True)
            # WatchedFileHandler reopens the file after logrotate moves it.
            handler = logging.handlers.WatchedFileHandler(s.log_file, encoding="utf-8")
            handler.setFormatter(logging.Formatter(f"%(asctime)s {component} %(levelname)s %(name)s: %(message)s"))
            root.addHandler(handler)
        except OSError as exc:
            root.warning("cannot write %s: %s; logging to journald only", s.log_file, exc)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    root._dnsone = True  # type: ignore[attr-defined]
