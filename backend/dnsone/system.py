"""File and process helpers shared by the zone and RPZ generators."""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


def utcnow() -> datetime:
    """Naive UTC, matching the DATETIME columns (connections run with time_zone '+00:00')."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class CommandError(RuntimeError):
    def __init__(self, cmd: list[str], code: int, output: str):
        super().__init__(f"{' '.join(cmd)} exited with {code}: {output}")
        self.cmd = cmd
        self.code = code
        self.output = output


def run(cmd: list[str], timeout: int = 60, check: bool = False) -> tuple[int, str]:
    """Runs a command without a shell; returns (exit code, stdout+stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        out = f"{cmd[0]}: not found"
        if check:
            raise CommandError(cmd, 127, out) from None
        return 127, out
    except subprocess.TimeoutExpired:
        out = f"timed out after {timeout}s"
        if check:
            raise CommandError(cmd, 124, out) from None
        return 124, out
    output = "\n".join(part.strip() for part in (proc.stdout, proc.stderr) if part and part.strip())
    log.debug("ran %s -> %s", cmd, proc.returncode)
    if check and proc.returncode != 0:
        raise CommandError(cmd, proc.returncode, output)
    return proc.returncode, output


def write_temp(target: Path, content: str, mode: int = 0o640) -> Path:
    """Writes content to a temporary file next to target (same filesystem, so rename is atomic)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return Path(tmp)


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(target: Path, content: str, mode: int = 0o640) -> None:
    tmp = write_temp(target, content, mode)
    os.replace(tmp, target)
    fsync_dir(target.parent)


def replace_keeping_previous(tmp: Path, target: Path) -> Path | None:
    """Moves tmp over target, keeping the old file as <target>.prev. Returns the .prev path, if any."""
    previous = target.with_name(target.name + ".prev")
    had_previous = target.exists()
    if had_previous:
        # A hard link keeps the old inode without a window where target is missing.
        previous.unlink(missing_ok=True)
        os.link(target, previous)
    os.replace(tmp, target)
    fsync_dir(target.parent)
    return previous if had_previous else None


def restore_previous(target: Path, previous: Path | None) -> None:
    if previous is not None and previous.exists():
        os.replace(previous, target)
    else:
        target.unlink(missing_ok=True)
    fsync_dir(target.parent)
