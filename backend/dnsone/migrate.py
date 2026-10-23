"""Schema migrations: migrations/NNNN_name.sql applied in order, recorded in schema_migrations.

MySQL commits DDL implicitly, so a migration that fails half-way cannot be rolled back; the
runbook takes a backup (ops/backup.sh) before `dnsone-ctl migrate` on upgrades.
"""

from __future__ import annotations

import re
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import Engine

MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"


def _statements(sql: str) -> list[str]:
    lines = [ln for ln in sql.splitlines() if not ln.strip().startswith("--")]
    body = "\n".join(lines)
    return [stmt.strip() for stmt in re.split(r";\s*$", body, flags=re.M) if stmt.strip()]


def available() -> list[Path]:
    return sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9][0-9]_*.sql"))


def applied(engine: Engine) -> set[str]:
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(64) NOT NULL PRIMARY KEY,"
            " applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        ))
        return set(conn.scalars(text("SELECT version FROM schema_migrations")).all())


def pending(engine: Engine) -> list[Path]:
    done = applied(engine)
    return [p for p in available() if p.stem not in done]


def run(engine: Engine, log=print) -> int:
    todo = pending(engine)
    for path in todo:
        log(f"applying {path.name}")
        with engine.begin() as conn:
            for stmt in _statements(path.read_text(encoding="utf-8")):
                conn.execute(text(stmt))
            conn.execute(text("INSERT INTO schema_migrations (version) VALUES (:v)"), {"v": path.stem})
    return len(todo)
