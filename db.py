"""SQLite database module (stdlib sqlite3, zero dependencies).

Owns the connection, schema, and daily backups. Mirrors the structure of
weighbridge-data-entry/db.js so the two apps are operated the same way,
even though this one is Python (Debian ships Python 3 out of the box;
Node here would have needed a separate install to get node:sqlite's
22.5+ requirement).
"""

import os
import shutil
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
BACKUP_KEEP_DAYS = int(os.environ.get("CLOCK_BACKUP_KEEP_DAYS", "14"))

_lock = threading.Lock()
_connection = None
_db_path = None


def resolve_database_path() -> Path:
    env_path = os.environ.get("CLOCK_DASHBOARD_DB", "").strip()
    if env_path:
        return Path(env_path).resolve()
    return DATA_DIR / "timeclock.db"


def get_db() -> sqlite3.Connection:
    """Thread-safe singleton connection. Callers must hold `lock()` while using it."""
    global _connection, _db_path
    resolved = resolve_database_path()
    if _connection is None or _db_path != resolved:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        _connection = sqlite3.connect(str(resolved), check_same_thread=False)
        _connection.row_factory = sqlite3.Row
        _db_path = resolved
        _connection.executescript(
            """
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 500;
            PRAGMA temp_store = MEMORY;
            PRAGMA cache_size = -8000;
            """
        )
        _ensure_schema(_connection)
    return _connection


def lock():
    """Serializes DB access across request-handling threads."""
    return _lock


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            employee_number TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );

        CREATE UNIQUE INDEX IF NOT EXISTS ux_employees_number
            ON employees(employee_number);

        CREATE TABLE IF NOT EXISTS time_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL REFERENCES employees(id),
            clock_in_utc TEXT NOT NULL,
            lunch_out_utc TEXT,
            lunch_in_utc TEXT,
            clock_out_utc TEXT,
            note TEXT,
            edited INTEGER NOT NULL DEFAULT 0,
            created_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );

        CREATE INDEX IF NOT EXISTS ix_time_entries_employee
            ON time_entries(employee_id);

        CREATE INDEX IF NOT EXISTS ix_time_entries_clock_in
            ON time_entries(clock_in_utc);

        CREATE UNIQUE INDEX IF NOT EXISTS ux_time_entries_open
            ON time_entries(employee_id)
            WHERE clock_out_utc IS NULL;
        """
    )
    # Migrate older DBs that only had clock_in / clock_out
    cols = {row[1] for row in conn.execute("PRAGMA table_info(time_entries);").fetchall()}
    if "lunch_out_utc" not in cols:
        conn.execute("ALTER TABLE time_entries ADD COLUMN lunch_out_utc TEXT;")
    if "lunch_in_utc" not in cols:
        conn.execute("ALTER TABLE time_entries ADD COLUMN lunch_in_utc TEXT;")
    conn.commit()


def db_stats(conn: sqlite3.Connection) -> dict:
    def count(sql):
        try:
            return conn.execute(sql).fetchone()[0]
        except sqlite3.Error:
            return None

    return {
        "employees": count("SELECT COUNT(*) FROM employees"),
        "entries": count("SELECT COUNT(*) FROM time_entries"),
        "openEntries": count("SELECT COUNT(*) FROM time_entries WHERE clock_out_utc IS NULL"),
    }


def _backup_dir_for(db_file: Path) -> Path:
    return db_file.parent / "backups"


def _prune_old_backups(backup_dir: Path) -> list:
    keep = BACKUP_KEEP_DAYS if BACKUP_KEEP_DAYS > 0 else 14
    names = sorted(
        [f.name for f in backup_dir.glob("timeclock-*.db") if len(f.stem) == len("timeclock-YYYY-MM-DD")],
        reverse=True,
    )
    removed = []
    for name in names[keep:]:
        try:
            (backup_dir / name).unlink()
            removed.append(name)
        except OSError:
            pass
    return removed


def run_db_backup(force: bool = False) -> dict:
    """Fast on-disk backup: WAL checkpoint + file copy. Skips if latest.db is <6h old."""
    try:
        with _lock:
            conn = get_db()
            db_file = resolve_database_path()
            backup_dir = _backup_dir_for(db_file)
            backup_dir.mkdir(parents=True, exist_ok=True)

            latest = backup_dir / "latest.db"
            if not force and latest.exists():
                age_seconds = datetime.now(timezone.utc).timestamp() - latest.stat().st_mtime
                if age_seconds < 6 * 3600:
                    return {"ok": True, "skipped": True, "reason": "fresh", "latest": str(latest)}

            stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            dest = backup_dir / f"timeclock-{stamp}.db"
            tmp = backup_dir / f".tmp-backup-{os.getpid()}.db"

            try:
                conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
            except sqlite3.Error:
                pass
            shutil.copyfile(db_file, tmp)
            tmp.replace(dest)
            try:
                shutil.copyfile(dest, latest)
            except OSError:
                pass
            for side in (f"{dest}-wal", f"{dest}-shm", f"{latest}-wal", f"{latest}-shm"):
                try:
                    Path(side).unlink()
                except OSError:
                    pass

            removed = _prune_old_backups(backup_dir)
            return {
                "ok": True,
                "dest": str(dest),
                "latest": str(latest),
                "size": dest.stat().st_size,
                "stats": db_stats(conn),
                "pruned": removed,
            }
    except Exception as err:  # noqa: BLE001 - report to caller instead of crashing
        return {"ok": False, "error": str(err)}
