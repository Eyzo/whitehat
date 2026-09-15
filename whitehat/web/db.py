"""Persistance SQLite des scans (thread-safe)."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

DB_PATH = Path(os.environ.get("WHITEHAT_DB",
                              os.path.expanduser("~/.local/share/whitehat/scans.db")))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    options     TEXT NOT NULL,
    status      TEXT NOT NULL,      -- queued | running | done | error
    stage       TEXT,
    pct         INTEGER DEFAULT 0,
    message     TEXT,
    summary     TEXT,               -- json compteurs (pour la liste)
    result      TEXT,               -- json ScanResult complet
    error       TEXT,
    created_at  REAL NOT NULL,
    finished_at REAL
);
"""


class DB:
    def __init__(self, path: Path = DB_PATH):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def create(self, scan_id: str, target: str, options: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO scans (id,target,options,status,pct,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (scan_id, target, json.dumps(options), "queued", 0, time.time()))
            self._conn.commit()

    def update_progress(self, scan_id: str, status: str, stage: str,
                        pct: int, message: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET status=?, stage=?, pct=?, message=? WHERE id=?",
                (status, stage, pct, message, scan_id))
            self._conn.commit()

    def finish(self, scan_id: str, result: dict, summary: dict) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET status='done', pct=100, stage='done', "
                "result=?, summary=?, finished_at=? WHERE id=?",
                (json.dumps(result), json.dumps(summary), time.time(), scan_id))
            self._conn.commit()

    def fail(self, scan_id: str, error: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET status='error', error=?, finished_at=? WHERE id=?",
                (error, time.time(), scan_id))
            self._conn.commit()

    def get(self, scan_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return _row_to_dict(row) if row else None

    def list(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id,target,status,stage,pct,message,summary,created_at,finished_at "
                "FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [_row_to_dict(r) for r in rows]

    def delete(self, scan_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
            self._conn.commit()


def _row_to_dict(row: sqlite3.Row) -> dict:
    d: dict[str, Any] = dict(row)
    for k in ("options", "summary", "result"):
        if k in d and d[k]:
            try:
                d[k] = json.loads(d[k])
            except (json.JSONDecodeError, TypeError):
                pass
    return d
