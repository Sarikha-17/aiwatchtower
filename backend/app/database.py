"""SQLite persistence. The path can be overridden with AIWATCHTOWER_DB (used by tests)."""
import os
import sqlite3
from pathlib import Path

from app.config import REPO_ROOT


def db_path() -> Path:
    return Path(os.getenv("AIWATCHTOWER_DB", REPO_ROOT / "aiwatchtower.db"))


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS traces (
            trace_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            scenario_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            mode TEXT NOT NULL,
            policy_version INTEGER,
            verdict TEXT NOT NULL,
            attack_succeeded INTEGER NOT NULL,
            trace_json TEXT NOT NULL
        )"""
    )
    return conn
