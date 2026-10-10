"""SQLite persistence. The path can be overridden with AIWATCHTOWER_DB (used by tests)."""
import os
import sqlite3
from pathlib import Path

from app.config import REPO_ROOT

SCHEMA = """
CREATE TABLE IF NOT EXISTS traces (
    trace_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, scenario_id TEXT NOT NULL,
    kind TEXT NOT NULL, mode TEXT NOT NULL, policy_version INTEGER, verdict TEXT NOT NULL,
    attack_succeeded INTEGER NOT NULL, trace_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_versions (
    version INTEGER PRIMARY KEY, policy_json TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL, approved_by TEXT, patch_id TEXT
);
CREATE TABLE IF NOT EXISTS patches (
    patch_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, status TEXT NOT NULL,
    base_version INTEGER, source_trace_id TEXT, patch_json TEXT, validation_json TEXT,
    replay_json TEXT, meta_json TEXT, rejection_reason TEXT
);
CREATE TABLE IF NOT EXISTS policy_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
    action TEXT NOT NULL, from_version INTEGER, to_version INTEGER, patch_id TEXT, note TEXT
);
"""


def db_path() -> Path:
    return Path(os.getenv("AIWATCHTOWER_DB", REPO_ROOT / "aiwatchtower.db"))


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn
