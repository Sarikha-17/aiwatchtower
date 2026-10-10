"""Versioned policy store (SQLite) with an append-only history log."""
import json
from datetime import datetime, timezone

from app.config import POLICY_DIR
from app.database import get_conn
from app.services.policy_engine import load_policy


class PolicyStoreError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(conn, actor, action, from_v, to_v, patch_id=None, note=None):
    conn.execute(
        "INSERT INTO policy_history (ts, actor, action, from_version, to_version, patch_id, note) VALUES (?,?,?,?,?,?,?)",
        (_now(), actor, action, from_v, to_v, patch_id, note),
    )


def _ensure_seed(conn) -> None:
    if conn.execute("SELECT COUNT(*) FROM policy_versions").fetchone()[0] == 0:
        policy = load_policy(POLICY_DIR / "policy_v1.yaml")
        conn.execute(
            "INSERT INTO policy_versions VALUES (?,?,?,?,?,?)",
            (policy["version"], json.dumps(policy), "active", _now(), "seed", None),
        )
        _log(conn, "system", "seed", None, policy["version"], None, "Initial weak keyword policy")
        conn.commit()


def get_active() -> dict:
    with get_conn() as conn:
        _ensure_seed(conn)
        row = conn.execute("SELECT policy_json FROM policy_versions WHERE status='active'").fetchone()
    return json.loads(row["policy_json"])


def get_policy(version: int) -> dict | None:
    with get_conn() as conn:
        _ensure_seed(conn)
        row = conn.execute("SELECT policy_json FROM policy_versions WHERE version=?", (version,)).fetchone()
    return json.loads(row["policy_json"]) if row else None


def next_version() -> int:
    with get_conn() as conn:
        _ensure_seed(conn)
        return conn.execute("SELECT MAX(version) FROM policy_versions").fetchone()[0] + 1


def list_versions() -> list:
    with get_conn() as conn:
        _ensure_seed(conn)
        rows = conn.execute(
            "SELECT version, status, created_at, approved_by, patch_id, policy_json FROM policy_versions ORDER BY version"
        ).fetchall()
    return [{**{k: r[k] for k in ("version", "status", "created_at", "approved_by", "patch_id")},
             "policy": json.loads(r["policy_json"])} for r in rows]


def list_history() -> list:
    with get_conn() as conn:
        _ensure_seed(conn)
        rows = conn.execute("SELECT * FROM policy_history ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def activate_new_version(policy: dict, patch_id: str, actor: str) -> dict:
    """Store an approved candidate as the new active version; the old one becomes 'previous'."""
    with get_conn() as conn:
        _ensure_seed(conn)
        current = conn.execute("SELECT version FROM policy_versions WHERE status='active'").fetchone()["version"]
        if conn.execute("SELECT 1 FROM policy_versions WHERE version=?", (policy["version"],)).fetchone():
            raise PolicyStoreError(f"version {policy['version']} already exists")
        conn.execute("UPDATE policy_versions SET status='previous' WHERE status='active'")
        conn.execute(
            "INSERT INTO policy_versions VALUES (?,?,?,?,?,?)",
            (policy["version"], json.dumps(policy), "active", _now(), actor, patch_id),
        )
        _log(conn, actor, "approve", current, policy["version"], patch_id, "Patch approved and activated")
        conn.commit()
    return policy


def rollback(version: int, actor: str) -> dict:
    """Restore a previously stored policy version as the active one."""
    with get_conn() as conn:
        _ensure_seed(conn)
        target = conn.execute("SELECT policy_json, status FROM policy_versions WHERE version=?", (version,)).fetchone()
        if target is None:
            raise PolicyStoreError(f"policy version {version} does not exist")
        if target["status"] == "active":
            raise PolicyStoreError(f"policy version {version} is already active")
        current = conn.execute("SELECT version FROM policy_versions WHERE status='active'").fetchone()["version"]
        conn.execute("UPDATE policy_versions SET status='rolled_back' WHERE status='active'")
        conn.execute("UPDATE policy_versions SET status='active' WHERE version=?", (version,))
        _log(conn, actor, "rollback", current, version, None, "Rolled back to a prior version")
        conn.commit()
    return json.loads(target["policy_json"])


def log_event(actor: str, action: str, patch_id: str | None, note: str | None) -> None:
    with get_conn() as conn:
        _ensure_seed(conn)
        active = conn.execute("SELECT version FROM policy_versions WHERE status='active'").fetchone()["version"]
        _log(conn, actor, action, active, active, patch_id, note)
        conn.commit()
