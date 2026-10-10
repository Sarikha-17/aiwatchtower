"""Stores complete traces (every event, decision and label) in SQLite."""
import json
from datetime import datetime, timezone

from app.database import get_conn


def save_trace(trace) -> None:
    data = trace.to_dict() if hasattr(trace, "to_dict") else trace
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO traces VALUES (?,?,?,?,?,?,?,?,?)",
            (
                data["trace_id"], datetime.now(timezone.utc).isoformat(),
                data["scenario_id"], data["kind"], data["mode"], data["policy_version"],
                data["verdict"], int(data["attack_succeeded"]), json.dumps(data),
            ),
        )


def list_traces(limit: int = 50) -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT trace_id, created_at, scenario_id, kind, mode, verdict "
            "FROM traces ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_trace(trace_id: str):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT trace_json FROM traces WHERE trace_id = ?", (trace_id,)
        ).fetchone()
    return json.loads(row["trace_json"]) if row else None
