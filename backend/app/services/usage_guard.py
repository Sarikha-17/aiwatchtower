"""Daily cap on real model calls, so a public demo cannot burn through the API credit.

0 means unlimited (the default for local use). When the cap is reached the patcher uses the clearly
labeled demo fallback (if DEMO_MODE=true) or fails honestly. The counter survives demo resets.
"""
from datetime import datetime, timezone

from app.config import get_settings
from app.database import get_conn


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def calls_today() -> int:
    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM model_calls WHERE day=?", (_today(),)).fetchone()[0]


def allow_call(role: str) -> bool:
    """Record one call and return True, or return False if today's cap is already used up."""
    cap = get_settings().max_model_calls_per_day
    if cap > 0 and calls_today() >= cap:
        return False
    with get_conn() as conn:
        conn.execute("INSERT INTO model_calls (ts, day, role) VALUES (?,?,?)",
                     (datetime.now(timezone.utc).isoformat(), _today(), role))
        conn.commit()
    return True
