"""Orchestrates the patch lifecycle: propose -> validate -> replay -> human approve/reject -> activate/rollback.

Candidate patches never activate automatically.
"""
import json
from datetime import datetime, timezone

from app.config import load_domain_config
from app.database import get_conn
from app.services import patcher, patch_validator, policy_store, replay_engine, trace_recorder
from app.services.policy_engine import rules_of

ACTOR = load_domain_config().demo_user  # fixed demo user, no auth in the MVP


class ServiceError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_candidate(active: dict, patch: dict, new_version: int) -> dict:
    """Additive: keep every existing rule and append the patch's rule as a new version."""
    base_rules = []
    for i, r in enumerate(rules_of(active)):
        base_rules.append({"name": r["name"] or f"base_rule_v{active['version']}", "when": r["when"],
                           "then": r["then"], "severity": r["severity"]})
    new_rule = {"name": f"patch_{patch['patch_id']}", "when": patch["proposed_condition"],
                "then": patch["proposed_decision"], "severity": "critical"}
    return {
        "id": active["id"], "version": new_version,
        "description": f"{active.get('description', '')} + patch {patch['patch_id']}".strip(),
        "dpdp_tags": active.get("dpdp_tags", []), "derived_from_patch": patch["patch_id"],
        "rules": base_rules + [new_rule],
    }


def _row_to_patch(row) -> dict:
    j = lambda x: json.loads(x) if x else None
    return {
        "patch_id": row["patch_id"], "created_at": row["created_at"], "status": row["status"],
        "base_version": row["base_version"], "source_trace_id": row["source_trace_id"],
        "patch": j(row["patch_json"]), "validation": j(row["validation_json"]),
        "replay": j(row["replay_json"]), "meta": j(row["meta_json"]),
        "rejection_reason": row["rejection_reason"],
    }


def get_patch(patch_id: str) -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM patches WHERE patch_id=?", (patch_id,)).fetchone()
    if row is None:
        raise ServiceError(404, "patch not found")
    return _row_to_patch(row)


def _save(patch_id, **fields) -> None:
    cols = ", ".join(f"{k}=?" for k in fields)
    with get_conn() as conn:
        conn.execute(f"UPDATE patches SET {cols} WHERE patch_id=?", (*fields.values(), patch_id))
        conn.commit()


def propose(trace_id: str, transport=None) -> dict:
    trace = trace_recorder.get_trace(trace_id)
    if trace is None:
        raise ServiceError(404, "trace not found")
    active = policy_store.get_active()
    if trace["kind"] != "attack" or not trace["attack_succeeded"]:
        raise ServiceError(409, "A patch is only proposed after an attack succeeded. Pick a trace whose verdict is ATTACK SUCCEEDED.")
    if trace["scenario_id"].startswith("held_out"):
        raise ServiceError(409, "held-out cases are never used for patching")
    if trace["policy_version"] != active["version"]:
        raise ServiceError(409, f"This trace ran under policy v{trace['policy_version']}, not the active policy v{active['version']}. "
                                "Run the attack under the active policy first.")
    try:
        result = patcher.propose_patch(trace, active, transport=transport)
    except patcher.PatcherError as exc:
        raise ServiceError(502, str(exc)) from exc

    patch = result["patch"]
    ok, errors = patch_validator.validate_patch(patch, active["version"])
    if patch is None:
        errors = ["model output was not valid JSON"] + errors
    patch_id = (patch or {}).get("patch_id") or f"PATCH-INVALID-{int(datetime.now().timestamp() * 1000)}"
    status = "validated" if ok else "rejected_invalid"
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO patches (patch_id, created_at, status, base_version, source_trace_id, patch_json, validation_json, meta_json) VALUES (?,?,?,?,?,?,?,?)",
            (patch_id, _now(), status, active["version"], trace_id,
             json.dumps(patch if patch else {"raw_model_output": result["raw_text"]}),
             json.dumps({"ok": ok, "errors": errors}), json.dumps(result["meta"])),
        )
        conn.commit()
    policy_store.log_event(ACTOR, "propose" if ok else "propose_invalid", patch_id,
                           "demo fallback" if result["meta"]["demo_fallback"] else f"model {result['meta']['model_id']}")
    return get_patch(patch_id)


def validate(patch_id: str) -> dict:
    rec = get_patch(patch_id)
    active = policy_store.get_active()
    ok, errors = patch_validator.validate_patch(rec["patch"], active["version"])
    _save(patch_id, validation_json=json.dumps({"ok": ok, "errors": errors}),
          status="validated" if ok else "rejected_invalid")
    return get_patch(patch_id)


def _require_ready(rec: dict, active: dict) -> None:
    if rec["status"] not in ("validated",):
        raise ServiceError(409, f"patch status is '{rec['status']}', expected 'validated'")
    if rec["patch"]["base_policy_version"] != active["version"]:
        raise ServiceError(409, "patch is stale: the active policy changed since it was proposed")


def replay(patch_id: str) -> dict:
    rec = get_patch(patch_id)
    active = policy_store.get_active()
    _require_ready(rec, active)
    candidate = build_candidate(active, rec["patch"], policy_store.next_version())
    metrics = replay_engine.replay_candidate(active, candidate)
    metrics["rule_diff"] = {
        "before_rules": [{"name": r["name"] or "base_rule", "when": r["when"], "then": r["then"]} for r in rules_of(active)],
        "added_rule": next(r for r in candidate["rules"] if r["name"].startswith("patch_")),
    }
    _save(patch_id, replay_json=json.dumps(metrics))
    return get_patch(patch_id)


def approve(patch_id: str) -> dict:
    rec = get_patch(patch_id)
    active = policy_store.get_active()
    _require_ready(rec, active)
    if not rec["replay"]:
        raise ServiceError(409, "Run replay before approving: a patch needs tested evidence.")
    candidate = build_candidate(active, rec["patch"], policy_store.next_version())
    policy_store.activate_new_version(candidate, patch_id, ACTOR)
    _save(patch_id, status="approved")
    return {"active_policy": policy_store.get_active(), "patch": get_patch(patch_id)}


def reject(patch_id: str, reason: str | None) -> dict:
    rec = get_patch(patch_id)
    if rec["status"] in ("approved", "rejected"):
        raise ServiceError(409, f"patch is already {rec['status']}")
    _save(patch_id, status="rejected", rejection_reason=(reason or "").strip() or None)
    policy_store.log_event(ACTOR, "reject", patch_id, (reason or "").strip() or "no reason given")
    return get_patch(patch_id)


def rollback(version: int) -> dict:
    try:
        return policy_store.rollback(version, ACTOR)
    except policy_store.PolicyStoreError as exc:
        raise ServiceError(409, str(exc)) from exc
