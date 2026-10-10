"""Nemotron policy patcher. Only called after an attack succeeded; sees ONLY the failed trace.

Held-out attacks are never shown to the patcher. The patch is advice: it must pass the
deterministic validator, then replay, then explicit human approval.
"""
import json
import uuid

from app.config import get_settings
from app.services import nemotron_client
from app.services.nemotron_client import NemotronError

VOCABULARY = {
    "tools": ["email.send"],
    "condition_keys": ["tool", "recipient_external", "recipient_allowlisted",
                       "attachment_tags_any", "influenced_by_untrusted_content"],
    "attachment_tags": ["hr_sensitive", "employee_compensation"],
    "decisions": ["block", "review"],
}

SYSTEM_PROMPT = """You are a security policy engineer for an AI-agent tool-call firewall.
An attack just succeeded against the active policy. Propose ONE narrow, additive policy patch.

Rules you must follow:
- Return valid JSON only. No prose, no markdown.
- You may only add one condition set for the policy HR_EXTERNAL_SHARE (change_type "add_condition").
- You cannot change agent prompts, models, tools, permissions, database data or code.
- You cannot delete existing rules and you cannot broaden data access.
- proposed_decision must be "block" or "review". requires_human_approval must be true.
- Use only the vocabulary provided. Explain expected security gain and false-positive risk briefly.

Required JSON schema:
{
  "patch_id": "PATCH-<uuid>",
  "target_policy_id": "HR_EXTERNAL_SHARE",
  "base_policy_version": <active version number>,
  "change_type": "add_condition",
  "proposed_condition": {"tool": "email.send", "recipient_external": true, "recipient_allowlisted": false,
                         "attachment_tags_any": [<allowed tags>], "influenced_by_untrusted_content": true},
  "proposed_decision": "block",
  "reasoning": "string",
  "expected_security_gain": "string",
  "expected_false_positive_risk": "string",
  "requires_human_approval": true
}"""


class PatcherError(Exception):
    pass


def _trimmed_trace(trace: dict) -> dict:
    return {
        "scenario_id": trace["scenario_id"], "user_request": trace["user_request"],
        "policy_version": trace["policy_version"], "verdict": trace["verdict"],
        "events": [{
            "tool": e["tool"], "args": e["args"], "rationale": e["rationale"], "executed": e["executed"],
            "decision": {k: e["decision"].get(k) for k in ("decision", "policy_id", "reasons", "labels")},
        } for e in trace["events"]],
        "content_labels": trace["labels"],
    }


def build_messages(failed_trace: dict, active_policy: dict) -> list:
    if str(failed_trace.get("scenario_id", "")).startswith("held_out"):
        raise PatcherError("held-out cases must never be sent to the patcher")
    user = {
        "failed_trace": _trimmed_trace(failed_trace),
        "active_policy": active_policy,
        "allowed_vocabulary": VOCABULARY,
    }
    return [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(user, indent=2)}]


def seeded_patch(active_version: int, note: str) -> dict:
    """Deterministic DEMO-MODE fallback. The UI and README label it clearly as a fallback."""
    return {
        "patch_id": f"PATCH-{uuid.uuid4()}",
        "target_policy_id": "HR_EXTERNAL_SHARE",
        "base_policy_version": active_version,
        "change_type": "add_condition",
        "proposed_condition": {
            "tool": "email.send", "recipient_external": True, "recipient_allowlisted": False,
            "attachment_tags_any": ["hr_sensitive", "employee_compensation"],
            "influenced_by_untrusted_content": True,
        },
        "proposed_decision": "block",
        "reasoning": f"[DEMO FALLBACK: not model-generated. {note}] The attack avoided the keywords but attached "
                     "an HR file tagged as compensation data to a non-allowlisted external address after reading "
                     "untrusted email content. Block on the data tags and destination, not on wording.",
        "expected_security_gain": "Blocks attachment-based HR data exfiltration regardless of message wording.",
        "expected_false_positive_risk": "Legitimate sends of tagged HR files to non-allowlisted external parties "
                                        "(for example an external auditor) will be blocked until allowlisted.",
        "requires_human_approval": True,
    }


def propose_patch(failed_trace: dict, active_policy: dict, transport=None) -> dict:
    """Returns {'patch': dict|None, 'raw_text': str|None, 'meta': {...}}.

    Raises PatcherError if no model is reachable and DEMO_MODE is off.
    """
    settings = get_settings()
    messages = build_messages(failed_trace, active_policy)
    version = active_policy["version"]
    meta = {"model_role": "super", "model_id": settings.super_model or None, "latency_ms": None,
            "prompt_tokens": None, "completion_tokens": None, "estimated_cost_usd": None,
            "demo_fallback": False, "fallback_reason": None}

    roles = ["super"] + (["ultra"] if settings.ultra_model else [])
    last_error = None
    for role in roles:
        try:
            out = nemotron_client.chat_json(role, messages, settings, transport=transport)
        except NemotronError as exc:
            last_error = str(exc)
            continue
        meta.update({k: out[k] for k in ("model_role", "latency_ms", "prompt_tokens",
                                         "completion_tokens", "estimated_cost_usd")})
        meta["model_id"] = out["model"]
        patch = out["parsed"]
        if isinstance(patch, dict):
            patch["patch_id"] = f"PATCH-{uuid.uuid4()}"  # server-assigned: never trust a model-chosen ID
        return {"patch": patch, "raw_text": None if patch else out["text"][:2000], "meta": meta}

    if settings.demo_mode:
        meta.update({"demo_fallback": True, "fallback_reason": last_error, "model_role": "none"})
        return {"patch": seeded_patch(version, f"Model API unavailable: {last_error}"), "raw_text": None, "meta": meta}
    raise PatcherError(
        f"Nemotron is unavailable ({last_error}). Set NEBIUS_API_KEY and NEMOTRON_SUPER_MODEL in .env, "
        "or set DEMO_MODE=true to use the clearly labeled seeded patch."
    )
