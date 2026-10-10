"""Deterministic validation of model-proposed policy patches. The model never bypasses this."""

REQUIRED = [
    "patch_id", "target_policy_id", "base_policy_version", "change_type", "proposed_condition",
    "proposed_decision", "reasoning", "expected_security_gain", "expected_false_positive_risk",
    "requires_human_approval",
]
ALLOWED_TOP = set(REQUIRED)  # anything else (code, models, prompts, tools, permissions...) is rejected
ALLOWED_COND = {"tool", "recipient_external", "recipient_allowlisted", "attachment_tags_any",
                "influenced_by_untrusted_content"}
ALLOWED_TAGS = {"hr_sensitive", "employee_compensation"}
TARGET_POLICY = "HR_EXTERNAL_SHARE"


def validate_patch(patch, active_version: int) -> tuple:
    """Returns (ok, errors)."""
    errors = []
    if not isinstance(patch, dict):
        return False, ["patch is not a JSON object"]
    for key in REQUIRED:
        if key not in patch:
            errors.append(f"missing required field: {key}")
    extra = sorted(set(patch) - ALLOWED_TOP)
    if extra:
        errors.append(f"unsupported fields (patches may only change the policy rule): {extra}")
    if errors and any(e.startswith("missing") for e in errors):
        return False, errors

    if patch["target_policy_id"] != TARGET_POLICY:
        errors.append(f"target_policy_id must be {TARGET_POLICY}")
    if patch["base_policy_version"] != active_version or isinstance(patch["base_policy_version"], bool):
        errors.append(f"base_policy_version must equal the active version ({active_version})")
    if patch["change_type"] != "add_condition":
        errors.append("change_type must be 'add_condition'")
    if patch["proposed_decision"] not in ("block", "review"):
        errors.append("proposed_decision must be 'block' or 'review', never 'allow'")
    if patch["requires_human_approval"] is not True:
        errors.append("requires_human_approval must be true")
    for key in ("reasoning", "expected_security_gain", "expected_false_positive_risk"):
        if not isinstance(patch[key], str) or not patch[key].strip():
            errors.append(f"{key} must be a non-empty string")

    cond = patch["proposed_condition"]
    if not isinstance(cond, dict):
        errors.append("proposed_condition must be an object")
        return False, errors
    unknown = sorted(set(cond) - ALLOWED_COND)
    if unknown:
        errors.append(f"unsupported condition keys: {unknown}")
    if cond.get("tool") != "email.send":
        errors.append("condition tool must be 'email.send'")
    if cond.get("recipient_external") is not True:
        errors.append("condition recipient_external must be true")
    if cond.get("recipient_allowlisted") is not False:
        errors.append("condition recipient_allowlisted must be false")
    tags = cond.get("attachment_tags_any")
    if not isinstance(tags, list) or not tags:
        errors.append("condition attachment_tags_any must be a non-empty list")
    elif not set(tags) <= ALLOWED_TAGS:
        errors.append(f"attachment tags not allowed: {sorted(set(map(str, tags)) - ALLOWED_TAGS)}")
    if "influenced_by_untrusted_content" in cond and not isinstance(cond["influenced_by_untrusted_content"], bool):
        errors.append("influenced_by_untrusted_content must be a boolean")
    return (not errors), errors
