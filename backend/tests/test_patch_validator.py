import copy

from app.services.patch_validator import validate_patch
from app.services.patcher import seeded_patch


def good():
    return seeded_patch(1, "test")


def errors_for(patch, version=1):
    ok, errors = validate_patch(patch, version)
    assert not ok
    return " | ".join(errors)


def test_seeded_patch_is_valid():
    assert validate_patch(good(), 1) == (True, [])


def test_non_dict_rejected():
    assert validate_patch("nope", 1)[0] is False
    assert validate_patch(None, 1)[0] is False


def test_missing_field_rejected():
    p = good(); del p["reasoning"]
    assert "missing required field: reasoning" in errors_for(p)


def test_wrong_target_policy_rejected():
    p = good(); p["target_policy_id"] = "OTHER"
    assert "target_policy_id" in errors_for(p)


def test_stale_base_version_rejected():
    assert "base_policy_version" in errors_for(good(), version=2)


def test_allow_decision_rejected():
    p = good(); p["proposed_decision"] = "allow"
    assert "never 'allow'" in errors_for(p)


def test_review_decision_accepted():
    p = good(); p["proposed_decision"] = "review"
    assert validate_patch(p, 1)[0] is True


def test_allowlisted_true_rejected():
    p = good(); p["proposed_condition"]["recipient_allowlisted"] = True
    assert "recipient_allowlisted" in errors_for(p)


def test_wrong_tool_rejected():
    p = good(); p["proposed_condition"]["tool"] = "hr.file.read"
    assert "email.send" in errors_for(p)


def test_unknown_tags_rejected():
    p = good(); p["proposed_condition"]["attachment_tags_any"] = ["hr_sensitive", "public"]
    assert "tags not allowed" in errors_for(p)


def test_empty_tags_rejected():
    p = good(); p["proposed_condition"]["attachment_tags_any"] = []
    assert "attachment_tags_any" in errors_for(p)


def test_human_approval_must_be_true():
    p = good(); p["requires_human_approval"] = False
    assert "requires_human_approval" in errors_for(p)


def test_out_of_scope_fields_rejected():
    for forbidden in ("code", "model", "agent_prompt", "tools", "permissions", "database_update"):
        p = good(); p[forbidden] = "anything"
        assert "unsupported fields" in errors_for(p), forbidden


def test_unknown_condition_key_rejected():
    p = good(); p["proposed_condition"]["run_shell"] = True
    assert "unsupported condition keys" in errors_for(p)


def test_change_type_other_than_add_condition_rejected():
    p = good(); p["change_type"] = "delete_rule"
    assert "change_type" in errors_for(p)


def test_validator_does_not_mutate_input():
    p = good(); snapshot = copy.deepcopy(p)
    validate_patch(p, 1)
    assert p == snapshot
