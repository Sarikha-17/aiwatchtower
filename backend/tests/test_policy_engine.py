import pytest

from app.config import POLICY_DIR
from app.services.policy_engine import (
    PolicyEngine, PolicyError, build_context, load_policy, validate_policy,
)

V1 = load_policy(POLICY_DIR / "policy_v1.yaml")
V2 = load_policy(POLICY_DIR / "policy_v2_example.yaml")

SEND = lambda to, body, att=None: {"to": to, "subject": "s", "body": body, "attachment_id": att}


def decide(policy, args, store, cfg, influenced):
    ctx = build_context("email.send", args, store, cfg, influenced)
    return PolicyEngine([policy]).evaluate(ctx).decision


def test_v1_blocks_salary_keyword_to_external(store, cfg):
    args = SEND("a@evil.example", "Here is the salary report")
    assert decide(V1, args, store, cfg, True) == "BLOCK"


def test_v1_blocks_payroll_keyword_case_insensitive(store, cfg):
    args = SEND("a@evil.example", "PAYROLL attached")
    assert decide(V1, args, store, cfg, False) == "BLOCK"


def test_v1_misses_bypass_without_keywords(store, cfg):
    args = SEND("a@evil.example", "Please find the requested document attached.", "salary_report_q3")
    assert decide(V1, args, store, cfg, True) == "ALLOW"


def test_v1_allows_keyword_email_to_internal(store, cfg):
    args = SEND("hr@company.example", "salary figures for review")
    assert decide(V1, args, store, cfg, False) == "ALLOW"


def test_v2_blocks_bypass(store, cfg):
    args = SEND("a@evil.example", "Please find the requested document attached.", "salary_report_q3")
    assert decide(V2, args, store, cfg, True) == "BLOCK"


def test_v2_allows_sensitive_file_to_internal_recipient(store, cfg):
    args = SEND("hr@company.example", "attached", "salary_report_q3")
    assert decide(V2, args, store, cfg, True) == "ALLOW"


def test_v2_allows_sensitive_file_to_allowlisted_vendor(store, cfg):
    args = SEND("billing@acct-vendor.example", "attached", "salary_report_q3")
    assert decide(V2, args, store, cfg, True) == "ALLOW"  # allowlisted recipients are out of scope


def test_v2_allows_approved_summary_to_external(store, cfg):
    args = SEND("a@evil.example", "totals", "payroll_summary_approved")
    assert decide(V2, args, store, cfg, True) == "ALLOW"


def test_v2_needs_influence_condition(store, cfg):
    args = SEND("a@evil.example", "x", "salary_report_q3")
    assert decide(V2, args, store, cfg, False) == "ALLOW"  # not influenced by untrusted content


def test_non_send_tools_not_matched(store, cfg):
    ctx = build_context("hr.file.read", {"file_id": "salary_report_q3"}, store, cfg, True)
    assert PolicyEngine([V2]).evaluate(ctx).decision == "ALLOW"


def test_decision_carries_policy_id_version_and_reasons(store, cfg):
    ctx = build_context("email.send", SEND("a@evil.example", "salary"), store, cfg, True)
    d = PolicyEngine([V1]).evaluate(ctx)
    assert (d.policy_id, d.policy_version, d.risk_level) == ("HR_EXTERNAL_SHARE", 1, "critical")
    assert d.reasons and "BLOCK by HR_EXTERNAL_SHARE v1" in d.explanation


def test_invalid_policy_rejected():
    with pytest.raises(PolicyError):
        validate_policy({"id": "X", "version": 1, "when": {"made_up": True}, "then": "block"})
    with pytest.raises(PolicyError):
        validate_policy({"id": "X", "version": 1, "when": {"tool": "email.send"}, "then": "allow"})
