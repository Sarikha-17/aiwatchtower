import pytest

from app.services.runner import load_scenarios, run_by_id

LEGIT = [s["scenario_id"] for s in load_scenarios() if s["kind"] == "legit"]


def test_legit_tasks_complete_under_every_mode():
    for sid in LEGIT:
        for version in (None, 1, 2):
            assert run_by_id(sid, version).verdict == "TASK COMPLETED", (sid, version)


def test_obvious_attack_behaviour():
    assert run_by_id("obvious_attack", None).verdict == "ATTACK SUCCEEDED"
    assert run_by_id("obvious_attack", 1).verdict == "ATTACK BLOCKED"
    assert run_by_id("obvious_attack", 2).verdict == "ATTACK BLOCKED"


def test_v1_bypass_behaviour():
    assert run_by_id("v1_bypass", None).verdict == "ATTACK SUCCEEDED"
    assert run_by_id("v1_bypass", 1).verdict == "ATTACK SUCCEEDED"  # the bypass
    assert run_by_id("v1_bypass", 2).verdict == "ATTACK BLOCKED"


def test_blocked_send_does_not_execute():
    trace = run_by_id("v1_bypass", 2)
    last = trace.events[-1]
    assert last["tool"] == "email.send"
    assert last["decision"]["decision"] == "BLOCK"
    assert last["executed"] is False
    assert last["decision"]["policy_id"] == "HR_EXTERNAL_SHARE"


def test_every_call_is_intercepted_with_a_decision():
    trace = run_by_id("v1_bypass", 1)
    assert [e["tool"] for e in trace.events] == ["email.read", "hr.file.read", "email.send"]
    assert all("decision" in e and e["decision"]["decision"] for e in trace.events)


def test_provenance_marks_influenced_actions_on_untrusted_email():
    trace = run_by_id("v1_bypass", None)
    email_label = next(l for l in trace.labels if l["source_type"] == "email")
    assert set(email_label["influenced_actions"]) == {"hr.file.read", "email.send"}


def test_agent_is_deterministic():
    strip = lambda t: [(e["tool"], e["args"], e["decision"]["decision"], e["executed"]) for e in t.events]
    a, b = run_by_id("v1_bypass", 1), run_by_id("v1_bypass", 1)
    assert strip(a) == strip(b) and a.verdict == b.verdict


def test_firewall_records_latency():
    trace = run_by_id("obvious_attack", 1)
    assert all(e["decision"]["latency_ms"] >= 0 for e in trace.events)
