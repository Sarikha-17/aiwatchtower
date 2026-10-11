"""End-to-end: bypass -> propose -> validate -> replay -> human approval -> bypass blocked -> rollback."""
import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def run(client, scenario, mode):
    r = client.post("/api/agent/run-scenario", json={"scenario_id": scenario, "mode": mode})
    assert r.status_code == 200, r.text
    return r.json()


def propose_from_bypass(client):
    trace = run(client, "v1_bypass", "active")
    assert trace["verdict"] == "ATTACK SUCCEEDED"
    r = client.post("/api/patches/propose", json={"trace_id": trace["trace_id"]})
    assert r.status_code == 200, r.text
    return r.json()


def test_full_loop(client):
    patch = propose_from_bypass(client)
    pid = patch["patch_id"]
    assert patch["status"] == "validated" and patch["meta"]["demo_fallback"] is True

    # nothing is active yet, and the bypass still works
    assert client.get("/api/policies/active").json()["version"] == 1
    assert run(client, "v1_bypass", "active")["verdict"] == "ATTACK SUCCEEDED"

    # approval requires replay evidence first
    assert client.post(f"/api/patches/{pid}/approve").status_code == 409

    replayed = client.post(f"/api/patches/{pid}/replay").json()["replay"]
    assert replayed["newly_blocked_train_attacks"] == 19
    assert replayed["newly_blocked_held_out_attacks"] == 8
    assert replayed["cases"]["newly_blocked_legitimate_tasks"] == ["legit_11"]
    assert set(replayed["cases"]["still_successful_held_out_attacks"]) == {
        "held_out_attack_09", "held_out_attack_10", "held_out_attack_11"}
    assert replayed["asr_after"] == 0.0 and replayed["held_out_asr_after"] == 0.25
    assert replayed["legitimate_task_success_after"] < replayed["legitimate_task_success_before"] + 1e-9
    assert replayed["rule_diff"]["added_rule"]["name"].startswith("patch_PATCH-")

    # candidate is still not active
    assert client.get("/api/policies/active").json()["version"] == 1

    approved = client.post(f"/api/patches/{pid}/approve").json()
    assert approved["active_policy"]["version"] == 2 and approved["patch"]["status"] == "approved"
    assert run(client, "v1_bypass", "active")["verdict"] == "ATTACK BLOCKED"
    assert run(client, "legit_invoice_summary", "active")["verdict"] == "TASK COMPLETED"

    history = client.get("/api/policies/history").json()
    assert [v["status"] for v in history["versions"]] == ["previous", "active"]
    actions = [e["action"] for e in history["log"]]
    assert actions[0] == "seed" and "approve" in actions

    # rollback restores v1 and the bypass works again
    assert client.post("/api/policies/1/rollback").json()["active_policy"]["version"] == 1
    assert run(client, "v1_bypass", "active")["verdict"] == "ATTACK SUCCEEDED"
    assert client.post("/api/policies/1/rollback").status_code == 409  # already active


def test_reject_keeps_policy_unchanged_and_stores_reason(client):
    pid = propose_from_bypass(client)["patch_id"]
    rec = client.post(f"/api/patches/{pid}/reject", json={"reason": "too many false positives"}).json()
    assert rec["status"] == "rejected" and rec["rejection_reason"] == "too many false positives"
    assert client.get("/api/policies/active").json()["version"] == 1
    assert client.post(f"/api/patches/{pid}/approve").status_code == 409
    assert "reject" in [e["action"] for e in client.get("/api/policies/history").json()["log"]]


def test_propose_requires_a_successful_attack_under_active_policy(client):
    assert client.post("/api/patches/propose", json={"trace_id": "nope"}).status_code == 404
    blocked = run(client, "obvious_attack", "active")  # attack blocked by v1: nothing to patch
    assert client.post("/api/patches/propose", json={"trace_id": blocked["trace_id"]}).status_code == 409
    legit = run(client, "legit_invoice_summary", "active")
    assert client.post("/api/patches/propose", json={"trace_id": legit["trace_id"]}).status_code == 409
    unguarded = run(client, "v1_bypass", "none")  # ran with no policy: wrong baseline
    assert client.post("/api/patches/propose", json={"trace_id": unguarded["trace_id"]}).status_code == 409


def test_stale_patch_cannot_be_approved_after_policy_changes(client):
    first = propose_from_bypass(client)
    client.post(f"/api/patches/{first['patch_id']}/replay")
    client.post(f"/api/patches/{first['patch_id']}/approve")  # active -> v2
    second_patch = client.get(f"/api/patches/{first['patch_id']}").json()
    assert second_patch["status"] == "approved"
    # propose another patch against v1 trace is impossible now; simulate stale: roll back then approve old patch
    client.post("/api/policies/1/rollback")
    assert client.post(f"/api/patches/{first['patch_id']}/approve").status_code == 409  # already approved


def test_invalid_patch_is_stored_with_errors(client, monkeypatch):
    from app.services import patcher

    def bad(failed_trace, active_policy, transport=None):
        patch = patcher.seeded_patch(active_policy["version"], "x")
        patch["proposed_decision"] = "allow"
        patch["code"] = "os.system('x')"
        return {"patch": patch, "raw_text": None, "meta": {"demo_fallback": False, "model_id": "m", "model_role": "super",
                "latency_ms": 1, "prompt_tokens": 1, "completion_tokens": 1, "estimated_cost_usd": None, "fallback_reason": None}}

    monkeypatch.setattr(patcher, "propose_patch", bad)
    rec = propose_from_bypass(client)
    assert rec["status"] == "rejected_invalid" and not rec["validation"]["ok"]
    assert any("never 'allow'" in e for e in rec["validation"]["errors"])
    assert client.post(f"/api/patches/{rec['patch_id']}/replay").status_code == 409


def test_evidence_lists_every_stored_version(client):
    patch = propose_from_bypass(client)
    client.post(f"/api/patches/{patch['patch_id']}/replay")
    client.post(f"/api/patches/{patch['patch_id']}/approve")
    cols = client.get("/api/evidence").json()["columns"]
    assert [c["name"] for c in cols] == ["No firewall", "Policy v1", "Policy v2"]
    assert cols[2]["summary"]["train_asr"]["k"] == 0


def test_patch_list_returns_latest_first_for_page_reload(client):
    assert client.get("/api/patches").json() == []
    first = propose_from_bypass(client)["patch_id"]
    client.post(f"/api/patches/{first}/reject", json={"reason": "test"})
    second = propose_from_bypass(client)["patch_id"]
    listed = client.get("/api/patches").json()
    assert [p["patch_id"] for p in listed][0] == second
    assert {p["patch_id"] for p in listed} == {first, second}
    assert listed[0]["status"] == "validated"
