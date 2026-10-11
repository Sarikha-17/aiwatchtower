import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import intent_check, patcher, usage_guard
from app.services.replay_engine import load_candidate
from app.services.runner import run_by_id


@pytest.fixture
def client():
    return TestClient(app)


def configure_model(monkeypatch, demo="true"):
    monkeypatch.setenv("NEBIUS_API_KEY", "k")
    monkeypatch.setenv("NEMOTRON_SUPER_MODEL", "fake/super")
    monkeypatch.setenv("NEMOTRON_NANO_MODEL", "fake/nano")
    monkeypatch.setenv("DEMO_MODE", demo)


def ok_transport():
    patch = patcher.seeded_patch(1, "x")
    body = {"choices": [{"message": {"content": json.dumps(patch)}, "finish_reason": "stop"}]}
    return httpx.MockTransport(lambda req: httpx.Response(200, json=body))


def trace():
    return run_by_id("v1_bypass", 1).to_dict()


def test_cap_zero_means_unlimited(monkeypatch):
    configure_model(monkeypatch)
    for _ in range(3):
        assert patcher.propose_patch(trace(), load_candidate(1), transport=ok_transport())["meta"]["demo_fallback"] is False
    assert usage_guard.calls_today() == 3


def test_cap_falls_back_to_labeled_demo_patch(monkeypatch):
    configure_model(monkeypatch)
    monkeypatch.setenv("MAX_MODEL_CALLS_PER_DAY", "1")
    first = patcher.propose_patch(trace(), load_candidate(1), transport=ok_transport())
    assert first["meta"]["demo_fallback"] is False
    second = patcher.propose_patch(trace(), load_candidate(1), transport=ok_transport())
    assert second["meta"]["demo_fallback"] is True
    assert "cap" in second["meta"]["fallback_reason"]
    assert "DEMO FALLBACK" in second["patch"]["reasoning"]
    assert usage_guard.calls_today() == 1  # the blocked call was not made or counted


def test_cap_without_demo_mode_fails_honestly(monkeypatch):
    configure_model(monkeypatch, demo="false")
    monkeypatch.setenv("MAX_MODEL_CALLS_PER_DAY", "1")
    patcher.propose_patch(trace(), load_candidate(1), transport=ok_transport())
    with pytest.raises(patcher.PatcherError) as exc:
        patcher.propose_patch(trace(), load_candidate(1), transport=ok_transport())
    assert "cap" in str(exc.value)


def test_cap_applies_to_nano_intent_checks(monkeypatch):
    configure_model(monkeypatch)
    monkeypatch.setenv("NANO_INTENT_CHECK", "annotate")
    monkeypatch.setenv("MAX_MODEL_CALLS_PER_DAY", "1")
    body = {"choices": [{"message": {"content": '{"intent_aligned": true, "confidence": 0.9, "reason": "ok"}'},
                         "finish_reason": "stop"}]}
    checker = intent_check.make_live_checker(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=body)))
    args = {"to": "a@company.example", "subject": "s", "body": "b", "attachment_id": None}
    assert checker("req", "email.send", args)["intent_aligned"] is True
    assert checker("req", "email.send", args)["error"] == "daily model-call cap reached"


def test_health_reports_usage_and_cap(client, monkeypatch):
    monkeypatch.setenv("MAX_MODEL_CALLS_PER_DAY", "5")
    body = client.get("/health").json()
    assert body["model_calls_cap"] == 5 and body["model_calls_today"] == 0 and body["reset_enabled"] is True
    assert "api_key" not in json.dumps(body).lower()


def test_reset_restores_initial_state_but_keeps_usage_counter(client, monkeypatch):
    trace_json = client.post("/api/agent/run-scenario", json={"scenario_id": "v1_bypass", "mode": "active"}).json()
    pid = client.post("/api/patches/propose", json={"trace_id": trace_json["trace_id"]}).json()["patch_id"]
    client.post(f"/api/patches/{pid}/replay")
    client.post(f"/api/patches/{pid}/approve")
    usage_guard.allow_call("super")
    assert client.get("/api/policies/active").json()["version"] == 2

    assert client.post("/api/admin/reset").status_code == 200
    assert client.get("/api/policies/active").json()["version"] == 1
    assert client.get("/api/patches").json() == []
    assert client.get("/api/traces").json() == []
    history = client.get("/api/policies/history").json()
    assert [v["version"] for v in history["versions"]] == [1]
    assert [e["action"] for e in history["log"]] == ["seed", "reset"]
    assert usage_guard.calls_today() == 1  # the cap cannot be bypassed by resetting
    run = client.post("/api/agent/run-scenario", json={"scenario_id": "v1_bypass", "mode": "active"}).json()
    assert run["verdict"] == "ATTACK SUCCEEDED"  # back to the weak v1


def test_reset_can_be_disabled(client, monkeypatch):
    monkeypatch.setenv("ALLOW_DEMO_RESET", "false")
    assert client.post("/api/admin/reset").status_code == 403
    assert client.get("/health").json()["reset_enabled"] is False


def test_unconfigured_model_is_not_counted_as_a_call():
    # conftest clears the API key: the patcher falls back to demo mode without using the counter
    out = patcher.propose_patch(trace(), load_candidate(1))
    assert out["meta"]["demo_fallback"] is True
    assert usage_guard.calls_today() == 0
