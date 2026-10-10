import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AIWATCHTOWER_DB", str(tmp_path / "test.db"))
    return TestClient(app)


def run(client, scenario, mode):
    r = client.post("/api/agent/run-scenario", json={"scenario_id": scenario, "mode": mode})
    assert r.status_code == 200, r.text
    return r.json()


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_scenarios_listed(client):
    ids = [s["scenario_id"] for s in client.get("/api/scenarios").json()]
    assert {"legit_invoice_summary", "obvious_attack", "v1_bypass"} <= set(ids)


def test_bypass_succeeds_under_v1_and_blocked_under_v2(client):
    assert run(client, "v1_bypass", "v1")["verdict"] == "ATTACK SUCCEEDED"
    assert run(client, "v1_bypass", "v2")["verdict"] == "ATTACK BLOCKED"


def test_legit_task_completes(client):
    assert run(client, "legit_invoice_summary", "v1")["verdict"] == "TASK COMPLETED"


def test_trace_is_persisted_and_retrievable(client):
    trace = run(client, "obvious_attack", "none")
    listed = client.get("/api/traces").json()
    assert any(t["trace_id"] == trace["trace_id"] for t in listed)
    detail = client.get(f"/api/traces/{trace['trace_id']}").json()
    assert detail["verdict"] == "ATTACK SUCCEEDED"
    assert detail["events"][0]["tool"] == "email.read"


def test_bad_mode_and_unknown_scenario_rejected(client):
    assert client.post("/api/agent/run-scenario", json={"scenario_id": "v1_bypass", "mode": "x"}).status_code == 400
    assert client.post("/api/agent/run-scenario", json={"scenario_id": "nope", "mode": "v1"}).status_code == 404
    assert client.get("/api/traces/does-not-exist").status_code == 404


def test_index_page_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "AIWatchTower" in r.text


def test_metrics_endpoint(client):
    r = client.get("/api/metrics")
    assert r.status_code == 200
    body = r.json()
    assert body["policies"]["v2"]["train_asr"]["k"] == 0
    assert body["policies"]["none"]["train_asr"]["rate"] == 1.0
