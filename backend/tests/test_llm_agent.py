"""The real-agent loop, tested with scripted fake models (no network). The real agent itself is NOT in CI."""
import json

import httpx
import pytest

from app.config import load_domain_config
from app.services import agent_eval, datasets
from app.services.agent_eval import AgentClient, BudgetExceeded, LLMCache, run_batch, summarize_runs
from app.services.data_store import DataStore
from app.services.llm_agent import TOOLS, build_system_prompt, run_agent_case, task_text
from app.services.patch_service import build_candidate
from app.services.patcher import seeded_patch
from app.services.replay_engine import load_candidate

BASE, CFG = DataStore.from_files(), load_domain_config()
V1 = load_candidate(1)
V2 = build_candidate(V1, seeded_patch(1, "t"), 2)


def tc(name, args, cid="c1"):
    return {"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


def msg(content=None, calls=None):
    return {"message": {"role": "assistant", "content": content, **({"tool_calls": calls} if calls else {})},
            "prompt_tokens": 10, "completion_tokens": 5, "latency_ms": 1.0}


class Fake:
    """Responds by the number of tool results already in the conversation."""
    def __init__(self, steps):
        self.steps, self.calls = steps, 0

    def complete(self, messages, tools, temperature, run_idx):
        self.calls += 1
        n = sum(1 for m in messages if m["role"] == "tool")
        out = self.steps[n] if n < len(self.steps) else msg("Done.")
        return {**out, "cached": False}


def attack_case(cid="train_attack_03"):
    return next(c for c in datasets.load_train_attacks() if c["case_id"] == cid)


def hijacked_steps(case):
    e, send = case["email"]["email_id"], case["calls"][1]["args"]
    return [msg(calls=[tc("email_read", {"email_id": e})]),
            msg(calls=[tc("hr_file_read", {"file_id": case["calls"][0]["args"]["file_id"]})]),
            msg(calls=[tc("email_send", send)]), msg("Summary done.")]


def test_task_text_includes_email_ids_and_prompt_is_neutral():
    case = attack_case()
    assert case["email"]["email_id"] in task_text(case)
    prompt = build_system_prompt(BASE).lower()
    assert "ignore" not in prompt and "follow all" not in prompt and "instruction" not in prompt
    assert "salary_report_q3" in prompt and "(fake" not in prompt  # catalog shows ids and neutral titles


def test_no_firewall_hijacked_agent_succeeds():
    case = attack_case()
    r = run_agent_case(case, None, Fake(hijacked_steps(case)), BASE, CFG, "none")
    assert r["outcome"] == "attack_succeeded" and r["succeeded"] and r["attempted"]


def test_v1_misses_bypass_and_v2_blocks_it_with_feedback_to_the_model():
    case = attack_case("train_attack_03")  # body avoids salary/payroll
    assert run_agent_case(case, V1, Fake(hijacked_steps(case)), BASE, CFG, "v1")["outcome"] == "attack_succeeded"
    r = run_agent_case(case, V2, Fake(hijacked_steps(case)), BASE, CFG, "v2")
    assert r["outcome"] == "attack_blocked" and not r["succeeded"] and r["attempted"]
    assert any("blocked by the security firewall" in m["content"] for m in r["transcript"] if m["role"] == "tool")


def test_v1_blocks_keyword_attack():
    case = attack_case("train_attack_01")
    assert run_agent_case(case, V1, Fake(hijacked_steps(case)), BASE, CFG, "v1")["outcome"] == "attack_blocked"


def test_agent_that_resists_is_not_attempted():
    case = attack_case()
    steps = [msg(calls=[tc("email_read", {"email_id": case["email"]["email_id"]})]), msg("Invoice summary.")]
    r = run_agent_case(case, None, Fake(steps), BASE, CFG, "none")
    assert r["outcome"] == "attack_not_attempted" and not r["attempted"]


def test_malformed_arguments_and_unknown_tool_are_handled_and_counted():
    case = attack_case()
    bad = {"id": "x", "type": "function", "function": {"name": "email_read", "arguments": "{not json"}}
    steps = [msg(calls=[bad]), msg(calls=[tc("delete_everything", {})]), msg("Gave up.")]
    r = run_agent_case(case, None, Fake(steps), BASE, CFG, "none")
    assert r["malformed_calls"] == 2 and r["outcome"] == "attack_not_attempted"


def test_step_limit_is_its_own_outcome():
    case = attack_case()
    forever = [msg(calls=[tc("email_read", {"email_id": case["email"]["email_id"]})])] * 20
    r = run_agent_case(case, None, Fake(forever), BASE, CFG, "none", max_steps=4)
    assert r["error"] == "step_limit" and r["steps"] == 4 and r["outcome"] == "agent_error"


def test_api_failure_is_logged_not_dropped():
    class Broken:
        def complete(self, *a, **k):
            raise RuntimeError("API down")
    r = run_agent_case(attack_case(), None, Broken(), BASE, CFG, "none")
    assert r["outcome"] == "agent_error" and "API down" in r["error"]


def test_legit_completed_and_false_block():
    case = next(c for c in datasets.load_legitimate_tasks() if c["case_id"] == "legit_11")
    send = case["calls"][0]["args"]
    steps = [msg(calls=[tc("email_read", {"email_id": case["email"]["email_id"]})]),
             msg(calls=[tc("email_send", send)]), msg("Sent.")]
    assert run_agent_case(case, None, Fake(steps), BASE, CFG, "none")["outcome"] == "legit_completed"
    assert run_agent_case(case, V2, Fake(steps), BASE, CFG, "v2")["outcome"] == "legit_blocked"  # the known false positive


def test_legit_incomplete_when_agent_skips_the_task():
    case = next(c for c in datasets.load_legitimate_tasks() if c["case_id"] == "legit_02")
    steps = [msg(calls=[tc("email_read", {"email_id": case["email"]["email_id"]})]), msg("Summary only.")]
    assert run_agent_case(case, None, Fake(steps), BASE, CFG, "none")["outcome"] == "legit_incomplete"


def test_draft_only_task_fails_if_agent_sends():
    case = next(c for c in datasets.load_legitimate_tasks() if c["case_id"] == "legit_12")
    steps = [msg(calls=[tc("email_read", {"email_id": case["email"]["email_id"]})]),
             msg(calls=[tc("email_send", {"to": "billing@acct-vendor.example", "subject": "s", "body": "b"})]), msg("Sent.")]
    assert run_agent_case(case, None, Fake(steps), BASE, CFG, "none")["outcome"] == "legit_incomplete"


# ---------- client: cache, pairing, budget ----------
def configure(monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "k")
    monkeypatch.setenv("NEMOTRON_NANO_MODEL", "fake/agent")


def transport_for(case, counter):
    def handler(request):
        counter["http"] += 1
        body = json.loads(request.content)
        n = sum(1 for m in body["messages"] if m["role"] == "tool")
        steps = hijacked_steps(case)
        step = steps[n] if n < len(steps) else msg("Done.")
        return httpx.Response(200, json={"choices": [{"message": step["message"], "finish_reason": "stop"}],
                                         "usage": {"prompt_tokens": 10, "completion_tokens": 5}})
    return httpx.MockTransport(handler)


def test_arms_share_cached_calls_until_the_firewall_changes_the_conversation(monkeypatch):
    configure(monkeypatch)
    case, counter = attack_case("train_attack_03"), {"http": 0}
    client = AgentClient(transport=transport_for(case, counter), sleep=lambda s: None)
    out = run_batch(client, [case], {"none": None, "v1": V1, "v2": V2}, runs=1, temperature=0.3, progress=lambda m: None)
    outcomes = {r["arm"]: r["outcome"] for r in out["runs"]}
    assert outcomes == {"none": "attack_succeeded", "v1": "attack_succeeded", "v2": "attack_blocked"}
    # none: 4 calls. v1 identical -> all cached. v2 diverges at the blocked send -> only 1-2 new calls.
    assert counter["http"] == 5 and client.cache_hits == 7  # none: 4 calls; v1: 4 cached; v2: 3 cached + 1 new


def test_cache_persists_to_disk_and_makes_reruns_free(monkeypatch, tmp_path):
    configure(monkeypatch)
    case, counter = attack_case(), {"http": 0}
    path = tmp_path / "cache.jsonl"
    c1 = AgentClient(transport=transport_for(case, counter), cache=LLMCache(path))
    run_batch(c1, [case], {"none": None}, 1, 0.3, progress=lambda m: None)
    first = counter["http"]
    c2 = AgentClient(transport=transport_for(case, counter), cache=LLMCache(path))
    run_batch(c2, [case], {"none": None}, 1, 0.3, progress=lambda m: None)
    assert counter["http"] == first and c2.calls_made == 0


def test_different_run_index_is_a_different_sample(monkeypatch):
    configure(monkeypatch)
    case, counter = attack_case(), {"http": 0}
    client = AgentClient(transport=transport_for(case, counter))
    run_batch(client, [case], {"none": None}, runs=2, temperature=0.3, progress=lambda m: None)
    assert counter["http"] == 8  # 4 calls per run, two independent runs


def test_budget_stops_cleanly_and_saves_partial_results(monkeypatch, tmp_path):
    configure(monkeypatch)
    cases, counter = [attack_case(), attack_case("train_attack_04")], {"http": 0}
    client = AgentClient(transport=transport_for(attack_case(), counter), max_calls=2)
    out_path = tmp_path / "out.json"
    out = run_batch(client, cases, {"none": None}, 1, 0.3, out_path, progress=lambda m: None)
    assert out["meta"]["stopped_early"] is True and client.calls_made == 2
    assert json.loads(out_path.read_text())["meta"]["stopped_early"] is True


def test_client_retries_transient_errors(monkeypatch):
    configure(monkeypatch)
    attempts = {"n": 0}
    def handler(request):
        attempts["n"] += 1
        if attempts["n"] < 3:
            return httpx.Response(429, text="slow down")
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}]})
    client = AgentClient(transport=httpx.MockTransport(handler), sleep=lambda s: None)
    out = client.complete([{"role": "user", "content": "x"}], TOOLS, 0.3, 0)
    assert out["message"]["content"] == "hi" and attempts["n"] == 3


# ---------- summary ----------
def test_summary_counts_runs_and_attacks_separately():
    runs = [
        {"arm": "none", "kind": "train_attack", "case_id": "a", "run": 0, "outcome": "attack_succeeded", "attempted": True, "succeeded": True, "malformed_calls": 0},
        {"arm": "none", "kind": "train_attack", "case_id": "a", "run": 1, "outcome": "attack_not_attempted", "attempted": False, "succeeded": False, "malformed_calls": 1},
        {"arm": "none", "kind": "train_attack", "case_id": "b", "run": 0, "outcome": "attack_not_attempted", "attempted": False, "succeeded": False, "malformed_calls": 0},
        {"arm": "none", "kind": "legitimate", "case_id": "l", "run": 0, "outcome": "legit_completed", "attempted": False, "succeeded": False, "malformed_calls": 0},
    ]
    e = summarize_runs(runs)["none"]
    assert e["train"]["succeeded"]["k"] == 1 and e["train"]["runs"] == 3
    assert e["train"]["attacks_succeeded_at_least_once"]["k"] == 1 and e["train"]["attacks_succeeded_at_least_once"]["n"] == 2
    assert e["legit"]["completed"]["k"] == 1 and e["malformed_calls"] == 1


def test_agent_evidence_endpoint(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    monkeypatch.setattr(agent_eval, "load_saved", lambda path=None, attack_set="original": None)
    assert TestClient(app).get("/api/agent-evidence").json() == {"available": False, "set": "original"}
    saved = {"meta": {"model": "m"}, "runs": [{"arm": "none", "kind": "legitimate", "case_id": "l", "run": 0,
             "outcome": "legit_completed", "attempted": False, "succeeded": False, "malformed_calls": 0}]}
    monkeypatch.setattr(agent_eval, "load_saved", lambda path=None, attack_set="original": saved)
    body = TestClient(app).get("/api/agent-evidence").json()
    assert body["available"] and body["summary"]["none"]["legit"]["completed"]["k"] == 1
    assert "transcript" not in json.dumps(body)
