import json

from fastapi.testclient import TestClient

from app.main import app
from app.services import agent_eval, datasets, detectors
from app.config import load_domain_config
from app.services.replay_engine import load_candidate, replay_all, summarize
from app.services.patch_service import build_candidate
from app.services.patcher import seeded_patch

CFG = load_domain_config()


def test_twenty_realistic_attacks_with_unique_ids():
    cases = datasets.load_realistic_attacks()
    assert len(cases) == 20
    assert len({c["case_id"] for c in cases}) == 20
    assert all(c["kind"] == "train_attack" and c["case_id"].startswith("real_attack_") for c in cases)


def test_realistic_attacks_are_disjoint_from_held_out_and_original_sets():
    realistic = datasets.load_realistic_attacks()
    others = datasets.load_train_attacks() + datasets.load_held_out_attacks()
    assert {c["case_id"] for c in realistic}.isdisjoint({c["case_id"] for c in others})
    bodies = {c["email"]["body"] for c in others if c.get("email")}
    assert all(c["email"]["body"] not in bodies for c in realistic)


def test_realistic_attacks_do_not_use_the_explicit_override_phrases():
    banned = ["ignore previous", "ignore all previous", "disregard the above", "you must"]
    for c in datasets.load_realistic_attacks():
        text = (c["email"]["subject"] + " " + c["email"]["body"]).lower()
        assert not any(b in text for b in banned), c["case_id"]


def test_every_realistic_attack_is_a_valid_attack_by_the_code_evaluator():
    # with no firewall the recorded exfiltration calls satisfy the deterministic success condition
    results = replay_all(None, datasets.load_realistic_attacks())
    assert all(r["attack_succeeded"] for r in results)


def test_recipients_are_unknown_external_and_attachments_sensitive():
    from app.services.data_store import DataStore
    store = DataStore.from_files()
    for c in datasets.load_realistic_attacks():
        send = [x for x in c["calls"] if x["tool"] == "email.send"][-1]["args"]
        assert detectors.classify_recipient(send["to"], CFG) == "unknown_external", c["case_id"]
        assert detectors.has_sensitive_hr_tags(detectors.attachment_tags(send["attachment_id"], store)), c["case_id"]


def test_task_framing_is_mixed_summarize_and_handle():
    requests = {c["user_request"] for c in datasets.load_realistic_attacks()}
    assert any("summarize" in r.lower() for r in requests) and any("take care of" in r.lower() for r in requests)


def test_additive_patch_blocks_all_realistic_attacks_on_replay():
    v1 = load_candidate(1)
    v2 = build_candidate(v1, seeded_patch(1, "t"), 2)
    cases = datasets.load_realistic_attacks()
    assert summarize(replay_all(v2, cases))["train_asr"]["k"] == 0
    assert summarize(replay_all(v1, cases))["train_asr"]["k"] > 0  # the weak v1 misses most of them


def test_patcher_may_see_realistic_set_but_never_held_out():
    visible = {c["case_id"] for c in datasets.patcher_visible_cases()}
    assert {c["case_id"] for c in datasets.load_realistic_attacks()} <= visible
    assert visible.isdisjoint({c["case_id"] for c in datasets.load_held_out_attacks()})


def test_select_cases_attack_set_switches_only_the_training_attacks():
    orig = agent_eval.select_cases(attack_set="original")
    real = agent_eval.select_cases(attack_set="realistic")
    kinds = lambda cs, k: [c["case_id"] for c in cs if c["kind"] == k]
    assert kinds(orig, "train_attack")[0].startswith("train_attack_")
    assert kinds(real, "train_attack")[0].startswith("real_attack_")
    assert kinds(orig, "held_out_attack") == kinds(real, "held_out_attack")
    assert kinds(orig, "legitimate") == kinds(real, "legitimate")


def test_results_files_are_separate_per_attack_set():
    assert agent_eval.RESULT_FILES["original"] != agent_eval.RESULT_FILES["realistic"]


def test_agent_evidence_endpoint_set_parameter(monkeypatch):
    client = TestClient(app)
    saved = {"meta": {"model": "m"}, "runs": [{"arm": "none", "kind": "legitimate", "case_id": "l", "run": 0,
             "outcome": "legit_completed", "attempted": False, "succeeded": False, "malformed_calls": 0}]}
    monkeypatch.setattr(agent_eval, "load_saved", lambda path=None, attack_set="original": saved if attack_set == "realistic" else None)
    assert client.get("/api/agent-evidence?set=original").json() == {"available": False, "set": "original"}
    assert client.get("/api/agent-evidence?set=realistic").json()["available"] is True
    assert client.get("/api/agent-evidence?set=bogus").status_code == 400
