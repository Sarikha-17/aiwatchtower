import math

from app.services import datasets
from app.services.replay_engine import (
    compare, compute_metrics, load_candidate, replay_all, summarize, wilson,
)


def test_dataset_sizes():
    assert len(datasets.load_train_attacks()) == 25
    assert len(datasets.load_held_out_attacks()) == 12
    assert len(datasets.load_legitimate_tasks()) == 12


def test_case_ids_unique_and_kinds_correct():
    cases = datasets.load_all_cases()
    ids = [c["case_id"] for c in cases]
    assert len(ids) == len(set(ids))
    assert {c["kind"] for c in datasets.load_train_attacks()} == {"train_attack"}
    assert {c["kind"] for c in datasets.load_held_out_attacks()} == {"held_out_attack"}


def test_held_out_isolation_from_patcher_inputs():
    held = datasets.load_held_out_attacks()
    held_ids = {c["case_id"] for c in held}
    visible = datasets.patcher_visible_cases()
    assert held_ids.isdisjoint({c["case_id"] for c in visible})
    # also no held-out content leaks into the visible set
    visible_text = " ".join(str(c.get("email")) + str(c["calls"]) for c in visible)
    for c in held:
        assert str(c["calls"]) not in visible_text
        if c.get("email"):
            assert c["email"]["body"] not in visible_text


def test_without_firewall_every_attack_succeeds_and_every_legit_task_completes():
    results = replay_all(None)
    assert all(r["attack_succeeded"] for r in results if r["kind"] != "legitimate")
    assert all(r["task_completed"] for r in results if r["kind"] == "legitimate")


def test_v1_misses_most_training_attacks_but_blocks_keyword_ones():
    summary = summarize(replay_all(load_candidate(1)))
    assert 0 < summary["train_asr"]["k"] < summary["train_asr"]["n"]


def test_v2_blocks_all_training_attacks():
    assert summarize(replay_all(load_candidate(2)))["train_asr"]["k"] == 0


def test_v2_held_out_gaps_are_reported_honestly():
    after = replay_all(load_candidate(2))
    still = {r["case_id"] for r in after if r["kind"] == "held_out_attack" and r["attack_succeeded"]}
    # internal-file injection (no untrusted read) and user-named recipient slip through
    assert still == {"held_out_attack_09", "held_out_attack_10", "held_out_attack_11"}


def test_false_positive_cost_is_measured_for_both_policies():
    v1, v2 = replay_all(load_candidate(1)), replay_all(load_candidate(2))
    delta = compare(v1, v2)
    assert delta["newly_blocked_legitimate_tasks"] == ["legit_11"]
    assert "legit_10" in delta["newly_allowed_legitimate_tasks"]  # v1 false positive fixed by v2


def test_wilson_interval_known_values():
    lo, hi = wilson(0, 25)
    assert lo == 0.0 and math.isclose(hi, 0.1332, abs_tol=1e-3)
    lo, hi = wilson(3, 12)
    assert math.isclose(lo, 0.0889, abs_tol=1e-3) and math.isclose(hi, 0.5323, abs_tol=1e-3)
    assert wilson(0, 0) == (0.0, 0.0)


def test_metrics_structure_and_no_hardcoded_cost_claims():
    m = compute_metrics()
    assert set(m["policies"]) == {"none", "v1", "v2"}
    assert m["dataset_sizes"] == {"train_attacks": 25, "held_out_attacks": 12, "legitimate_tasks": 12}
    assert m["policies"]["v2"]["held_out_asr"]["n"] == 12
    assert any("not an independent benchmark" in n for n in m["notes"])
