import pytest

from app.services import policy_store
from app.services.patch_service import build_candidate
from app.services.patcher import seeded_patch


def test_seed_is_weak_v1_active():
    active = policy_store.get_active()
    assert active["version"] == 1 and "body_contains_any" in active["when"]
    assert [v["status"] for v in policy_store.list_versions()] == ["active"]


def test_activation_marks_previous_and_logs():
    patch = seeded_patch(1, "t")
    candidate = build_candidate(policy_store.get_active(), patch, policy_store.next_version())
    policy_store.activate_new_version(candidate, patch["patch_id"], "security_admin@company.example")
    versions = {v["version"]: v["status"] for v in policy_store.list_versions()}
    assert versions == {1: "previous", 2: "active"}
    assert policy_store.get_active()["version"] == 2
    assert policy_store.list_history()[-1]["action"] == "approve"


def test_candidate_is_additive_and_keeps_original_rule():
    candidate = build_candidate(policy_store.get_active(), seeded_patch(1, "t"), 2)
    assert len(candidate["rules"]) == 2
    assert "body_contains_any" in candidate["rules"][0]["when"]
    assert candidate["rules"][1]["name"].startswith("patch_PATCH-")


def test_rollback_restores_prior_version_and_logs():
    patch = seeded_patch(1, "t")
    policy_store.activate_new_version(build_candidate(policy_store.get_active(), patch, 2), patch["patch_id"], "a")
    policy_store.rollback(1, "a")
    assert policy_store.get_active()["version"] == 1
    assert {v["version"]: v["status"] for v in policy_store.list_versions()} == {1: "active", 2: "rolled_back"}
    assert policy_store.list_history()[-1]["action"] == "rollback"


def test_rollback_errors():
    with pytest.raises(policy_store.PolicyStoreError):
        policy_store.rollback(99, "a")
    with pytest.raises(policy_store.PolicyStoreError):
        policy_store.rollback(1, "a")  # already active


def test_duplicate_version_rejected():
    patch = seeded_patch(1, "t")
    cand = build_candidate(policy_store.get_active(), patch, 2)
    policy_store.activate_new_version(cand, patch["patch_id"], "a")
    with pytest.raises(policy_store.PolicyStoreError):
        policy_store.activate_new_version(cand, patch["patch_id"], "a")
