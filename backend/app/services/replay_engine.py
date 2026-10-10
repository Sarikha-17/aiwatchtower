"""Replay stored cases under a policy WITHOUT calling any agent or model, then compute metrics.

All numbers are computed from the stored cases; none are hardcoded.
"""
import math
import statistics

from app.config import POLICY_DIR, load_domain_config
from app.services import datasets
from app.services.data_store import DataStore
from app.services.policy_engine import PolicyEngine, load_policy
from app.services.sandbox_agent import run_scenario
from app.services.tool_firewall import ToolFirewall


def wilson(k: int, n: int, z: float = 1.96) -> tuple:
    """Wilson score interval for a proportion k/n."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _rate(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else 0.0,
            "ci_low": round(lo, 4), "ci_high": round(hi, 4)}


def make_firewall_from_policy(policy: dict | None, store, cfg):
    return None if policy is None else ToolFirewall(PolicyEngine([policy]), store, cfg)


def replay_case(case: dict, policy: dict | None, base_store: DataStore | None = None, cfg=None):
    """Replay one stored case. policy=None means no firewall."""
    base_store = base_store or DataStore.from_files()
    cfg = cfg or load_domain_config()
    emails = dict(base_store.emails)
    if case.get("email"):
        emails[case["email"]["email_id"]] = case["email"]
    store = DataStore(emails=emails, hr_files=base_store.hr_files)
    version = policy["version"] if policy else None
    return run_scenario(datasets.case_to_scenario(case), store, cfg,
                        make_firewall_from_policy(policy, store, cfg), version)


def replay_all(policy: dict | None, cases: list | None = None) -> list:
    cases = cases if cases is not None else datasets.load_all_cases()
    store, cfg = DataStore.from_files(), load_domain_config()
    out = []
    for case in cases:
        trace = replay_case(case, policy, store, cfg)
        latencies = [e["decision"]["latency_ms"] for e in trace.events]
        out.append({
            "case_id": case["case_id"], "kind": case["kind"], "category": case["category"],
            "attack_succeeded": trace.attack_succeeded,
            "task_completed": trace.verdict == "TASK COMPLETED",
            "verdict": trace.verdict, "latencies": latencies,
            "decisions": [e["decision"]["decision"] for e in trace.events],
        })
    return out


def summarize(results: list) -> dict:
    train = [r for r in results if r["kind"] == datasets.TRAIN]
    held = [r for r in results if r["kind"] == datasets.HELD_OUT]
    legit = [r for r in results if r["kind"] == datasets.LEGIT]
    lat = sorted(l for r in results for l in r["latencies"])
    p95 = lat[max(0, math.ceil(0.95 * len(lat)) - 1)] if lat else 0.0
    return {
        "train_asr": _rate(sum(r["attack_succeeded"] for r in train), len(train)),
        "held_out_asr": _rate(sum(r["attack_succeeded"] for r in held), len(held)),
        "legit_success": _rate(sum(r["task_completed"] for r in legit), len(legit)),
        "false_positive_rate": _rate(sum(not r["task_completed"] for r in legit), len(legit)),
        "median_firewall_latency_ms": round(statistics.median(lat), 3) if lat else 0.0,
        "p95_firewall_latency_ms": round(p95, 3),
    }


def compare(before: list, after: list) -> dict:
    b = {r["case_id"]: r for r in before}
    a = {r["case_id"]: r for r in after}
    ids = lambda pred: [cid for cid in b if pred(b[cid], a[cid])]
    newly_blocked = lambda kind: ids(lambda x, y: x["kind"] == kind and x["attack_succeeded"] and not y["attack_succeeded"])
    return {
        "newly_blocked_train_attacks": newly_blocked(datasets.TRAIN),
        "newly_blocked_held_out_attacks": newly_blocked(datasets.HELD_OUT),
        "still_successful_train_attacks": ids(lambda x, y: x["kind"] == datasets.TRAIN and y["attack_succeeded"]),
        "still_successful_held_out_attacks": ids(lambda x, y: x["kind"] == datasets.HELD_OUT and y["attack_succeeded"]),
        "newly_blocked_legitimate_tasks": ids(lambda x, y: x["kind"] == datasets.LEGIT and x["task_completed"] and not y["task_completed"]),
        "newly_allowed_legitimate_tasks": ids(lambda x, y: x["kind"] == datasets.LEGIT and not x["task_completed"] and y["task_completed"]),
    }


def load_candidate(version: int) -> dict:
    files = {1: "policy_v1.yaml", 2: "policy_v2_example.yaml"}
    return load_policy(POLICY_DIR / files[version])


def compute_metrics() -> dict:
    results = {"none": replay_all(None), "v1": replay_all(load_candidate(1)), "v2": replay_all(load_candidate(2))}
    cases = datasets.load_all_cases()
    return {
        "dataset_sizes": {
            "train_attacks": sum(c["kind"] == datasets.TRAIN for c in cases),
            "held_out_attacks": sum(c["kind"] == datasets.HELD_OUT for c in cases),
            "legitimate_tasks": sum(c["kind"] == datasets.LEGIT for c in cases),
        },
        "policies": {name: summarize(r) for name, r in results.items()},
        "v1_to_v2": compare(results["v1"], results["v2"]),
        "estimated_cost_per_1000_actions_usd": 0.0,
        "notes": [
            "All cases are fabricated and hand-written; they run only inside the local sandbox.",
            "Replay measures these recorded traces, not unknown adaptive attacks.",
            "Small samples are suggestive, not conclusive: see the Wilson 95% intervals.",
            "Held-out cases were written by the same author as the policy logic, so they are not an independent benchmark.",
            "Cost is 0 because Level 2 uses no model calls; Nemotron costs are added in Level 3.",
        ],
    }
