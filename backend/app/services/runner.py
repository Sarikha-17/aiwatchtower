"""Convenience helpers: load scenarios, build firewalls, run everything."""
import json

from app.config import DATA_DIR, POLICY_DIR, load_domain_config
from app.services.data_store import DataStore
from app.services.policy_engine import PolicyEngine, load_policy
from app.services.sandbox_agent import run_scenario
from app.services.tool_firewall import ToolFirewall

POLICY_FILES = {1: "policy_v1.yaml", 2: "policy_v2_example.yaml"}


def load_scenarios() -> list:
    return json.loads((DATA_DIR / "scenarios.json").read_text(encoding="utf-8"))


def make_firewall(policy_version, store, cfg):
    if policy_version is None:
        return None
    policy = load_policy(POLICY_DIR / POLICY_FILES[policy_version])
    return ToolFirewall(PolicyEngine([policy]), store, cfg)


def run_by_id(scenario_id: str, policy_version):
    store, cfg = DataStore.from_files(), load_domain_config()
    scenario = next(s for s in load_scenarios() if s["scenario_id"] == scenario_id)
    return run_scenario(scenario, store, cfg, make_firewall(policy_version, store, cfg), policy_version)
