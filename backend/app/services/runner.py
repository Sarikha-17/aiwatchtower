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


def resolve_policy(policy_ref):
    """None (no firewall), an int version (YAML reference files), or a policy dict."""
    if policy_ref is None or isinstance(policy_ref, dict):
        return policy_ref
    return load_policy(POLICY_DIR / POLICY_FILES[policy_ref])


def make_firewall(policy_ref, store, cfg, live: bool = False):
    """live=True (interactive demo only) attaches the optional Nano intent check. Replay never does."""
    policy = resolve_policy(policy_ref)
    if policy is None:
        return None
    checker, mode = None, "off"
    if live:
        from app.config import get_settings
        from app.services.intent_check import make_live_checker
        checker, mode = make_live_checker(), get_settings().nano_intent_mode
    return ToolFirewall(PolicyEngine([policy]), store, cfg, intent_checker=checker, intent_mode=mode)


def run_by_id(scenario_id: str, policy_ref, live: bool = False):
    store, cfg = DataStore.from_files(), load_domain_config()
    scenario = next(s for s in load_scenarios() if s["scenario_id"] == scenario_id)
    policy = resolve_policy(policy_ref)
    version = policy["version"] if policy else None
    return run_scenario(scenario, store, cfg, make_firewall(policy, store, cfg, live=live), version)
