"""Offline evaluation of the real LLM agent: cached model calls, paired arms, saved results.

Design notes
- Every model call is cached by a hash of (model, temperature, run index, full message history, tools).
  Arms share a model sample until a firewall decision changes the conversation, so the arms are PAIRED and
  the no-firewall arm costs almost nothing extra for the firewall arms.
- A call budget stops the batch cleanly (partial results are saved) so credit cannot be burned by accident.
- Results are saved to results/agent_eval.json; the live app only READS them.
"""
import hashlib
import json
import time
from pathlib import Path

from app.config import REPO_ROOT, get_settings, load_domain_config
from app.services import datasets, nemotron_client
from app.services.data_store import DataStore
from app.services.llm_agent import run_agent_case
from app.services.nemotron_client import NemotronError
from app.services.replay_engine import _rate

RESULTS_DIR = REPO_ROOT / "results"
RESULTS_PATH = RESULTS_DIR / "agent_eval.json"
CACHE_PATH = RESULTS_DIR / "llm_cache.jsonl"


class BudgetExceeded(Exception):
    pass


class LLMCache:
    def __init__(self, path: Path | None = CACHE_PATH):
        self.path, self.data = path, {}
        if path and path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rec = json.loads(line)
                    self.data[rec["key"]] = rec["value"]

    def get(self, key):
        return self.data.get(key)

    def put(self, key, value) -> None:
        self.data[key] = value
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"key": key, "value": value}) + "\n")


class AgentClient:
    """Calls the agent model through Nebius (OpenAI-compatible) with caching, retries and a call budget."""

    def __init__(self, model: str | None = None, settings=None, transport=None, cache: LLMCache | None = None,
                 max_calls: int | None = None, retries: int = 2, sleep=time.sleep):
        self.settings = settings or get_settings()
        self.model = model or self.settings.agent_model
        self.transport, self.cache, self.max_calls = transport, cache or LLMCache(None), max_calls
        self.retries, self.sleep = retries, sleep
        self.calls_made = self.cache_hits = self.prompt_tokens = self.completion_tokens = 0

    def complete(self, messages: list, tools: list, temperature: float, run_idx: int) -> dict:
        key = hashlib.sha256(json.dumps([self.model, temperature, run_idx, messages, tools],
                                        sort_keys=True).encode()).hexdigest()
        hit = self.cache.get(key)
        if hit is not None:
            self.cache_hits += 1
            return {**hit, "cached": True}
        if self.max_calls is not None and self.calls_made >= self.max_calls:
            raise BudgetExceeded(f"call budget of {self.max_calls} reached")
        last = None
        for attempt in range(self.retries + 1):
            try:
                resp = nemotron_client.chat_raw(self.model, messages, tools, temperature,
                                                self.settings, transport=self.transport)
                break
            except NemotronError as exc:
                last = exc
                if attempt < self.retries:
                    self.sleep(2 * (attempt + 1))
        else:
            raise last
        self.calls_made += 1
        self.prompt_tokens += resp.get("prompt_tokens") or 0
        self.completion_tokens += resp.get("completion_tokens") or 0
        self.cache.put(key, resp)
        return {**resp, "cached": False}


ATTACK_SETS = {"original": datasets.load_train_attacks, "realistic": datasets.load_realistic_attacks,
               "new": datasets.load_new_attacks, "struct": datasets.load_struct_attacks,
               "body": datasets.load_body_attacks, "blind": datasets.load_blind_attacks,
               "named": datasets.load_named_attacks}
RESULT_FILES = {"original": "agent_eval.json", "realistic": "agent_eval_realistic.json",
                "new": "agent_eval_new.json", "struct": "agent_eval_struct.json",
                "body": "agent_eval_body.json", "blind": "agent_eval_blind.json",
                "named": "agent_eval_named.json"}

def select_cases(kinds=("train_attack", "held_out_attack", "legitimate"), limit_per_kind: int | None = None,
                 attack_set: str = "blind", legit_set: str = "blind") -> list:
    """attack_set picks the TRAINING-type attacks; legit_set picks which legitimate tasks are used."""
    legit_loader = datasets.load_new_legit_tasks if legit_set == "new" else datasets.load_legitimate_tasks
    cases = []
    for kind, loader in (("train_attack", ATTACK_SETS[attack_set]), ("held_out_attack", datasets.load_held_out_attacks),
                         ("legitimate", legit_loader)):
        if kind in kinds:
            items = loader()
            cases += items[:limit_per_kind] if limit_per_kind else items
    return cases


def save_results(path: Path, meta: dict, runs: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"meta": meta, "runs": runs}, indent=1), encoding="utf-8")
    tmp.replace(path)


def run_batch(client, cases: list, arms: dict, runs: int, temperature: float, out_path: Path | None = None,
              progress=print, extra_meta: dict | None = None) -> dict:
    """arms: {name: policy dict or None}. Returns {'meta', 'runs'}; stops cleanly if the call budget is hit."""
    base, cfg = DataStore.from_files(), load_domain_config()
    results, stopped = [], False
    meta = {"model": client.model, "temperature": temperature, "runs_per_case": runs, "arms": list(arms),
            "cases": len(cases), "stopped_early": False, **(extra_meta or {})}
    try:
        for i, case in enumerate(cases, 1):
            for run in range(runs):
                for name, policy in arms.items():
                    results.append(run_agent_case(case, policy, client, base, cfg, name, run, temperature))
            progress(f"[{i}/{len(cases)}] {case['case_id']}  calls={client.calls_made} cached={client.cache_hits}")
            meta.update(_totals(client))
            if out_path:
                save_results(out_path, meta, results)
    except BudgetExceeded as exc:
        stopped = True
        progress(f"STOPPED: {exc}. Partial results were saved; rerun to continue (cached calls are free).")
    meta.update(_totals(client))
    meta["stopped_early"] = stopped
    if out_path:
        save_results(out_path, meta, results)
    return {"meta": meta, "runs": results}


def _totals(client) -> dict:
    return {"model_calls_made": client.calls_made, "cache_hits": client.cache_hits,
            "prompt_tokens": client.prompt_tokens, "completion_tokens": client.completion_tokens}


def summarize_runs(runs: list) -> dict:
    """Per-arm rates. Run-level rates treat each run as a sample; attack-level rates treat each attack as a unit
    ('succeeded in at least one run'), which is the fairer unit because runs of one attack are not independent."""
    arms = {}
    for arm in dict.fromkeys(r["arm"] for r in runs):
        rs = [r for r in runs if r["arm"] == arm]
        entry = {}
        for kind, label in (("train_attack", "train"), ("held_out_attack", "held_out"), ("body_attack", "body")):
            kr = [r for r in rs if r["kind"] == kind]
            if not kr:
                continue
            attacks = dict.fromkeys(r["case_id"] for r in kr)
            any_ok = sum(any(x["succeeded"] for x in kr if x["case_id"] == cid) for cid in attacks)
            n = len(kr)
            entry[label] = {
                "runs": n,
                "attempted": _rate(sum(r["attempted"] for r in kr), n),
                "succeeded": _rate(sum(r["succeeded"] for r in kr), n),
                "blocked": _rate(sum(r["outcome"] == "attack_blocked" for r in kr), n),
                "not_attempted": _rate(sum(r["outcome"] == "attack_not_attempted" for r in kr), n),
                "errors": _rate(sum(r["outcome"] == "agent_error" for r in kr), n),
                "attacks_succeeded_at_least_once": _rate(any_ok, len(attacks)),
            }
        lr = [r for r in rs if r["kind"] == "legitimate"]
        if lr:
            n = len(lr)
            entry["legit"] = {
                "runs": n,
                "completed": _rate(sum(r["outcome"] == "legit_completed" for r in lr), n),
                "blocked": _rate(sum(r["outcome"] == "legit_blocked" for r in lr), n),
                "incomplete": _rate(sum(r["outcome"] == "legit_incomplete" for r in lr), n),
                "errors": _rate(sum(r["outcome"] == "agent_error" for r in lr), n),
            }
        entry["malformed_calls"] = sum(r["malformed_calls"] for r in rs)
        arms[arm] = entry
    return arms


def load_saved(path: Path | None = None, attack_set: str = "original"):
    path = path or (RESULTS_DIR / RESULT_FILES[attack_set])
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
