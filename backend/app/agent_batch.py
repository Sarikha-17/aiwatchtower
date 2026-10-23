"""Offline batch evaluation of the real LLM agent.

Examples (run from backend/ with the venv active):
  python -m app.agent_batch --limit-per-kind 3 --runs 1 --max-calls 60      # small pilot first
  python -m app.agent_batch --runs 3 --temperature 0.3 --max-calls 600      # full run
Arms: none (no firewall), v1 (weak keyword policy), v2 (additive patch, same rule Nemotron proposed).
Rerunning is cheap: every model call is cached in results/llm_cache.jsonl.
"""
import argparse
import copy

from app.config import POLICY_DIR, get_settings, load_dotenv
from app.services import agent_eval
from app.services.patch_service import build_candidate
from app.services.patcher import seeded_patch
from app.services.policy_engine import load_policy
from app.services.replay_engine import load_candidate


def main() -> None:
    load_dotenv()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--arms", default="none,v1,v2")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--temperature", type=float, default=0.3)
    ap.add_argument("--max-calls", type=int, default=400, help="stop after this many NEW (uncached) model calls")
    ap.add_argument("--limit-per-kind", type=int, default=None, help="pilot: only the first N cases of each kind")
    ap.add_argument("--model", default=None, help="override AGENT_MODEL (default: AGENT_MODEL or Nano)")
    ap.add_argument("--attack-set", choices=list(agent_eval.ATTACK_SETS), default="original",
                    help="original = explicit injections; realistic = disguised business requests")
    ap.add_argument("--legit-set", choices=["original", "new", "share", "finance"], default="original")
    ap.add_argument("--extra-policy", action="append", default=[], metavar="NAME=PATH",
                    help="add an arm from a policy YAML file, e.g. patched=../policies/policy_patched.yaml")
    ap.add_argument("--out", default=None, help="default depends on --attack-set (never overwrites the other set)")
    args = ap.parse_args()

    s = get_settings()
    model = args.model or s.agent_model
    if not s.api_key or not model:
        print("Set NEBIUS_API_KEY and AGENT_MODEL (or NEMOTRON_NANO_MODEL) in ../.env first.")
        return
    v1 = load_candidate(1)
    v2 = build_candidate(v1, seeded_patch(1, "batch"), 2)
    v3 = copy.deepcopy(v2)
    v3["version"] = 3
    v3["rules"][0]["when"]["influenced_by_untrusted_content"] = True
    v4 = copy.deepcopy(v3)
    v4["version"] = 4
    v4["rules"].append({"name": "review_sensitive_external",
        "when": {"tool": "email.send", "recipient_external": True, "recipient_allowlisted": False,
                 "attachment_tags_any": ["hr_sensitive", "employee_compensation"]},
        "then": "review", "severity": "high"})
    v5 = load_policy(POLICY_DIR / "policy_v5.yaml")
    v6 = load_policy(POLICY_DIR / "policy_v6.yaml")
    v7 = load_policy(POLICY_DIR / "policy_v7.yaml")
    policies = {"none": None, "v1": v1, "v2": v2, "v3": v3, "v4": v4, "v5": v5, "v6": v6, "v7": v7}
    for spec in args.extra_policy:
        name, _, path = spec.partition("=")
        policies[name] = load_policy(__import__("pathlib").Path(path))
    arms = {a: policies[a] for a in args.arms.split(",")}
    cases = agent_eval.select_cases(limit_per_kind=args.limit_per_kind, attack_set=args.attack_set, legit_set=args.legit_set)
    out_path = args.out or str(agent_eval.RESULTS_DIR / agent_eval.RESULT_FILES[args.attack_set])
    client = agent_eval.AgentClient(model=model, cache=agent_eval.LLMCache(), max_calls=args.max_calls)
    print(f"Agent model: {model} | attack set: {args.attack_set} | arms: {list(arms)} | cases: {len(cases)} | runs: {args.runs} | "
          f"temperature: {args.temperature} | max new calls: {args.max_calls}")
    out = agent_eval.run_batch(client, cases, arms, args.runs, args.temperature, __import__("pathlib").Path(out_path),
                              extra_meta={"attack_set": args.attack_set, "legit_set": args.legit_set})
    m = out["meta"]
    print(f"\nDone. New model calls: {m['model_calls_made']}, cache hits: {m['cache_hits']}, "
          f"tokens: {m['prompt_tokens']} in / {m['completion_tokens']} out")
    if s.price_in_per_1m is not None and s.price_out_per_1m is not None:
        cost = (m["prompt_tokens"] * s.price_in_per_1m + m["completion_tokens"] * s.price_out_per_1m) / 1e6
        print(f"Estimated cost: ${cost:.4f}")
    for arm, e in agent_eval.summarize_runs(out["runs"]).items():
        print(f"\n== arm: {arm} ==")
        for label in ("train", "held_out"):
            if label in e:
                k = e[label]
                print(f"  {label:8} attacks: attempted {k['attempted']['k']}/{k['runs']}  succeeded {k['succeeded']['k']}/{k['runs']}"
                      f"  blocked {k['blocked']['k']}  not attempted {k['not_attempted']['k']}  errors {k['errors']['k']}")
        if "legit" in e:
            k = e["legit"]
            print(f"  legit    completed {k['completed']['k']}/{k['runs']}  blocked {k['blocked']['k']}  "
                  f"incomplete {k['incomplete']['k']}  errors {k['errors']['k']}")
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
