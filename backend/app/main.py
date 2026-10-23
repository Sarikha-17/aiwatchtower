"""AIWatchTower API.  Run from backend/:  uvicorn app.main:app --reload"""
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.config import POLICY_DIR, get_settings, load_dotenv

load_dotenv()  # read ../.env before anything else

from app.services import agent_eval, patch_service, policy_store, replay_engine, trace_recorder, usage_guard  # noqa: E402
from app.services.patch_service import ServiceError  # noqa: E402
from app.services.policy_engine import load_policy  # noqa: E402
from app.services.runner import load_scenarios, run_by_id  # noqa: E402

app = FastAPI(title="AIWatchTower", version="0.3.0")
STATIC_DIR = Path(__file__).parent / "static"


class RunRequest(BaseModel):
    scenario_id: str
    mode: str = "active"  # none | active | v<N> (a stored policy version)


class ProposeRequest(BaseModel):
    trace_id: str


class RejectRequest(BaseModel):
    reason: str | None = None


def _svc(fn, *args):
    try:
        return fn(*args)
    except ServiceError as exc:
        raise HTTPException(exc.status, exc.message) from exc


@app.get("/health")
def health():
    s = get_settings()
    return {"status": "ok", "demo_mode": s.demo_mode, "model_api_configured": bool(s.api_key and s.super_model),
            "model_calls_today": usage_guard.calls_today(), "model_calls_cap": s.max_model_calls_per_day,
            "reset_enabled": s.allow_demo_reset}


@app.get("/api/scenarios")
def scenarios():
    return [{k: s[k] for k in ("scenario_id", "title", "kind", "user_request")} for s in load_scenarios()]


@app.post("/api/agent/run-scenario")
def run_scenario_endpoint(req: RunRequest):
    if req.scenario_id not in {s["scenario_id"] for s in load_scenarios()}:
        raise HTTPException(404, f"unknown scenario: {req.scenario_id}")
    if req.mode == "none":
        policy = None
    elif req.mode == "active":
        policy = policy_store.get_active()
    elif req.mode.startswith("v") and req.mode[1:].isdigit():
        policy = policy_store.get_policy(int(req.mode[1:]))
        if policy is None:
            raise HTTPException(404, f"policy version not found: {req.mode}")
    elif req.mode.startswith("eval:v") and req.mode[6:].isdigit() and 3 <= int(req.mode[6:]) <= 6:
        # The evaluation policies from policies/policy_v<N>.yaml (the ones measured in the README).
        path = POLICY_DIR / f"policy_v{req.mode[6:]}.yaml"
        if not path.exists():
            raise HTTPException(404, f"evaluation policy file not found: {path.name}")
        policy = load_policy(path)
    else:
        raise HTTPException(400, "mode must be 'none', 'active', 'v<N>' or 'eval:v<N>'")
    trace = run_by_id(req.scenario_id, policy, live=True)
    trace_recorder.save_trace(trace)
    return trace.to_dict()


class ReviewRequest(BaseModel):
    action: str  # approve | deny


@app.post("/api/traces/{trace_id}/review")
def resolve_review(trace_id: str, req: ReviewRequest):
    """Human decision on a call the firewall held (REVIEW). Approve runs the held call; deny leaves it unrun.
    The decision is recorded on the trace. A hold is a speed bump, not a wall: an approval really executes."""
    if req.action not in ("approve", "deny"):
        raise HTTPException(400, "action must be 'approve' or 'deny'")
    trace = trace_recorder.get_trace(trace_id)
    if trace is None:
        raise HTTPException(404, "trace not found")
    review = trace.get("review")
    if not review or review.get("state") != "pending":
        raise HTTPException(409, "this trace has no pending review")
    event = trace["events"][review["step"] - 1]
    from app.config import load_domain_config
    from app.services import evaluator
    from app.services.data_store import DataStore
    from app.services.tools import ToolError, ToolRunner
    store, cfg = DataStore.from_files(), load_domain_config()
    if req.action == "approve":
        runner = ToolRunner(store)
        try:
            runner.execute(event["tool"], event["args"])
        except ToolError as exc:
            raise HTTPException(400, str(exc)) from exc
        event["executed"] = True
        event["result_summary"] = "executed after human approval"
        trace["attack_succeeded"] = evaluator.attack_succeeded(runner.outbox, store, cfg)
        trace["verdict"] = evaluator.verdict(trace["kind"], trace["attack_succeeded"], True)
        review["state"] = "approved"
    else:
        event["result_summary"] = "denied by human reviewer: not executed"
        review["state"] = "denied"
    trace_recorder.save_trace(trace)
    return trace


@app.get("/api/traces")
def traces():
    return trace_recorder.list_traces()


@app.get("/api/traces/{trace_id}")
def trace_detail(trace_id: str):
    trace = trace_recorder.get_trace(trace_id)
    if trace is None:
        raise HTTPException(404, "trace not found")
    return trace


# ---- policies ----
@app.get("/api/policies/active")
def active_policy():
    return policy_store.get_active()


@app.get("/api/policies/history")
def policy_history():
    return {"versions": policy_store.list_versions(), "log": policy_store.list_history()}


@app.post("/api/policies/{version}/rollback")
def rollback(version: int):
    _svc(patch_service.rollback, version)
    return {"active_policy": policy_store.get_active()}


# ---- patches ----
@app.post("/api/patches/propose")
def propose(req: ProposeRequest):
    return _svc(patch_service.propose, req.trace_id)


@app.get("/api/patches")
def patches():
    return [{k: p[k] for k in ("patch_id", "created_at", "status", "base_version")} for p in patch_service.list_patches()]


@app.get("/api/patches/{patch_id}")
def patch_detail(patch_id: str):
    return _svc(patch_service.get_patch, patch_id)


@app.post("/api/patches/{patch_id}/validate")
def patch_validate(patch_id: str):
    return _svc(patch_service.validate, patch_id)


@app.post("/api/patches/{patch_id}/replay")
def patch_replay(patch_id: str):
    return _svc(patch_service.replay, patch_id)


@app.post("/api/patches/{patch_id}/approve")
def patch_approve(patch_id: str):
    return _svc(patch_service.approve, patch_id)


@app.post("/api/patches/{patch_id}/reject")
def patch_reject(patch_id: str, req: RejectRequest):
    return _svc(patch_service.reject, patch_id, req.reason)


@app.post("/api/admin/reset")
def reset_demo():
    if not get_settings().allow_demo_reset:
        raise HTTPException(403, "demo reset is disabled on this deployment")
    policy_store.reset()
    return {"active_policy": policy_store.get_active()}


# ---- evidence ----
@app.get("/api/metrics")
def metrics():
    """Level 2 reference numbers (hand-written v2 candidate)."""
    return replay_engine.compute_metrics()


@app.get("/api/agent-evidence")
def agent_evidence(set: str = "original"):
    """Saved results of the offline real-agent batch (read only). No transcripts are returned.
    set = original (explicit injections) or realistic (disguised business requests)."""
    if set not in agent_eval.ATTACK_SETS:
        raise HTTPException(400, f"set must be one of {sorted(agent_eval.ATTACK_SETS)}")
    saved = agent_eval.load_saved(attack_set=set)
    if saved is None:
        return {"available": False, "set": set}
    return {"available": True, "set": set, "meta": saved["meta"], "summary": agent_eval.summarize_runs(saved["runs"])}


@app.get("/api/evidence")
def evidence():
    return replay_engine.compute_evidence(policy_store.list_versions())


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")
