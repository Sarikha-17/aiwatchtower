"""AIWatchTower API.  Run from backend/:  uvicorn app.main:app --reload"""
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.services import replay_engine, trace_recorder
from app.services.runner import load_scenarios, run_by_id

app = FastAPI(title="AIWatchTower", version="0.1.0")
STATIC_DIR = Path(__file__).parent / "static"

MODES = {"none": None, "v1": 1, "v2": 2}


class RunRequest(BaseModel):
    scenario_id: str
    mode: str = "v1"  # none | v1 | v2


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/scenarios")
def scenarios():
    return [
        {k: s[k] for k in ("scenario_id", "title", "kind", "user_request")}
        for s in load_scenarios()
    ]


@app.post("/api/agent/run-scenario")
def run_scenario_endpoint(req: RunRequest):
    if req.mode not in MODES:
        raise HTTPException(400, f"mode must be one of {sorted(MODES)}")
    if req.scenario_id not in {s["scenario_id"] for s in load_scenarios()}:
        raise HTTPException(404, f"unknown scenario: {req.scenario_id}")
    trace = run_by_id(req.scenario_id, MODES[req.mode])
    trace_recorder.save_trace(trace)
    return trace.to_dict()


@app.get("/api/traces")
def traces():
    return trace_recorder.list_traces()


@app.get("/api/traces/{trace_id}")
def trace_detail(trace_id: str):
    trace = trace_recorder.get_trace(trace_id)
    if trace is None:
        raise HTTPException(404, "trace not found")
    return trace


@app.get("/api/metrics")
def metrics():
    return replay_engine.compute_metrics()


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")
