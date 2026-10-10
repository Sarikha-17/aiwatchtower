import json

import httpx
import pytest

from app.services import datasets, patcher, nemotron_client
from app.services.nemotron_client import NemotronError, extract_json
from app.services.replay_engine import load_candidate
from app.services.runner import run_by_id


def failed_trace():
    return run_by_id("v1_bypass", 1).to_dict()


def test_extract_json_handles_think_blocks_and_fences():
    text = '<think>reasoning {not json}</think>\n```json\n{"a": 1}\n```'
    assert extract_json(text) == {"a": 1}
    assert extract_json("no json here") is None
    assert extract_json("{broken") is None


def test_prompt_never_contains_held_out_content():
    messages = patcher.build_messages(failed_trace(), load_candidate(1))
    text = json.dumps(messages)
    for case in datasets.load_held_out_attacks():
        assert case["case_id"] not in text
        if case.get("email"):
            assert case["email"]["body"] not in text


def test_held_out_trace_is_refused():
    trace = failed_trace(); trace["scenario_id"] = "held_out_attack_09"
    with pytest.raises(patcher.PatcherError):
        patcher.build_messages(trace, load_candidate(1))


def test_demo_mode_fallback_is_labeled(monkeypatch):
    out = patcher.propose_patch(failed_trace(), load_candidate(1))
    assert out["meta"]["demo_fallback"] is True
    assert "DEMO FALLBACK" in out["patch"]["reasoning"]


def test_no_model_and_no_demo_mode_raises(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    with pytest.raises(patcher.PatcherError):
        patcher.propose_patch(failed_trace(), load_candidate(1))


def _configure(monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "test-key")
    monkeypatch.setenv("NEMOTRON_SUPER_MODEL", "fake/super-model")
    monkeypatch.setenv("DEMO_MODE", "false")


def test_model_path_parses_fenced_json_and_overrides_patch_id(monkeypatch):
    _configure(monkeypatch)
    model_patch = patcher.seeded_patch(1, "x")
    model_patch["patch_id"] = "PATCH-model-chosen"
    seen = {}

    def handler(request: httpx.Request):
        seen["auth"] = request.headers["authorization"]
        seen["model"] = json.loads(request.content)["model"]
        body = {"choices": [{"message": {"content": "<think>hmm</think>```json\n" + json.dumps(model_patch) + "\n```"}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50}}
        return httpx.Response(200, json=body)

    out = patcher.propose_patch(failed_trace(), load_candidate(1), transport=httpx.MockTransport(handler))
    assert seen["model"] == "fake/super-model" and seen["auth"] == "Bearer test-key"
    assert out["patch"]["patch_id"] != "PATCH-model-chosen"  # server-assigned
    assert out["meta"]["demo_fallback"] is False and out["meta"]["prompt_tokens"] == 100
    assert out["meta"]["latency_ms"] is not None


def test_malformed_model_output_is_returned_for_validation_failure(monkeypatch):
    _configure(monkeypatch)
    handler = lambda req: httpx.Response(200, json={"choices": [{"message": {"content": "I cannot help"}}]})
    out = patcher.propose_patch(failed_trace(), load_candidate(1), transport=httpx.MockTransport(handler))
    assert out["patch"] is None and "cannot help" in out["raw_text"]


def test_api_error_falls_back_only_in_demo_mode(monkeypatch):
    _configure(monkeypatch)
    handler = lambda req: httpx.Response(500, text="boom")
    transport = httpx.MockTransport(handler)
    with pytest.raises(patcher.PatcherError):
        patcher.propose_patch(failed_trace(), load_candidate(1), transport=transport)
    monkeypatch.setenv("DEMO_MODE", "true")
    out = patcher.propose_patch(failed_trace(), load_candidate(1), transport=transport)
    assert out["meta"]["demo_fallback"] is True and "500" in out["meta"]["fallback_reason"]


def test_cost_estimate_uses_configured_prices(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setenv("MODEL_PRICE_INPUT_PER_1M_USD", "1.0")
    monkeypatch.setenv("MODEL_PRICE_OUTPUT_PER_1M_USD", "2.0")
    handler = lambda req: httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}],
                                                    "usage": {"prompt_tokens": 1000, "completion_tokens": 500}})
    out = nemotron_client.chat_json("super", [{"role": "user", "content": "x"}], transport=httpx.MockTransport(handler))
    assert out["estimated_cost_usd"] == pytest.approx(0.002)
    with pytest.raises(NemotronError):
        nemotron_client.chat_json("nano", [{"role": "user", "content": "x"}])  # no nano model configured
