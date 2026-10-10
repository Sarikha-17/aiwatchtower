"""Minimal OpenAI-compatible chat client for Nebius Token Factory (plain HTTPS via httpx).

Model IDs come from environment variables only. Every call records the model role,
latency and token usage. Nothing here decides security outcomes: models only advise.
"""
import json
import re
import time

import httpx

from app.config import Settings, get_settings


class NemotronError(Exception):
    """API unavailable, misconfigured or returned an error."""


def extract_json(text: str):
    """Return the first JSON object found in model text (handles <think> blocks and code fences)."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None


def model_for(role: str, settings: Settings) -> str:
    return {"nano": settings.nano_model, "super": settings.super_model, "ultra": settings.ultra_model}[role]


def chat_json(role: str, messages: list, settings: Settings | None = None,
              timeout: float = 90.0, transport=None) -> dict:
    """Call one model role. Returns text, parsed JSON (or None), model, latency_ms, usage, est cost."""
    settings = settings or get_settings()
    model = model_for(role, settings)
    if not settings.api_key:
        raise NemotronError("NEBIUS_API_KEY is not set")
    if not model:
        raise NemotronError(f"no model ID configured for role '{role}' (set NEMOTRON_{role.upper()}_MODEL)")
    url = settings.base_url.rstrip("/") + "/chat/completions"
    started = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout, transport=transport) as client:
            resp = client.post(
                url,
                headers={"Authorization": f"Bearer {settings.api_key}"},
                json={"model": model, "messages": messages, "temperature": 0.1, "max_tokens": 1500},
            )
    except httpx.HTTPError as exc:
        raise NemotronError(f"request failed: {type(exc).__name__}") from exc
    latency_ms = round((time.perf_counter() - started) * 1000, 1)
    if resp.status_code != 200:
        raise NemotronError(f"API returned HTTP {resp.status_code}: {resp.text[:200]}")
    try:
        data = resp.json()
        text = data["choices"][0]["message"]["content"] or ""
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise NemotronError("unexpected API response shape") from exc
    usage = data.get("usage") or {}
    pt, ct = usage.get("prompt_tokens"), usage.get("completion_tokens")
    cost = None
    if pt is not None and ct is not None and settings.price_in_per_1m is not None and settings.price_out_per_1m is not None:
        cost = round((pt * settings.price_in_per_1m + ct * settings.price_out_per_1m) / 1_000_000, 6)
    return {"text": text, "parsed": extract_json(text), "model": model, "model_role": role,
            "latency_ms": latency_ms, "prompt_tokens": pt, "completion_tokens": ct, "estimated_cost_usd": cost}
