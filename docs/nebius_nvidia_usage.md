# Nebius Token Factory and NVIDIA Nemotron usage

## Why a model at all
Writing a policy fix after a failure is open-ended reasoning over a trace, which suits a language model. Enforcement
is not: it stays deterministic. The model proposes; code validates, replay tests, and a human approves.

## Roles
| Role | Env var | Used for | Authority |
|---|---|---|---|
| Nemotron Super | `NEMOTRON_SUPER_MODEL` | Policy patcher (strict JSON) | Advisory; must pass the validator and human approval |
| Nemotron Nano | `NEMOTRON_NANO_MODEL` | Optional per-call intent check (live demo only) | Advisory; may escalate ALLOW to REVIEW, never relax a BLOCK |
| Nemotron Ultra | `NEMOTRON_ULTRA_MODEL` | Optional fallback if the Super call fails | Same as Super |

The app works with only Nano and Super (and with neither, in `DEMO_MODE`).

## Integration
- OpenAI-compatible `chat/completions` on Nebius Token Factory, called with `httpx`. Base URL from `NEBIUS_BASE_URL`.
- Model IDs come only from environment variables. Run `python -m app.check_nebius` to list the Nemotron IDs your key
  can use. Confirm availability, pricing, context window and tool-call support in the Token Factory model catalog.
- `<think>` blocks and code fences in model output are stripped before JSON parsing; invalid JSON becomes a stored
  validation failure, not a crash.
- Server-assigned patch IDs: a model-chosen ID is never trusted.

## Measurement
Every model call records role, model ID, latency, prompt/completion tokens and an estimated cost (when
`MODEL_PRICE_*` variables are set). The patch record shows these in the Patch Review tab.

## Failure handling
Timeouts and errors raise a clear message. With `DEMO_MODE=true` a deterministic seeded patch is used and clearly
labeled **DEMO FALLBACK** in the UI, API and README; with `DEMO_MODE=false` the patch request fails honestly.

## Held-out isolation
The patcher prompt contains only the single failed trace, the active policy and the allowed vocabulary. A test asserts
that no held-out case ID or content can appear in it.
