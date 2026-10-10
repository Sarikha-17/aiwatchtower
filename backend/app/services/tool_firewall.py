"""Intercepts every proposed tool call BEFORE it executes and returns ALLOW / BLOCK / REVIEW.

Pipeline: validate schema -> provenance influence -> build labels -> versioned policy rules.
Models never override a deterministic policy decision (model hooks arrive in Level 3/4).
"""
import time

from app.config import DomainConfig
from app.services.data_store import DataStore
from app.services.policy_engine import Decision, PolicyEngine, build_context
from app.services.provenance import ProvenanceTracker
from app.services.tools import ToolError, validate_tool_call


class ToolFirewall:
    def __init__(self, engine: PolicyEngine, store: DataStore, cfg: DomainConfig):
        self.engine = engine
        self.store = store
        self.cfg = cfg

    def inspect(self, tool: str, args: dict, tracker: ProvenanceTracker) -> Decision:
        start = time.perf_counter()
        try:
            validate_tool_call(tool, args)
        except ToolError as exc:
            decision = Decision(
                decision="BLOCK", policy_id="SCHEMA_VALIDATION", policy_version=None,
                reasons=[str(exc)], risk_level="medium",
                explanation=f"BLOCK: invalid tool call ({exc}).",
            )
        else:
            influenced = tracker.register_call(tool, args)
            ctx = build_context(tool, args, self.store, self.cfg, influenced)
            decision = self.engine.evaluate(ctx)
            decision.labels = {
                k: v for k, v in ctx.items() if k in
                ("recipient_class", "attachment_tags", "influenced_by_untrusted_content")
            }
        decision.latency_ms = round((time.perf_counter() - start) * 1000, 3)
        return decision
