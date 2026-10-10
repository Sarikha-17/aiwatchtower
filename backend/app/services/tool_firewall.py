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
    def __init__(self, engine: PolicyEngine, store: DataStore, cfg: DomainConfig,
                 intent_checker=None, intent_mode: str = "off"):
        self.engine = engine
        self.store = store
        self.cfg = cfg
        self.intent_checker = intent_checker  # optional, advisory (see intent_check.py)
        self.intent_mode = intent_mode

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
            self._apply_intent_check(decision, tool, args, tracker)
        decision.latency_ms = round((time.perf_counter() - start) * 1000, 3)
        return decision

    def _apply_intent_check(self, decision: Decision, tool: str, args: dict, tracker: ProvenanceTracker) -> None:
        """Advisory model opinion. It can annotate, or escalate ALLOW -> REVIEW. It can never relax a BLOCK."""
        if self.intent_checker is None or tool != "email.send":
            return
        result = self.intent_checker(tracker.raw_request, tool, args)
        decision.labels["intent_check"] = result
        if (self.intent_mode == "escalate" and decision.decision == "ALLOW"
                and result.get("intent_aligned") is False and result.get("confidence", 0) >= 0.8):
            decision.decision = "REVIEW"
            decision.policy_id = "NANO_INTENT_CHECK"
            decision.risk_level = "medium"
            decision.reasons = decision.reasons + ["model judged the action not aligned with the user request"]
            decision.explanation = ("REVIEW by NANO_INTENT_CHECK (advisory model escalation): "
                                    + result.get("reason", "") + " Held for human review.")
