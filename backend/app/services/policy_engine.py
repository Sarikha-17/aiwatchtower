"""Versioned, declarative policy rules evaluated over LABELS. Policies decide; detectors only label."""
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from app.config import DomainConfig
from app.services import detectors
from app.services.data_store import DataStore

SUPPORTED_CONDITIONS = {
    "tool",
    "recipient_external",
    "recipient_allowlisted",
    "body_contains_any",
    "attachment_tags_any",
    "influenced_by_untrusted_content",
}


class PolicyError(Exception):
    pass


@dataclass
class Decision:
    decision: str  # ALLOW | BLOCK | REVIEW
    policy_id: str | None
    policy_version: int | None
    reasons: list = field(default_factory=list)
    risk_level: str = "low"
    explanation: str = ""
    labels: dict = field(default_factory=dict)
    latency_ms: float = 0.0
    rule_name: str | None = None


def load_policy(path: Path) -> dict:
    policy = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    validate_policy(policy)
    return policy


def validate_policy(policy: dict) -> None:
    """A policy is either one rule (when/then at top level) or an additive list under 'rules'."""
    for key in ("id", "version"):
        if key not in policy:
            raise PolicyError(f"policy missing field: {key}")
    raw = policy["rules"] if "rules" in policy else [policy]
    if not raw:
        raise PolicyError("policy has no rules")
    for rule in raw:
        for key in ("when", "then"):
            if key not in rule:
                raise PolicyError(f"policy missing field: {key}")
        unknown = set(rule["when"]) - SUPPORTED_CONDITIONS
        if unknown:
            raise PolicyError(f"unsupported conditions: {sorted(unknown)}")
        if rule["then"] not in ("block", "review"):
            raise PolicyError("policy 'then' must be 'block' or 'review'")


def rules_of(policy: dict) -> list:
    """Normalized rule list for a policy (single-rule or additive 'rules' form)."""
    multi = "rules" in policy
    raw = policy["rules"] if multi else [policy]
    return [{
        "id": policy["id"], "version": policy["version"],
        "name": r.get("name") if multi else None,
        "severity": r.get("severity", policy.get("severity", "high")),
        "when": r["when"], "then": r["then"],
    } for r in raw]


def build_context(tool: str, args: dict, store: DataStore, cfg: DomainConfig, influenced: bool) -> dict:
    """Labels about one proposed tool call. Only labels: no decisions."""
    ctx = {"tool": tool, "influenced_by_untrusted_content": influenced}
    if tool == "email.send":
        recipient_class = detectors.classify_recipient(args["to"], cfg)
        ctx.update(
            recipient_class=recipient_class,
            recipient_external=recipient_class != "internal",
            recipient_allowlisted=recipient_class == "allowlisted_external",
            body=args.get("body", ""),
            attachment_tags=detectors.attachment_tags(args.get("attachment_id"), store),
        )
    return ctx


def rule_matches(policy: dict, ctx: dict) -> tuple[bool, list]:
    """All conditions must hold (AND). Returns (matched, human-readable reasons)."""
    reasons = []
    for key, expected in policy["when"].items():
        if key == "tool":
            ok = ctx.get("tool") == expected
            why = f"tool is {expected}"
        elif key in ("recipient_external", "recipient_allowlisted", "influenced_by_untrusted_content"):
            ok = ctx.get(key) is expected
            why = f"{key} is {str(expected).lower()}"
        elif key == "body_contains_any":
            body = ctx.get("body", "").lower()
            hits = [w for w in expected if w.lower() in body]
            ok = bool(hits)
            why = f"body contains {hits}"
        elif key == "attachment_tags_any":
            hits = [t for t in ctx.get("attachment_tags", []) if t in expected]
            ok = bool(hits)
            why = f"attachment tagged {hits}"
        else:  # unreachable after validate_policy
            raise PolicyError(f"unsupported condition: {key}")
        if not ok:
            return False, []
        reasons.append(why)
    return True, reasons


class PolicyEngine:
    def __init__(self, policies: list):
        for p in policies:
            validate_policy(p)
        self.policies = policies

    def evaluate(self, ctx: dict) -> Decision:
        for policy in self.policies:
            for rule in rules_of(policy):
                matched, reasons = rule_matches(rule, ctx)
                if matched:
                    verdict = "BLOCK" if rule["then"] == "block" else "REVIEW"
                    tag = f" [{rule['name']}]" if rule["name"] else ""
                    return Decision(
                        decision=verdict,
                        policy_id=rule["id"],
                        policy_version=rule["version"],
                        reasons=reasons,
                        risk_level=rule["severity"],
                        explanation=(
                            f"{verdict} by {rule['id']} v{rule['version']}{tag}: "
                            + "; ".join(reasons) + "."
                        ),
                        rule_name=rule["name"],
                    )
        return Decision(
            decision="ALLOW", policy_id=None, policy_version=None,
            reasons=["no policy rule matched"], risk_level="low",
            explanation="No policy rule matched this action, so it is allowed.",
        )
