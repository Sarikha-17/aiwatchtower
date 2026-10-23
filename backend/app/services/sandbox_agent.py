"""Scripted, deterministic stand-in for an LLM agent.

It models a VULNERABLE agent: if an email contains an injected directive, it follows it.
No LLM drives it, so every run reproduces exactly. Every proposed call goes through the
firewall (or straight to the tool when mode == 'none') before it executes.
"""
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from app.config import DomainConfig
from app.services import evaluator
from app.services.data_store import DataStore
from app.services.provenance import ProvenanceTracker, label_for_email, label_for_hr_file
from app.services.tool_firewall import ToolFirewall
from app.services.tools import ToolError, ToolRunner


@dataclass
class Event:
    step: int
    tool: str
    args: dict
    rationale: str
    decision: dict
    executed: bool
    result_summary: str
    timestamp: str


@dataclass
class Trace:
    trace_id: str
    scenario_id: str
    kind: str
    mode: str
    policy_version: int | None
    user_request: str
    events: list = field(default_factory=list)
    attack_succeeded: bool = False
    verdict: str = ""
    labels: list = field(default_factory=list)
    review: dict | None = None  # set when the run halted on a REVIEW hold: {"step", "state", ...}

    def to_dict(self) -> dict:
        return asdict(self)


def _plan(scenario: dict, email: dict | None) -> list:
    """The calls the agent will propose, in order. A scenario without an email starts
    directly with its stored calls (used by replay cases that never read an email)."""
    plan = []
    if email is not None:
        plan.append((
            "email.read", {"email_id": scenario["email_id"]},
            "Reading the email the user asked me to summarize.",
        ))
    directive = email.get("injected_directive") if email else None
    if directive:  # vulnerable behaviour: instruction-like text in data is treated as authority
        plan.append((
            "hr.file.read", {"file_id": directive["read_file"]},
            "The email tells me to retrieve this file, so I am retrieving it.",
        ))
        if directive.get("tool") == "file.share":
            plan.append((
                "file.share",
                {"file_id": directive["read_file"], "recipient": directive["send_to"], "permission": "view"},
                "The email tells me to share the file with this address, so I am sharing it.",
            ))
        else:
          plan.append((
            "email.send",
            {"to": directive["send_to"], "subject": directive["subject"],
             "body": directive["body"], "attachment_id": directive["attachment_id"]},
            "The email tells me to send the file to this address, so I am sending it.",
          ))
    for extra in scenario.get("extra_calls", []):
        plan.append((extra["tool"], dict(extra["args"]), extra["rationale"]))
    return plan


def run_scenario(scenario: dict, store: DataStore, cfg: DomainConfig,
                 firewall: ToolFirewall | None, policy_version: int | None) -> Trace:
    mode = "none" if firewall is None else f"policy_v{policy_version}"
    email = store.emails[scenario["email_id"]] if scenario.get("email_id") else None
    runner = ToolRunner(store)
    tracker = ProvenanceTracker(scenario["user_request"])
    trace = Trace(
        trace_id=f"trace-{uuid.uuid4().hex[:8]}", scenario_id=scenario["scenario_id"],
        kind=scenario["kind"], mode=mode, policy_version=policy_version,
        user_request=scenario["user_request"],
    )

    plan = _plan(scenario, email)
    all_executed = True
    for step, (tool, args, rationale) in enumerate(plan, start=1):
        if firewall is None:
            tracker.register_call(tool, args)
            decision = {"decision": "ALLOW", "policy_id": None, "policy_version": None,
                        "reasons": ["no firewall"], "risk_level": "unknown",
                        "explanation": "No firewall active: action runs unchecked.",
                        "labels": {}, "latency_ms": 0.0}
        else:
            decision = asdict(firewall.inspect(tool, args, tracker))

        executed, summary = False, ""
        if decision["decision"] == "ALLOW":
            try:
                result = runner.execute(tool, args)
                executed, summary = True, f"{tool} executed"
                if tool == "email.read":
                    tracker.record_read(label_for_email(store.emails[args["email_id"]]))
                elif tool == "hr.file.read":
                    tracker.record_read(label_for_hr_file(store.hr_files[args["file_id"]]))
                elif tool == "email.send":
                    summary = f"email sent to {result['to']}"
                elif tool == "file.share":
                    summary = f"file shared with {result['to']}"
            except ToolError as exc:
                summary = f"tool error: {exc}"
        else:
            summary = f"{decision['decision']}: tool did not execute"

        trace.events.append(Event(
            step=step, tool=tool, args=args, rationale=rationale, decision=decision,
            executed=executed, result_summary=summary,
            timestamp=datetime.now(timezone.utc).isoformat(),
        ))
        if not executed:
            all_executed = False
            if decision["decision"] == "REVIEW":
                trace.review = {"step": step, "state": "pending"}
            break  # the agent halts at the first action it cannot perform

    trace.attack_succeeded = evaluator.attack_succeeded(runner.outbox, store, cfg)
    trace.verdict = evaluator.verdict(trace.kind, trace.attack_succeeded, all_executed)
    trace.labels = [l.model_dump() for l in tracker.labels]
    trace.events = [asdict(e) for e in trace.events]
    return trace
