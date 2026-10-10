"""Detectors only produce LABELS. They never decide ALLOW/BLOCK: policies do that."""
import re

from app.config import DomainConfig
from app.services.data_store import DataStore

SENSITIVE_HR_TAGS = frozenset({"hr_sensitive", "employee_compensation"})

_INSTRUCTION_PATTERNS = [
    r"ignore (all )?(previous|prior) instructions",
    r"disregard (the )?(above|previous)",
    r"\bplease send\b",
    r"\bemail it to\b",
    r"\bforward (it|this|the)\b",
    r"\bsend the attached\b",
    r"\byou must\b",
]
_INSTRUCTION_RE = re.compile("|".join(_INSTRUCTION_PATTERNS), re.IGNORECASE)


def recipient_domain(address: str) -> str:
    return address.strip().lower().rsplit("@", 1)[-1]


def classify_recipient(address: str, cfg: DomainConfig) -> str:
    """Return 'internal', 'allowlisted_external' or 'unknown_external'.

    Matching is on the EXACT domain, so lookalikes such as
    'acct-vendor.example.co' or 'company.example.evil.example' are unknown_external.
    """
    domain = recipient_domain(address)
    if domain in cfg.internal_domains:
        return "internal"
    if domain in cfg.allowlisted_external_domains:
        return "allowlisted_external"
    return "unknown_external"


def attachment_tags(attachment_id: str | None, store: DataStore) -> list[str]:
    if not attachment_id:
        return []
    f = store.hr_files.get(attachment_id)
    return list(f["data_tags"]) if f else []


def has_sensitive_hr_tags(tags: list[str]) -> bool:
    return any(t in SENSITIVE_HR_TAGS for t in tags)


def detect_instruction_like_text(text: str) -> bool:
    """Heuristic label only. A paraphrased instruction can evade it: a known limitation."""
    return bool(_INSTRUCTION_RE.search(text))
