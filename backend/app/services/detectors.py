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
def _norm_text(s: str) -> str:
    return re.sub(r"\s+", " ", s.lower()).strip()


def body_leaks_sensitive_content(body: str, store: DataStore) -> bool:
    """Label: does an outgoing message body repeat content of a sensitive HR file?

    A file line leaks if at least two of its '|'-separated fields appear in the body
    (and, when the line has a pay figure of 5+ digits, that figure is one of them).
    Figures are compared with commas removed, so '18,50,000' matches '1850000'.
    Lines without '|' leak only if the whole line appears. Deterministic, no model involved.
    """
    if not body:
        return False
    text = _norm_text(body)
    digits_text = text.replace(",", "").replace(" ", "")
    for f in store.hr_files.values():
        if not has_sensitive_hr_tags(list(f.get("data_tags", []))):
            continue
        for line in str(f.get("content", "")).splitlines():
            fields = [x.strip() for x in line.split("|") if x.strip()]
            if len(fields) < 2:
                whole = _norm_text(line)
                if len(whole) >= 12 and whole in text:
                    return True
                continue
            matched, numeric_total, numeric_hit = 0, 0, 0
            for fld in fields:
                nd = re.sub(r"\D", "", fld)
                is_num = len(nd) >= 5
                hit = (nd in digits_text) if is_num else (_norm_text(fld) in text)
                numeric_total += is_num
                numeric_hit += is_num and hit
                matched += hit
            if matched >= 2 and (numeric_total == 0 or numeric_hit >= 1):
                return True
    return False