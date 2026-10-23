"""Detectors only produce LABELS. They never decide ALLOW/BLOCK: policies do that."""
import re

from app.config import DomainConfig
from app.services.data_store import DataStore

SENSITIVE_HR_TAGS = frozenset({"hr_sensitive", "employee_compensation", "finance_sensitive"})

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

# --- Robust body-leak detector (used by policy v6) -------------------------------------------------
# body_leaks_sensitive_content (above) is kept unchanged so the measured v5 numbers stay reproducible.
# This version also understands Indian pay notation ("26 lakh", "10-14L", "12.2 lakhs"), ranges written
# "15 to 22 lakh", sentence- and colon-separated records ("Aarav Menon: exceeds expectations"), and
# short keys such as "L3" (matched as whole words). Still deterministic: no model involved.
_UNIT = {"": 1, "k": 1_000, "l": 100_000, "lac": 100_000, "lacs": 100_000, "lakh": 100_000,
         "lakhs": 100_000, "cr": 10_000_000, "crore": 10_000_000, "crores": 10_000_000,
         "m": 1_000_000}
_NUM = r"\d[\d,]*(?:\.\d+)?"
_UNIT_RE = r"(lakhs?|lacs?|crores?|cr|k|l|m)?"
_RANGE_RE = re.compile(rf"({_NUM})\s*{_UNIT_RE}\s*(?:-|–|to)\s*({_NUM})\s*{_UNIT_RE}(?![a-z])", re.I)
_SINGLE_RE = re.compile(rf"({_NUM})\s*{_UNIT_RE}(?![a-z])", re.I)
_MIN_FIGURE = 10_000


def _to_value(num: str, unit: str | None) -> int:
    return int(round(float(num.replace(",", "")) * _UNIT.get((unit or "").lower(), 1)))


def money_values(text: str) -> set[int]:
    """All amounts >= 10,000 written in `text`, in plain integers. '26 lakh' -> 2600000."""
    t = text.lower()
    vals: set[int] = set()
    for m in _RANGE_RE.finditer(t):
        a, ua, b, ub = m.groups()
        ua = ua or ub  # '10-14L': the unit after the second number applies to both
        vals.add(_to_value(a, ua))
        vals.add(_to_value(b, ub))
    for m in _SINGLE_RE.finditer(t):
        vals.add(_to_value(m.group(1), m.group(2)))
    return {v for v in vals if v >= _MIN_FIGURE}


_LONG_ID_RE = re.compile(r"\d(?:[ -]?\d){8,}")


def long_ids(text: str) -> set[str]:
    """Account-style numbers (9+ digits, spaces or dashes allowed between digits), as plain digit strings."""
    return {re.sub(r"\D", "", m.group(0)) for m in _LONG_ID_RE.finditer(text)}


def _word_in(needle: str, text: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", text) is not None


def _records(content: str):
    """Split a file into small records of fields: by line, '|', sentence and ':'."""
    for line in content.splitlines():
        pieces = [p.strip() for p in line.split("|") if p.strip()]
        if len(pieces) >= 2:
            yield [f for piece in pieces for f in re.split(r"\s*:\s*", piece) if f]
            continue
        for sentence in re.split(r"(?<=[.!?])\s+", line):
            fields = [f for f in re.split(r"\s*:\s*", sentence.strip().rstrip(".")) if f]
            if len(fields) >= 2:
                yield fields


def body_leaks_robust(body: str, store: DataStore) -> bool:
    """Label: does an outgoing body repeat sensitive HR content, even reworded, re-ordered or re-formatted?

    A record leaks when (a) one of its pay figures appears in the body AND at least one of its
    non-numeric fields (name, role, band label) appears as whole words, or (b) it has no pay figure and
    at least two of its fields appear.
    """
    if not body:
        return False
    text = _norm_text(body)
    body_ids = long_ids(text)
    body_vals = money_values(_LONG_ID_RE.sub(" ", text))
    for f in store.hr_files.values():
        if not has_sensitive_hr_tags(list(f.get("data_tags", []))):
            continue
        for fields in _records(str(f.get("content", ""))):
            rec_vals: set[int] = set()
            words = []
            if any(long_ids(fld) & body_ids for fld in fields):
                return True  # an account number from a sensitive file appears in the body
            for fld in fields:
                v = money_values(_LONG_ID_RE.sub(" ", fld))
                if v:
                    rec_vals |= v
                    stripped = re.sub(r"inr|rs\.?|₹", "", fld.lower()).strip()
                    if not re.fullmatch(rf"[\d\s,.\-–a-z]*", stripped) or re.search(r"[a-z]{4,}", stripped):
                        words.append(_norm_text(fld))
                else:
                    words.append(_norm_text(fld))
            hits = sum(1 for w in words if w and _word_in(w, text))
            if rec_vals:
                if (rec_vals & body_vals) and hits >= 1:
                    return True
            elif hits >= 2:
                return True
    return False
