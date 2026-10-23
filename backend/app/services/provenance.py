"""Per-content provenance labels and the deterministic 'influenced by untrusted content' rule.

A proposed tool call is INFLUENCED if BOTH hold:
  (a) at least one untrusted item was read earlier in the same trace, and
  (b) at least one target identifier of the call (recipient address, attachment ID or
      file ID) does not appear in the trusted user request text.

There is no session-wide taint flag: labels are kept per content item.
"""
from app.schemas.models import ContentLabel
from app.services.detectors import detect_instruction_like_text


def label_for_email(email: dict) -> ContentLabel:
    # Email bodies are data, not authority: always untrusted.
    return ContentLabel(
        source_type="email",
        source_id=email["email_id"],
        trust_level="untrusted",
        contains_instruction_like_text=detect_instruction_like_text(
            f"{email['subject']} {email['body']}"
        ),
        data_tags=["vendor_document"],
    )


def label_for_hr_file(hr_file: dict) -> ContentLabel:
    return ContentLabel(
        source_type="hr_file",
        source_id=hr_file["file_id"],
        trust_level="internal_sensitive",
        data_tags=list(hr_file["data_tags"]),
    )


def target_identifiers(tool: str, args: dict) -> list[str]:
    """The identifiers a call acts on, used for rule (b)."""
    ids = []
    if tool == "email.send":
        ids.append(args.get("to"))
        ids.append(args.get("attachment_id"))
    elif tool == "file.share":
        ids.append(args.get("recipient"))
        ids.append(args.get("file_id"))
    elif tool == "hr.file.read":
        ids.append(args.get("file_id"))
    elif tool == "email.read":
        ids.append(args.get("email_id"))
    return [i for i in ids if i]


class ProvenanceTracker:
    def __init__(self, trusted_request: str):
        self.raw_request = trusted_request
        self.trusted_request = trusted_request.lower()
        self.labels: list[ContentLabel] = []

    def record_read(self, label: ContentLabel) -> None:
        self.labels.append(label)

    def untrusted_labels(self) -> list[ContentLabel]:
        return [l for l in self.labels if l.trust_level == "untrusted"]

    def is_influenced(self, tool: str, args: dict) -> bool:
        if not self.untrusted_labels():
            return False  # rule (a) fails
        ids = target_identifiers(tool, args)
        return any(i.lower() not in self.trusted_request for i in ids)  # rule (b)

    def register_call(self, tool: str, args: dict) -> bool:
        """Evaluate influence and, if influenced, record it on the untrusted labels."""
        influenced = self.is_influenced(tool, args)
        if influenced:
            for label in self.untrusted_labels():
                if tool not in label.influenced_actions:
                    label.influenced_actions.append(tool)
        return influenced
