"""The three agent tools. They only touch fake data and never send real email."""
import hashlib
import json

from pydantic import ValidationError

from app.schemas.models import TOOL_ARG_MODELS
from app.services.data_store import DataStore


class ToolError(Exception):
    """Raised for invalid arguments, unknown tools or unknown IDs."""


def validate_tool_call(tool: str, args: dict):
    """Validate arguments against the tool's schema. Returns the parsed model."""
    model = TOOL_ARG_MODELS.get(tool)
    if model is None:
        raise ToolError(f"unknown tool: {tool}")
    try:
        return model(**args)
    except ValidationError as exc:
        raise ToolError(f"invalid arguments for {tool}: {exc.errors()[0]['msg']}") from exc


class ToolRunner:
    def __init__(self, store: DataStore):
        self.store = store
        self.outbox: list[dict] = []

    def execute(self, tool: str, args: dict) -> dict:
        parsed = validate_tool_call(tool, args)
        if tool == "email.read":
            return self._email_read(parsed.email_id)
        if tool == "hr.file.read":
            return self._hr_file_read(parsed.file_id)
        if tool == "file.share":
            return self._file_share(parsed)
        return self._email_send(parsed)

    def _email_read(self, email_id: str) -> dict:
        email = self.store.emails.get(email_id)
        if email is None:
            raise ToolError(f"email not found: {email_id}")
        return {
            "email_id": email["email_id"],
            "from": email["from"],
            "subject": email["subject"],
            "body": email["body"],
        }

    def _hr_file_read(self, file_id: str) -> dict:
        f = self.store.hr_files.get(file_id)
        if f is None:
            raise ToolError(f"hr file not found: {file_id}")
        return {
            "file_id": f["file_id"],
            "title": f["title"],
            "content": f["content"],
            "data_tags": list(f["data_tags"]),
        }

    def _file_share(self, args) -> dict:
        if args.file_id not in self.store.hr_files:
            raise ToolError(f"hr file not found: {args.file_id}")
        # Recorded in the same outbox as emails, so the attack check treats both exits alike.
        message = {
            "message_id": "shr-" + hashlib.sha1(json.dumps(
                [args.recipient, args.file_id, args.permission]).encode()).hexdigest()[:8],
            "to": args.recipient, "subject": f"shared:{args.file_id}", "body": "",
            "attachment_id": args.file_id, "via": "file.share", "permission": args.permission,
        }
        self.outbox.append(message)
        return {"status": "shared", **message}

    def _email_send(self, args) -> dict:
        if args.attachment_id and args.attachment_id not in self.store.hr_files:
            raise ToolError(f"attachment not found: {args.attachment_id}")
        message = {
            # deterministic (hash of content) so identical conversations stay identical for model-call caching
            "message_id": "msg-" + hashlib.sha1(json.dumps(
                [args.to, args.subject, args.body, args.attachment_id]).encode()).hexdigest()[:8],
            "to": args.to,
            "subject": args.subject,
            "body": args.body,
            "attachment_id": args.attachment_id,
        }
        self.outbox.append(message)  # recorded in memory only: nothing is really sent
        return {"status": "sent", **message}
