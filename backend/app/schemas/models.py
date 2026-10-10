"""Pydantic schemas: tool arguments and provenance labels."""
import re
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class _StrictModel(BaseModel):
    # Unknown fields are rejected: an agent cannot smuggle extra arguments in.
    model_config = ConfigDict(extra="forbid")


class EmailReadArgs(_StrictModel):
    email_id: str = Field(min_length=1)


class HrFileReadArgs(_StrictModel):
    file_id: str = Field(min_length=1)


class EmailSendArgs(_StrictModel):
    to: str
    subject: str = Field(min_length=1)
    body: str
    attachment_id: Optional[str] = None

    @field_validator("to")
    @classmethod
    def _valid_address(cls, v: str) -> str:
        v = v.strip()
        if not _EMAIL_RE.match(v):
            raise ValueError(f"invalid email address: {v!r}")
        return v


TOOL_ARG_MODELS = {
    "email.read": EmailReadArgs,
    "hr.file.read": HrFileReadArgs,
    "email.send": EmailSendArgs,
}


class ContentLabel(BaseModel):
    """Provenance label attached to one piece of content the agent has read."""

    source_type: Literal["email", "hr_file"]
    source_id: str
    trust_level: Literal["trusted", "untrusted", "internal_sensitive"]
    contains_instruction_like_text: bool = False
    data_tags: list[str] = Field(default_factory=list)
    influenced_actions: list[str] = Field(default_factory=list)
