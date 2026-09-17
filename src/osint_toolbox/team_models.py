"""Validated application inputs; shared by HTTP and direct service callers."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CaseInput(Input):
    title: str = Field(min_length=3, max_length=200)
    purpose: str = Field(min_length=3, max_length=2000)
    authority: str = Field(min_length=3, max_length=2000)
    target_type: Literal["person", "organization", "domain", "username", "email", "media", "location", "social", "event"]
    target: str = Field(min_length=2, max_length=500)
    sensitivity: Literal["internal", "confidential", "restricted"] = "confidential"
    retention_until: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")


class MemberInput(Input):
    subject: str = Field(min_length=1, max_length=200)
    role: Literal["viewer", "analyst", "reviewer", "owner"]


class NoteInput(Input):
    body: str = Field(min_length=1, max_length=4000)


class WorkInput(Input):
    title: str = Field(min_length=1, max_length=300)


class AssignmentInput(Input):
    assignee: str = Field(min_length=1, max_length=200)
    status: Literal["open", "in-review", "resolved"]


class JobInput(Input):
    kind: Literal["provider", "media"]
    provider: str = Field(min_length=1, max_length=40)
    target: str | None = Field(default=None, max_length=500)
    source_object_id: str | None = Field(default=None, max_length=40)
    options: dict[str, str] = Field(default_factory=dict, max_length=20)
    disclosure_confirmed: bool = False


class DecisionInput(Input):
    approve: bool
    reason: str = Field(min_length=3, max_length=1000)


class ReasonInput(Input):
    reason: str = Field(min_length=3, max_length=1000)


class ReportInput(Input):
    markdown: str = Field(min_length=1, max_length=200000)


class HoldInput(Input):
    active: bool
    reason: str = Field(min_length=3, max_length=1000)
    authority: str = Field(min_length=3, max_length=1000)


class RetentionInput(Input):
    retention_until: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    reason: str = Field(min_length=3, max_length=1000)
