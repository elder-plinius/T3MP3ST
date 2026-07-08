from __future__ import annotations

from typing import NotRequired, TypedDict

_JiraId = int | str
_Key = str
_AssigneeId = str
_ReporterId = str
_Description = str
_Summary = str
_BusinessImpact = str


class JiraObject(TypedDict):
    id: NotRequired[_JiraId]
    key: NotRequired[_Key]
    assignee_id: _AssigneeId
    reporter_id: _ReporterId
    description: _Description
    summary: _Summary
    issue_type: str
    project_key: str
    business_impact: _BusinessImpact
