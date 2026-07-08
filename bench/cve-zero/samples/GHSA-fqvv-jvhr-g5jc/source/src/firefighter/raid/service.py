from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.conf import settings

from firefighter.jira_app.client import (
    JiraAPIError,
    JiraUserNotFoundError,
)
from firefighter.jira_app.models import JiraUser
from firefighter.raid.client import client as jira_client

if TYPE_CHECKING:
    from firefighter.incidents.models.user import User
    from firefighter.raid.types import JiraObject


logger = logging.getLogger(__name__)
RAID_DEFAULT_JIRA_QRAFT_USER_ID: str = settings.RAID_DEFAULT_JIRA_QRAFT_USER_ID
error_jira_ticket_creation = "Could not create Jira ticket"


def check_issue_id(issue: JiraObject, title: str, reporter: str) -> int | str:
    """Check and return the issue ID from a JiraObject.

    Raises JiraAPIError if the issue ID is missing or invalid.
    """
    issue_id = issue.get("id")
    if issue_id is None:
        logger.error(
            f"Could not create Jira ticket for the incident {title} and the reporter {reporter}"
        )
        raise JiraAPIError(error_jira_ticket_creation)
    return issue_id


def get_jira_user_from_user(user: User) -> JiraUser:
    """Returns the JiraUser object for a given user, if it exists in DB or can be fetched on Jira API. Returns the default JiraUser if not found."""
    try:
        jira_user = jira_client.get_jira_user_from_user(user)
    except JiraAPIError:
        logger.exception(f"Could not find Jira user for {user.id}")

        logger.warning(f"User {user.id} has no Jira user")
        try:
            jira_user = jira_client.get_jira_user_from_jira_id(
                RAID_DEFAULT_JIRA_QRAFT_USER_ID
            )
        except JiraUserNotFoundError:
            logger.exception(
                f"Could not find Jira user with account id {RAID_DEFAULT_JIRA_QRAFT_USER_ID}"
            )
            jira_user = JiraUser.objects.get(id=RAID_DEFAULT_JIRA_QRAFT_USER_ID)
    return jira_user


def create_issue_feature_request(
    title: str,
    description: str,
    reporter: str,
    priority: int | None,
    labels: list[str] | None,
    platform: str,
) -> JiraObject:
    """Creates a Jira issue of type Feature Request.

    Args:
        title (str): Summary of the issue
        description (str): Description of the issue
        reporter (str): Jira account id of the reporter
        priority (int): Priority of the issue
        labels (list[str]): Labels to add to the issue
        platform (str): Platform of the issue
    """
    if labels is None:
        labels = [""]
    if "feature-request" not in labels:
        labels.append("feature-request")
    issue = jira_client.create_issue(
        issuetype="Feature Request",
        summary=title,
        description=description,
        assignee=None,
        reporter=reporter,
        priority=priority,
        labels=labels,
        platform=platform,
    )
    check_issue_id(issue, title=title, reporter=reporter)
    return issue


def create_issue_documentation_request(
    title: str,
    description: str,
    reporter: str,
    priority: int | None,
    labels: list[str] | None,
    platform: str,
) -> JiraObject:
    """Creates a Jira issue of type Documentation/Process Request.

    Args:
        title (str): Summary of the issue
        description (str): Description of the issue
        reporter (str): Jira account id of the reporter
        priority (int): Priority of the issue
        labels (list[str]): Labels to add to the issue
        platform (str): Platform of the issue
    """
    if labels is None:
        labels = [""]
    if "documentation-request" not in labels:
        labels.append("documentation-request")
    issue = jira_client.create_issue(
        issuetype="Documentation/Process Request",
        summary=title,
        description=description,
        assignee=None,
        reporter=reporter,
        priority=priority,
        labels=labels,
        platform=platform,
    )
    check_issue_id(issue, title=title, reporter=reporter)
    return issue


def create_issue_internal(
    title: str,
    description: str,
    reporter: str,
    priority: int | None,
    labels: list[str] | None,
    platform: str,
    business_impact: str | None,
    team_to_be_routed: str | None,
    incident_category: str | None,
) -> JiraObject:
    """Creates a Jira Incident Issue of type Internal.

    Args:
        title (str): Summary of the issue
        description (str): Description of the issue
        reporter (str): Jira account id of the reporter
        priority (int): Priority of the issue
        labels (list[str]): Labels to add to the issue
        platform (str): Platform of the issue
        business_impact (str): Business impact of the issue
        team_to_be_routed (str): Team to be routed
        incident_category (str): Incident category of the issue
    """
    issue = jira_client.create_issue(
        issuetype="Incident",
        summary=title,
        description=description,
        assignee=None,
        reporter=reporter,
        priority=priority,
        labels=labels,
        platform=platform,
        business_impact=business_impact,
        suggested_team_routing=team_to_be_routed,
        incident_category=incident_category,
    )
    check_issue_id(issue, title=title, reporter=reporter)
    return issue


@dataclass
class CustomerIssueData:
    """Data container for customer issue creation parameters."""
    priority: int | None
    labels: list[str] | None
    platform: str
    business_impact: str | None
    team_to_be_routed: str | None
    area: str | None
    zendesk_ticket_id: str | None
    incident_category: str | None = None


def create_issue_customer(
    title: str,
    description: str,
    reporter: str,
    issue_data: CustomerIssueData,
) -> JiraObject:
    """Creates a Jira Incident issue of type Customer.

    Args:
        title (str): Summary of the issue
        description (str): Description of the issue
        reporter (str): Jira account id of the reporter
        issue_data (CustomerIssueData): Container with issue parameters
    """
    issue = jira_client.create_issue(
        issuetype="Incident",
        summary=title,
        description=description,
        assignee=None,
        reporter=reporter,
        priority=issue_data.priority,
        labels=issue_data.labels,
        platform=issue_data.platform,
        business_impact=issue_data.business_impact,
        suggested_team_routing=issue_data.team_to_be_routed,
        zendesk_ticket_id=issue_data.zendesk_ticket_id,
        incident_category=issue_data.incident_category,
    )
    check_issue_id(issue, title=title, reporter=reporter)
    return issue


def create_issue_seller(  # noqa: PLR0913
    title: str,
    description: str,
    reporter: str,
    priority: int | None,
    labels: list[str] | None,
    platform: str,
    business_impact: str | None,
    team_to_be_routed: str | None,
    incident_category: str | None,
    seller_contract_id: str | None,
    is_key_account: bool | None,
    is_seller_in_golden_list: bool | None,
    zoho_desk_ticket_id: str | None,
) -> JiraObject:
    """Creates a Jira Incident issue of type Seller.

    Args:
        title (str): Summary of the issue
        description (str): Description of the issue
        reporter (str): Jira account id of the reporter
        priority (int): Priority of the issue
        labels (list[str]): Labels to add to the issue
        platform (str): Platform of the issue
        business_impact (str): Business impact of the issue
        team_to_be_routed (str): Team to be routed
        incident_category (str): Incident category of the issue
        seller_contract_id (str): Seller contract id
        is_key_account (bool): Is key account
        is_seller_in_golden_list (bool): Is seller in golden list
        zoho_desk_ticket_id (str): Zoho desk ticket id
    """
    issue = jira_client.create_issue(
        issuetype="Incident",
        summary=title,
        description=description,
        assignee=None,
        reporter=reporter,
        priority=priority,
        labels=labels,
        platform=platform,
        business_impact=business_impact,
        suggested_team_routing=team_to_be_routed,
        seller_contract_id=seller_contract_id,
        is_key_account=is_key_account,
        is_seller_in_golden_list=is_seller_in_golden_list,
        zoho_desk_ticket_id=zoho_desk_ticket_id,
        incident_category=incident_category,
    )
    check_issue_id(issue, title=title, reporter=reporter)
    return issue
