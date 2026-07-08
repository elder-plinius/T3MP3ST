from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Never

from django.conf import settings
from django.db import models
from slack_sdk.errors import SlackApiError

from firefighter.incidents.forms.select_impact import SelectImpactForm
from firefighter.incidents.models.priority import Priority
from firefighter.jira_app.client import (
    JiraAPIError,
    JiraUserNotFoundError,
)
from firefighter.jira_app.models import JiraUser
from firefighter.raid.client import client as jira_client
from firefighter.raid.messages import (
    SlackMessageRaidComment,
    SlackMessageRaidCreatedIssue,
    SlackMessageRaidModifiedIssue,
)
from firefighter.raid.models import JiraTicket
from firefighter.raid.utils import get_domain_from_email
from firefighter.slack.models.conversation import Conversation

if TYPE_CHECKING:
    from django.db.models import QuerySet

    from firefighter.incidents.models.impact import ImpactLevel
    from firefighter.incidents.models.user import User
    from firefighter.raid.types import JiraObject
    from firefighter.slack.messages.base import SlackMessageSurface

logger = logging.getLogger(__name__)
RAID_DEFAULT_JIRA_QRAFT_USER_ID: str = settings.RAID_DEFAULT_JIRA_QRAFT_USER_ID


class PlatformChoices(models.TextChoices):
    FR = "platform-FR", ":fr: FR"
    DE = "platform-DE", ":de: DE"
    IT = "platform-IT", ":it: IT"
    ES = "platform-ES", ":es: ES"
    UK = "platform-UK", ":uk: UK"
    ALL = "platform-All", ":earth_africa: ALL"
    INTERNAL = "platform-Internal", ":logo-manomano: Internal"


def initial_priority() -> Priority:
    return Priority.objects.get(default=True)


# NOTE: Incident creation forms have been unified and moved to:
# firefighter.incidents.forms.unified_incident.UnifiedIncidentForm
# This handles all incident types (P1-P5) with dynamic field visibility.
# The following utility functions remain here as they are used by the unified form
# and by JIRA webhook handlers.


def process_jira_issue(
    issue_data: JiraObject,
    user: User,
    jira_user: JiraUser,
    impacts_data: dict[str, ImpactLevel],
    *args: Never,
    **kwargs: Never,
) -> None:
    # XXX Deduplicate from these forms and from incident_created signal
    jira_ticket = JiraTicket.objects.create(**issue_data)
    impacts_form = SelectImpactForm(impacts_data)

    impacts_form.save(incident=jira_ticket)

    set_jira_ticket_watchers_raid(jira_ticket)
    alert_slack_new_jira_ticket(jira_ticket)


def set_jira_ticket_watchers_raid(jira_ticket: JiraTicket) -> None:
    issue_id = jira_ticket.id
    reporter = jira_ticket.reporter.id

    try:
        default_jira_user = jira_client.get_jira_user_from_jira_id(
            RAID_DEFAULT_JIRA_QRAFT_USER_ID
        )
    except JiraUserNotFoundError:
        logger.exception(
            f"Could not find Jira user with account id {RAID_DEFAULT_JIRA_QRAFT_USER_ID}"
        )
    try:
        jira_client.jira.add_watcher(issue=issue_id, watcher=reporter)
    except JiraAPIError:
        logger.exception(
            f"Could not add the watcher {jira_ticket.reporter.id} to the ticket {issue_id}"
        )
        try:
            jira_client.jira.remove_watcher(issue=issue_id, watcher=default_jira_user)

        except JiraAPIError:
            logger.exception(
                f"Could not add the watcher {jira_ticket.reporter.id} to the ticket {issue_id}"
            )


def alert_slack_new_jira_ticket(
    jira_ticket: JiraTicket,
    reporter_user: User | None = None,
    reporter_email: str | None = None,
) -> None:
    # These alerts are for P4-P5 incidents only, not P1-P3 critical incidents
    if (
        hasattr(jira_ticket, "incident")
        and jira_ticket.incident
        and jira_ticket.incident.priority.value <= 3
    ):
        raise ValueError("This is a critical incident, not a raid incident.")

    # Get the reporter's email and user from ticket if not provided
    reporter_user = reporter_user or jira_ticket.reporter.user
    reporter_email = reporter_email or reporter_user.email
    # Get the user's email domain (without @, without subdomain(s), with tld)
    user_domain: str = get_domain_from_email(reporter_email)

    if not reporter_user:
        logger.warning(f"Reporter user not found for Jira ticket {jira_ticket.id}.")
        return
    message = SlackMessageRaidCreatedIssue(jira_ticket, reporter_user=reporter_user)
    if (
        hasattr(reporter_user, "slack_user")
        and reporter_user.slack_user
        and reporter_user.slack_user.slack_id
    ):
        try:
            # XXX: Slack ID is posted in the message instead of Name
            reporter_user.slack_user.send_private_message(
                message,
                unfurl_links=False,
            )
        except SlackApiError as e:
            if e.response.get("error") == "messages_tab_disabled":
                logger.warning(
                    f"User {reporter_user.slack_user} has disabled private messages from bots"
                )
            else:
                logger.exception(
                    f"Couldn't send private message to reporter {reporter_user.slack_user}"
                )

    # Get the right channels from tags
    channels = get_internal_alert_conversations(jira_ticket)
    if user_domain:
        channels.union(get_partner_alert_conversations(user_domain))
    channels_list = list(channels)
    if len(channels_list) == 0:
        logger.warning(
            f"No channel to send notification for Jira ticket {jira_ticket.id}."
        )

    for channel in channels_list:
        try:
            channel.send_message_and_save(message)
        except SlackApiError:
            logger.exception(
                f"Couldn't send message to channel {channel} for ticket {jira_ticket.id}"
            )


def alert_slack_update_ticket(
    jira_ticket_id: int,
    jira_ticket_key: str,
    jira_author_name: str,
    jira_field_modified: str,
    jira_field_from: str,
    jira_field_to: str,
) -> bool:
    message = SlackMessageRaidModifiedIssue(
        jira_ticket_key=jira_ticket_key,
        jira_author_name=jira_author_name,
        jira_field_modified=jira_field_modified,
        jira_field_from=jira_field_from,
        jira_field_to=jira_field_to,
    )
    return send_message_to_watchers(jira_issue_id=jira_ticket_id, message=message)


def alert_slack_comment_ticket(
    webhook_event: str,
    jira_ticket_id: int,
    jira_ticket_key: str,
    author_jira_name: str,
    comment: str,
) -> bool:
    message: SlackMessageSurface = SlackMessageRaidComment(
        jira_ticket_key=jira_ticket_key,
        author_jira_name=author_jira_name,
        comment=comment,
        webhook_event=webhook_event,
    )
    return send_message_to_watchers(jira_issue_id=jira_ticket_id, message=message)


def send_message_to_watchers(
    jira_issue_id: int,
    message: SlackMessageSurface,
) -> bool:
    watchers = jira_client.get_watchers_from_jira_ticket(jira_issue_id)
    if not watchers:
        return True

    for watcher in watchers:
        try:
            watcher_account_id = watcher.get("accountId")
            if watcher_account_id is None:
                logger.warning(f"Couldn't find Jira account ID for watcher {watcher}")
                continue

            if watcher.get("accountType") == "app":
                logger.info(
                    f"Skipping sending message to jira_user_id={watcher_account_id}: is an app"
                )
                continue
            if not JiraUser.objects.filter(id=watcher_account_id).exists():
                logger.debug(
                    "Skipping watcher %s: no JiraUser mapping in database",
                    watcher_account_id,
                )
                continue
            watcher_jira_user = jira_client.get_jira_user_from_jira_id(
                watcher_account_id
            )
            watcher_slack_user = (
                watcher_jira_user.user.slack_user
                if hasattr(watcher_jira_user.user, "slack_user")
                else None
            )
            if watcher_slack_user is None:
                logger.debug(
                    "Watcher %s has a JiraUser but no linked Slack user",
                    watcher_account_id,
                )
                continue
            watcher_slack_user.send_private_message(
                message,
                unfurl_links=False,
            )
        except SlackApiError:
            logger.warning(
                f"Couldn't send private message to reporter with jira_id={watcher.get('accountId', watcher)}"
            )
    return True


def get_business_impact(impacts_data: dict[str, ImpactLevel]) -> str | None:
    impact_form = SelectImpactForm(impacts_data)
    return impact_form.business_impact_new


def prepare_jira_fields(
    *,
    title: str,
    description: str,
    priority: int,
    reporter: str,
    incident_category: str,
    environments: list[str],
    platforms: list[str],
    impacts_data: dict[str, ImpactLevel],
    optional_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Prepare all fields for jira_client.create_issue().

    This function centralizes Jira field preparation for both P1-P3 and P4-P5 incidents,
    ensuring all custom fields are properly passed.

    Args:
        title: Incident title
        description: Incident description
        priority: Priority value (1-5)
        reporter: Jira user account ID
        incident_category: Category name
        environments: List of environment values (e.g. ["PRD", "STG"])
        platforms: List of platform values (e.g. ["platform-FR", "platform-DE"])
        impacts_data: Dictionary of impact data for business_impact computation
        optional_fields: Optional dictionary containing:
            - zendesk_ticket_id: Zendesk ticket ID (customer-specific)
            - seller_contract_id: Seller contract ID (seller-specific)
            - zoho_desk_ticket_id: Zoho Desk ticket ID (seller-specific)
            - is_key_account: Key account flag (seller-specific)
            - is_seller_in_golden_list: Golden list flag (seller-specific)
            - suggested_team_routing: Suggested team routing (P4-P5 only)

    Returns:
        Dictionary of kwargs ready for jira_client.create_issue()
    """
    business_impact = get_business_impact(impacts_data)
    platform = platforms[0] if platforms else PlatformChoices.ALL.value

    # Extract optional fields with defaults
    opt = optional_fields or {}
    zendesk_ticket_id = opt.get("zendesk_ticket_id", "")
    seller_contract_id = opt.get("seller_contract_id", "")
    zoho_desk_ticket_id = opt.get("zoho_desk_ticket_id", "")
    is_key_account = opt.get("is_key_account")
    is_seller_in_golden_list = opt.get("is_seller_in_golden_list")
    suggested_team_routing = opt.get("suggested_team_routing")

    return {
        "issuetype": "Incident",
        "summary": title,
        "description": description,
        "priority": priority,
        "reporter": reporter,
        "assignee": None,
        "incident_category": incident_category,
        "environments": environments,  # ✅ Always pass environments list
        "platform": platform,
        "business_impact": business_impact,
        "zendesk_ticket_id": zendesk_ticket_id,
        "seller_contract_id": seller_contract_id,
        "zoho_desk_ticket_id": zoho_desk_ticket_id,
        "is_key_account": is_key_account if is_key_account is not None else False,
        "is_seller_in_golden_list": is_seller_in_golden_list if is_seller_in_golden_list is not None else False,
        "suggested_team_routing": suggested_team_routing,
    }


def get_partner_alert_conversations(user_domain: str) -> QuerySet[Conversation]:
    # Get the right channel from tags
    return Conversation.objects.filter(tag__contains=f"raid_alert__{user_domain}")


def get_internal_alert_conversations(jira_ticket: JiraTicket) -> QuerySet[Conversation]:
    impact_tag = "high" if jira_ticket.business_impact == "High" else "normal"
    project = "sbi" if jira_ticket.project_key == "SBI" else "incidents"
    return Conversation.objects.filter(
        tag__contains=f"raid_alert__{project}_{impact_tag}"
    )
