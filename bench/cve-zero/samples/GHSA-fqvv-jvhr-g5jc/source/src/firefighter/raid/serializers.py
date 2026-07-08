from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core.cache import cache
from rest_framework import serializers

from firefighter.incidents.enums import IncidentStatus
from firefighter.incidents.models.priority import Priority
from firefighter.incidents.models.user import User
from firefighter.jira_app.client import (
    JiraAPIError,
    JiraUserNotFoundError,
    SlackNotificationError,
)
from firefighter.raid.client import client as jira_client
from firefighter.raid.forms import (
    alert_slack_comment_ticket,
    alert_slack_new_jira_ticket,
    alert_slack_update_ticket,
)
from firefighter.raid.messages import SlackMessageJiraClosedBlockedByCanBeClosed
from firefighter.raid.models import JiraTicket
from firefighter.raid.utils import get_domain_from_email, normalize_cache_value
from firefighter.slack.models.user import SlackUser

if TYPE_CHECKING:
    from firefighter.incidents.models.incident import Incident
    from firefighter.jira_app.models import JiraUser


JIRA_USER_IDS: dict[str, str] = settings.RAID_JIRA_USER_IDS
JIRA_TO_IMPACT_STATUS_MAP: dict[str, IncidentStatus] = {
    "Incoming": IncidentStatus.OPEN,
    "Pending resolution": IncidentStatus.OPEN,
    "in progress": IncidentStatus.MITIGATING,
    "Reporter validation": IncidentStatus.MITIGATED,
    "Closed": IncidentStatus.CLOSED,
}
JIRA_TO_IMPACT_PRIORITY_MAP: dict[str, int] = {
    "1": 1,
    "2": 2,
    "3": 3,
    "4": 4,
    "5": 5,
    # Legacy Jira names still supported
    "Highest": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4,
    "Lowest": 5,
}

logger = logging.getLogger(__name__)


class IgnoreEmptyStringListField(serializers.ListField):
    def to_internal_value(self, data: list[Any] | Any) -> list[str]:
        # Check if data is a list
        if not isinstance(data, list):
            msg = f'Expected a list but got type "{type(data).__name__}".'
            raise serializers.ValidationError(msg)

        # Filter out any empty string values
        data = [item for item in data if item != ""]

        return super().to_internal_value(data)


def validate_no_spaces(value: str) -> None:
    """Ensure the string does not contain spaces."""
    if " " in value:
        raise serializers.ValidationError("The string cannot contain spaces.")


def get_reporter_user_from_email(reporter_email: str) -> tuple[User, JiraUser, str]:
    user_domain: str = get_domain_from_email(reporter_email)
    try:
        reporter_user: User = User.objects.get(email=reporter_email)
        reporter = jira_client.get_jira_user_from_user(reporter_user)
    except (User.DoesNotExist, JiraUserNotFoundError):
        reporter_user_tmp = SlackUser.objects.upsert_by_email(email=reporter_email)
        if reporter_user_tmp is not None:
            reporter_user = reporter_user_tmp

        logger.warning(
            f"Reporter email {reporter_email} not found in Jira. Using default user."
        )

        # Get default Jira user, depending on the domain
        # We might have accounts with Slack users, but not Jira users
        # In that case, we use the default Jira user for that domain
        match JIRA_USER_IDS.get(user_domain):
            case jira_user_id if jira_user_id is not None:
                reporter = jira_client.get_jira_user_from_jira_id(jira_user_id)
                reporter_user = (
                    reporter.user if reporter_user_tmp is None else reporter_user_tmp
                )
            case _:
                reporter = jira_client.get_jira_user_from_jira_id(
                    settings.RAID_DEFAULT_JIRA_QRAFT_USER_ID
                )
                reporter_user = (
                    reporter.user if reporter_user_tmp is None else reporter_user_tmp
                )
    return reporter_user, reporter, user_domain


class LandbotIssueRequestSerializer(serializers.ModelSerializer[JiraTicket]):
    id = serializers.IntegerField(read_only=True)
    key = serializers.CharField(read_only=True)
    seller_contract_id = serializers.CharField(
        max_length=128,
        write_only=True,
        allow_null=True,
        allow_blank=True,
    )
    zoho = serializers.CharField(
        max_length=256,
        write_only=True,
        allow_null=True,
        allow_blank=True,
    )
    zendesk = serializers.CharField(
        max_length=256,
        write_only=True,
        allow_null=True,
        allow_blank=True,
        required=False,
    )
    platform = serializers.ChoiceField(
        write_only=True, choices=["ES", "IT", "FR", "UK", "DE", "All", "Internal"]
    )
    reporter_email = serializers.EmailField(write_only=True)

    labels = serializers.ListField(
        required=False,
        write_only=True,
        allow_null=True,
        default=list,
        child=serializers.CharField(
            max_length=128,
            allow_blank=False,
            allow_null=False,
            validators=[validate_no_spaces],
        ),
        help_text="List of labels to be added to the ticket. Labels cannot contain spaces and must not exceed 255 characters.",
    )
    incident_category = serializers.CharField(
        max_length=128,
        write_only=True,
        allow_null=True,
        allow_blank=True,
    )
    suggested_team_routing = serializers.CharField(max_length=10, write_only=True)
    project = serializers.CharField(
        max_length=128,
        required=False,
        allow_blank=True,
        allow_null=True,
        default="SBI",
    )
    priority = serializers.IntegerField(
        min_value=1,
        max_value=5,
        write_only=True,
        allow_null=True,
        help_text="Priority level 1-5 (1=Critical, 2=High, 3=Medium, 4=Low, 5=Lowest)",
    )
    business_impact = serializers.ChoiceField(
        write_only=True, choices=["High", "Medium", "Low"], allow_null=True
    )
    environments = serializers.ListField(
        write_only=True,
        allow_null=True,
        default=["-"],
        child=serializers.ChoiceField(
            allow_null=True,
            allow_blank=True,
            choices=["INT", "STG", "PRD", "SUPPORT", "-"],
        ),
    )
    attachments = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
    )
    issue_type = serializers.ChoiceField(
        required=False,
        allow_blank=True,
        allow_null=True,
        default="Incident",
        choices=[
            "Incident",
            "Service Request",
            "Documentation/Process Request",
            "Feature Request",
        ],
    )

    def validate_labels(self, value: list[str] | None) -> list[str]:
        """Transform null labels to empty list."""
        if value is None:
            return []
        return value

    def validate_environments(self, value: list[str] | None) -> list[str] | Any:
        if not value:
            return self.fields["environments"].default
        return value

    def create(self, validated_data: dict[str, Any]) -> JiraTicket:
        reporter_email: str = validated_data["reporter_email"]

        reporter_user, reporter, user_domain = get_reporter_user_from_email(
            reporter_email
        )
        user_in_description: str = (
            f"\nReporter email {reporter_email}\n"
            if "manomano" not in user_domain
            else ""
        )

        issue = jira_client.create_issue(
            issuetype=validated_data["issue_type"],
            summary=validated_data["summary"],
            description=f"""{validated_data.get("description")}\n
\n
🤖 This ticket was created through the Incident Verification Bot https://landbot.pro/v3/H-1332620-8BF395J9STSHL7IN/index.html.\n
\n
{user_in_description}
\n
""",
            assignee=None,
            reporter=reporter.id,
            labels=validated_data["labels"],
            priority=validated_data["priority"],
            seller_contract_id=validated_data["seller_contract_id"],
            zoho_desk_ticket_id=validated_data["zoho"],
            zendesk_ticket_id=validated_data.get("zendesk"),
            platform=validated_data["platform"],
            incident_category=validated_data["incident_category"],
            business_impact=validated_data["business_impact"],
            environments=validated_data["environments"],
            suggested_team_routing=validated_data["suggested_team_routing"],
            project=validated_data["project"],
        )
        issue_id = issue.get("id")
        if issue_id is None:
            logger.error("Could not create Jira ticket")
            raise JiraAPIError("Could not create Jira ticket")
        if validated_data["attachments"] is not None:
            #  Prepare attachments and double check we don't have any empty strings
            attachments: list[str] = [
                a
                for a in validated_data["attachments"]
                .replace("[", "")
                .replace("]", "")
                .replace("'", "")
                .split(", ")
                if a
            ]
            jira_client.add_attachments_to_issue(issue_id, attachments)

        jira_ticket = JiraTicket.objects.create(**issue)

        # Send messages in the relevant Slack channels if needed and alert the reporter in DMs
        alert_slack_new_jira_ticket(
            jira_ticket, reporter_user=reporter_user, reporter_email=reporter_email
        )

        return jira_ticket

    class Meta:
        model = JiraTicket
        fields = [
            "summary",
            "description",
            "seller_contract_id",
            "zoho",
            "zendesk",
            "platform",
            "reporter_email",
            "incident_category",
            "labels",
            "environments",
            "issue_type",
            "business_impact",
            "priority",
            "id",
            "key",
            "attachments",
            "suggested_team_routing",
            "project",
        ]


class JiraWebhookUpdateSerializer(serializers.Serializer[Any]):
    issue = serializers.DictField()
    changelog = serializers.DictField()
    user = serializers.DictField()
    webhookEvent = serializers.ChoiceField(  # noqa: N815
        write_only=True,
        choices=["jira:issue_updated"],
    )

    def create(self, validated_data: dict[str, Any]) -> bool:
        changes = validated_data.get("changelog", {}).get("items") or []
        if not changes:
            logger.debug("Jira webhook had no changelog items; skipping.")
            return True

        jira_ticket_key = validated_data["issue"].get("key")
        incident = (
            self._get_incident_from_jira_ticket(jira_ticket_key)
            if jira_ticket_key
            else None
        )
        if incident is None:
            # No linked incident: still emit Slack alerts for tracked fields (status/priority).
            for change_item in changes:
                field = (change_item.get("field") or "").lower()
                to_val = change_item.get("toString")
                from_val = change_item.get("fromString")
                is_status = field == "status"
                is_priority = (
                    self._parse_priority_value(to_val) is not None
                    or self._parse_priority_value(from_val) is not None
                )
                if not (is_status or is_priority):
                    continue
                if not self._alert_slack_update(
                    validated_data, jira_ticket_key, change_item
                ):
                    raise SlackNotificationError("Could not alert in Slack")
            return True

        for change_item in changes:
            if not self._sync_jira_fields_to_incident(
                validated_data, jira_ticket_key, incident, change_item
            ):
                continue

        return True

    @staticmethod
    def _alert_slack_update(
        validated_data: dict[str, Any],
        jira_ticket_key: str | None,
        change_item: dict[str, Any],
    ) -> bool:
        ticket_id = validated_data["issue"].get("id")
        ticket_key = jira_ticket_key or ""
        jira_author_name = str(validated_data["user"].get("displayName") or "")
        jira_field_modified = str(change_item.get("field") or "")
        jira_field_from = str(change_item.get("fromString") or "")
        jira_field_to = str(change_item.get("toString") or "")

        if ticket_id is None or ticket_key == "" or jira_field_modified == "":
            logger.error(
                "Missing required Jira changelog data: id=%s key=%s field=%s",
                ticket_id,
                jira_ticket_key,
                change_item.get("field"),
            )
            return False

        status = alert_slack_update_ticket(
            jira_ticket_id=int(ticket_id),
            jira_ticket_key=ticket_key,
            jira_author_name=jira_author_name,
            jira_field_modified=jira_field_modified,
            jira_field_from=jira_field_from,
            jira_field_to=jira_field_to,
        )
        if status is not True:
            logger.error(
                "Could not alert in Slack for the update/s in the Jira ticket %s",
                jira_ticket_key or "unknown",
            )
            return False
        return True

    def _sync_jira_fields_to_incident(
        self,
        validated_data: dict[str, Any],
        jira_ticket_key: str | None,
        incident: Incident,
        change_item: dict[str, Any],
    ) -> bool:
        field = (change_item.get("field") or "").lower()

        # Loop prevention: skip if this exact change was just sent Impact -> Jira
        if self._skip_due_to_recent_impact_change(jira_ticket_key, field, change_item):
            logger.debug(
                "Skipping Jira→Impact sync for %s on %s due to recent Impact change",
                field,
                jira_ticket_key,
            )
            return False

        # Detect and apply status/priority updates only
        if field == "status":
            if not self._alert_slack_update(
                validated_data, jira_ticket_key, change_item
            ):
                raise SlackNotificationError("Could not alert in Slack")
            return self._handle_status_update(validated_data, incident, change_item)

        to_val = change_item.get("toString")
        from_val = change_item.get("fromString")
        if (
            self._parse_priority_value(to_val) is not None
            or self._parse_priority_value(from_val) is not None
        ):
            if not self._alert_slack_update(
                validated_data, jira_ticket_key, change_item
            ):
                raise SlackNotificationError("Could not alert in Slack")
            return self._handle_priority_update(validated_data, incident, change_item)

        return False

    @staticmethod
    def _get_incident_from_jira_ticket(jira_ticket_key: str) -> Incident | None:
        try:
            jira_ticket = JiraTicket.objects.select_related("incident").get(
                key=jira_ticket_key
            )
        except JiraTicket.DoesNotExist:
            logger.warning(
                "Received Jira webhook for %s but no JiraTicket found; skipping",
                jira_ticket_key,
            )
            return None

        incident = getattr(jira_ticket, "incident", None)
        if incident is None:
            logger.warning(
                "Jira ticket %s not linked to an incident; skipping sync",
                jira_ticket_key,
            )
            return None

        return incident

    def _handle_status_update(
        self,
        validated_data: dict[str, Any],
        incident: Incident,
        change_item: dict[str, Any],
    ) -> bool:
        jira_status_to = change_item.get("toString") or ""
        jira_status_from = change_item.get("fromString") or ""
        impact_status = JIRA_TO_IMPACT_STATUS_MAP.get(jira_status_to)
        if impact_status is None:
            logger.debug(
                "Jira status '%s' has no Impact mapping; skipping incident sync",
                jira_status_to,
            )
            return True

        # Guard against unintentional closures triggered by non-standard Jira workflows.
        # If the target maps to CLOSED but the previous Jira status is not a known Impact
        # status (e.g. "Code Review" from a CI/CD automation), this is likely an intermediate
        # step and not a deliberate incident closure. Only allow close when the transition
        # comes from a recognised Impact status (e.g. "Reporter validation").
        if impact_status == IncidentStatus.CLOSED and jira_status_from not in JIRA_TO_IMPACT_STATUS_MAP:
            logger.warning(
                "Skipping Jira→Impact close for incident %s: transition from unknown Jira status '%s' to 'Closed'. "
                "This looks like an intermediate step in a non-standard Jira workflow (e.g. CI/CD automation). "
                "Close the ticket from a recognised status (e.g. 'Reporter validation') to trigger Impact closure.",
                incident.id,
                jira_status_from,
            )
            return True

        if incident.status == impact_status:
            logger.debug(
                "Incident %s already at status %s from Jira webhook; no-op",
                incident.id,
                incident.status.label,
            )
            return True

        # Before closing, verify all business rules are satisfied (key events, status, etc.).
        # If not, notify the incident channel and leave the incident open.
        if impact_status == IncidentStatus.CLOSED:
            can_close, reasons = incident.can_be_closed
            if not can_close:
                logger.warning(
                    "Jira ticket closed but Impact incident %s cannot be closed yet: %s",
                    incident.id,
                    reasons,
                )
                jira_ticket_key = validated_data.get("issue", {}).get("key", "")
                if hasattr(incident, "conversation") and jira_ticket_key:
                    try:
                        incident.conversation.send_message_and_save(
                            SlackMessageJiraClosedBlockedByCanBeClosed(
                                jira_ticket_key=jira_ticket_key,
                                reasons=reasons,
                            )
                        )
                    except Exception:
                        logger.exception(
                            "Failed to notify incident channel for blocked close of incident %s",
                            incident.id,
                        )
                return True

        incident.create_incident_update(
            created_by=None,
            status=impact_status,
            message=f"Status synced from Jira ({jira_status_to})",
            event_type="jira_status_sync",
        )
        return True

    def _handle_priority_update(
        self,
        _validated_data: dict[str, Any],
        incident: Incident,
        change_item: dict[str, Any],
    ) -> bool:
        jira_priority_to = change_item.get("toString") or ""

        impact_priority_value = self._parse_priority_value(jira_priority_to)

        if impact_priority_value is None:
            logger.debug(
                "Jira priority '%s' has no Impact mapping; skipping incident sync",
                jira_priority_to,
            )
            return True
        if incident.priority and incident.priority.value == impact_priority_value:
            logger.debug(
                "Incident %s already at priority %s from Jira webhook; no-op",
                incident.id,
                incident.priority.value,
            )
            return True

        try:
            impact_priority = Priority.objects.get(value=impact_priority_value)
        except Priority.DoesNotExist:
            logger.warning(
                "No Impact priority with value %s; skipping Jira→Impact priority sync",
                impact_priority_value,
            )
            return True

        incident.create_incident_update(
            created_by=None,
            priority_id=impact_priority.id,
            message=f"Priority synced from Jira ({jira_priority_to})",
            event_type="jira_priority_sync",
        )
        return True

    @staticmethod
    def _skip_due_to_recent_impact_change(
        jira_ticket_key: str | None, field: str, change_item: dict[str, Any]
    ) -> bool:
        if not jira_ticket_key:
            return False
        try:
            jira_ticket = JiraTicket.objects.select_related("incident").get(
                key=jira_ticket_key
            )
        except JiraTicket.DoesNotExist:
            return False

        incident = getattr(jira_ticket, "incident", None)
        if not incident:
            return False

        raw_value = change_item.get("toString")
        # Normalize value consistently with Impact→Jira writes
        if field == "status":
            value_for_cache = raw_value
        else:
            parsed = JiraWebhookUpdateSerializer._parse_priority_value(raw_value)
            value_for_cache = parsed if parsed is not None else raw_value

        cache_key = f"sync:impact_to_jira:{incident.id}:{field}:{normalize_cache_value(value_for_cache)}"
        if cache.get(cache_key):
            cache.delete(cache_key)
            return True
        return False

    @staticmethod
    def _parse_priority_value(raw: Any) -> int | None:
        """Try to extract a priority value (1-5) from Jira changelog strings."""
        if raw is None:
            return None
        try:
            parsed = int(raw)
            if 1 <= parsed <= 5:
                return parsed
        except (TypeError, ValueError):
            pass

        return JIRA_TO_IMPACT_PRIORITY_MAP.get(str(raw))

    def update(self, instance: Any, validated_data: Any) -> Any:
        raise NotImplementedError


class JiraWebhookCommentSerializer(serializers.Serializer[Any]):
    issue = serializers.DictField()
    comment = serializers.DictField()
    webhookEvent = serializers.ChoiceField(  # noqa: N815
        write_only=True,
        choices=["comment_created", "comment_updated", "comment_deleted"],
    )

    def create(self, validated_data: dict[str, Any]) -> bool:
        jira_ticket_key = validated_data["issue"].get("key")
        status = alert_slack_comment_ticket(
            webhook_event=validated_data["webhookEvent"],
            jira_ticket_id=validated_data["issue"].get("id"),
            jira_ticket_key=jira_ticket_key,
            author_jira_name=validated_data["comment"].get("author").get("displayName"),
            comment=validated_data["comment"].get("body"),
        )
        if status is not True:
            logger.error(
                f"Could not alert in Slack for created/modified comment in the Jira ticket {jira_ticket_key}"
            )
            raise SlackNotificationError("Could not alert in Slack")
        return True

    def update(self, instance: Any, validated_data: Any) -> Any:
        raise NotImplementedError
