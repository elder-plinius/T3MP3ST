from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core.cache import cache
from django.db.models.signals import post_save
from django.dispatch.dispatcher import receiver

from firefighter.incidents.enums import IncidentStatus
from firefighter.incidents.models.incident import Incident
from firefighter.incidents.signals import incident_updated
from firefighter.raid.client import RAID_JIRA_WORKFLOW_NAME, client
from firefighter.raid.utils import normalize_cache_value

if TYPE_CHECKING:
    from firefighter.incidents.models.incident_update import IncidentUpdate

logger = logging.getLogger(__name__)
JIRA_SYNC_CACHE_TIMEOUT = getattr(settings, "JIRA_SYNC_CACHE_TIMEOUT", 60)

JIRA_STATUS_INCOMING = "Incoming"
JIRA_STATUS_PENDING_RESOLUTION = "Pending resolution"
JIRA_STATUS_IN_PROGRESS = "in progress"
JIRA_STATUS_REPORTER_VALIDATION = "Reporter validation"
JIRA_STATUS_CLOSED = "Closed"

IMPACT_TO_JIRA_STATUS_MAP: dict[IncidentStatus, str] = {
    IncidentStatus.OPEN: JIRA_STATUS_INCOMING,
    IncidentStatus.INVESTIGATING: JIRA_STATUS_IN_PROGRESS,
    IncidentStatus.MITIGATING: JIRA_STATUS_IN_PROGRESS,
    IncidentStatus.MITIGATED: JIRA_STATUS_REPORTER_VALIDATION,
    IncidentStatus.POST_MORTEM: JIRA_STATUS_REPORTER_VALIDATION,
    IncidentStatus.CLOSED: JIRA_STATUS_CLOSED,
}


def _set_impact_to_jira_cache(
    incident_id: Any, field: str, value: Any, timeout: int = JIRA_SYNC_CACHE_TIMEOUT
) -> None:
    cache_key = (
        f"sync:impact_to_jira:{incident_id}:{field}:{normalize_cache_value(value)}"
    )
    cache.set(cache_key, value=True, timeout=timeout)


@receiver(signal=incident_updated, sender="update_status")
def incident_updated_close_ticket_when_mitigated_or_postmortem(
    sender: Any,
    incident: Incident,
    incident_update: IncidentUpdate,
    updated_fields: list[str],
    **kwargs: Any,
) -> None:
    """Close Jira incident ticket based on incident status and priority.

    Closure logic:
    - P1/P2 (needs_postmortem): Close only when incident is CLOSED
    - P3+ (no postmortem): Close when incident is MITIGATED or CLOSED
    - POST_MORTEM status never closes the ticket (it remains open during PM phase)
    """
    logger.debug(
        "incident_updated handler invoked for incident #%s with status %s; updated_fields=%s event_type=%s",
        getattr(incident, "id", "unknown"),
        incident_update.status,
        updated_fields,
        incident_update.event_type,
    )
    # Skip if this update was produced by Jira webhook sync to avoid redundant close calls
    if incident_update.event_type == "jira_status_sync":
        logger.debug(
            "Skipping Jira transition: incident #%s update came from Jira (event_type=jira_status_sync)",
            getattr(incident, "id", "unknown"),
        )
        return

    if "_status" not in updated_fields:
        logger.debug(
            "Skipping Jira transition: incident #%s update lacks _status in updated_fields (%s)",
            getattr(incident, "id", "unknown"),
            updated_fields,
        )
        return

    if not hasattr(incident, "jira_ticket") or incident.jira_ticket is None:
        logger.warning(
            "Trying to close Jira ticket for incident %s but no Jira ticket found",
            getattr(incident, "id", "unknown"),
        )
        return

    # Special case: when Impact moves to INVESTIGATING or MITIGATING, Jira must go
    # through two steps: "Pending resolution" then "in progress". We also set
    # cache keys for both steps to prevent the Jira→Impact webhook from bouncing
    # Impact back to OPEN on the intermediate hop.
    if incident_update.status in (IncidentStatus.INVESTIGATING, IncidentStatus.MITIGATING):
        steps = (JIRA_STATUS_PENDING_RESOLUTION, JIRA_STATUS_IN_PROGRESS)
        incident_id = getattr(incident, "id", None)
        if incident_id is not None:
            for step in steps:
                _set_impact_to_jira_cache(incident_id, "status", step)

        all_steps_succeeded = True
        for step in steps:
            try:
                logger.debug(
                    "Transitioning Jira ticket %s via workflow %s to status %s (incident #%s, impact status %s)",
                    incident.jira_ticket.id,
                    RAID_JIRA_WORKFLOW_NAME,
                    step,
                    getattr(incident, "id", "unknown"),
                    incident_update.status,
                )
                client.transition_issue_auto(
                    incident.jira_ticket.id, step, RAID_JIRA_WORKFLOW_NAME
                )
            except Exception:
                all_steps_succeeded = False
                logger.exception(
                    "Failed to transition Jira ticket %s to %s for incident %s",
                    incident.jira_ticket.id,
                    step,
                    getattr(incident, "id", "unknown"),
                )
        if all_steps_succeeded:
            logger.info(
                "Transitioned Jira ticket %s through Pending resolution -> in progress from Impact status %s",
                incident.jira_ticket.id,
                incident_update.status.label if incident_update.status else "Unknown",
            )
        else:
            logger.warning(
                "At least one Jira transition failed while moving ticket %s to MITIGATING (incident #%s)",
                incident.jira_ticket.id,
                getattr(incident, "id", "unknown"),
            )
        return

    # Decide target Jira status based on Impact status and postmortem requirement.
    # P3+ (no postmortem): close Jira when Impact reaches MITIGATED or CLOSED.
    # P1/P2 (needs_postmortem): close Jira only when Impact reaches CLOSED.
    incident_status = incident_update.status
    if incident_status is None:
        logger.info(
            "Skipping Jira transition: incident #%s status is None",
            getattr(incident, "id", "unknown"),
        )
        return

    target_jira_status: str | None = (
        JIRA_STATUS_CLOSED
        if incident_status == IncidentStatus.CLOSED
        else IMPACT_TO_JIRA_STATUS_MAP.get(incident_status)
    )

    if target_jira_status is None:
        logger.info(
            "Skipping Jira transition: no Jira status mapping for Impact status %s (incident #%s)",
            incident_update.status,
            getattr(incident, "id", "unknown"),
        )
        return

    try:
        incident_id = getattr(incident, "id", None)
        if incident_id is not None:
            _set_impact_to_jira_cache(incident_id, "status", target_jira_status)
        logger.debug(
            "Transitioning Jira ticket %s via workflow %s to status %s (incident #%s, impact status %s)",
            incident.jira_ticket.id,
            RAID_JIRA_WORKFLOW_NAME,
            target_jira_status,
            getattr(incident, "id", "unknown"),
            incident_update.status,
        )
        client.transition_issue_auto(
            incident.jira_ticket.id, target_jira_status, RAID_JIRA_WORKFLOW_NAME
        )
        logger.info(
            "Transitioned Jira ticket %s to %s from Impact status %s",
            incident.jira_ticket.id,
            target_jira_status,
            incident_update.status.label if incident_update.status else "Unknown",
        )
    except Exception:
        logger.exception(
            "Failed to transition Jira ticket %s to %s for incident %s",
            incident.jira_ticket.id,
            target_jira_status,
            getattr(incident, "id", "unknown"),
        )


# Listen to all incident_updated signals so both UI (update_status) and API/admin paths trigger
@receiver(signal=incident_updated)
def incident_updated_sync_priority_to_jira(
    sender: Any,
    incident: Incident,
    incident_update: IncidentUpdate,
    updated_fields: list[str],
    **kwargs: Any,
) -> None:
    """Push Impact priority changes to Jira custom priority field (customfield_11064).
    Skips if change originated from Jira (event_type='jira_priority_sync') to avoid loops.
    """
    logger.debug(
        "Priority sync handler invoked: incident #%s sender=%s updated_fields=%s event_type=%s",
        getattr(incident, "id", "unknown"),
        sender,
        updated_fields,
        incident_update.event_type,
    )

    if incident_update.event_type == "jira_priority_sync":
        logger.debug(
            "Skipping Jira priority sync: incident #%s update came from Jira (event_type=jira_priority_sync)",
            getattr(incident, "id", "unknown"),
        )
        return

    if "priority_id" not in updated_fields:
        logger.debug(
            "Skipping Jira priority sync: incident #%s update lacks priority_id in updated_fields (%s) sender=%s",
            getattr(incident, "id", "unknown"),
            updated_fields,
            sender,
        )
        return

    if not hasattr(incident, "jira_ticket") or incident.jira_ticket is None:
        logger.debug(
            "Skipping Jira priority sync: incident #%s has no Jira ticket",
            getattr(incident, "id", "unknown"),
        )
        return

    if not incident.priority:
        logger.debug(
            "Skipping Jira priority sync: incident #%s priority is missing",
            getattr(incident, "id", "unknown"),
        )
        return

    try:
        incident_id = getattr(incident, "id", None)
        if incident_id is not None:
            _set_impact_to_jira_cache(incident_id, "priority", incident.priority.value)
        client.update_issue_fields(
            incident.jira_ticket.id,
            customfield_11064={"value": str(incident.priority.value)},
        )
        logger.info(
            "Synced priority %s to Jira ticket %s (customfield_11064) for incident #%s",
            incident.priority.value,
            incident.jira_ticket.id,
            getattr(incident, "id", "unknown"),
        )
    except Exception:
        logger.exception(
            "Failed to sync priority %s to Jira ticket %s for incident %s",
            incident.priority.value,
            incident.jira_ticket.id,
            getattr(incident, "id", "unknown"),
        )


# Fallback: if an Incident save bypasses incident_updated (e.g., admin inline), push priority anyway.
@receiver(post_save, sender=Incident)
def incident_priority_post_save_fallback(
    sender: Any,
    instance: Incident,
    *,
    created: bool,
    update_fields: set[str] | None,
    **kwargs: Any,
) -> None:
    """Fallback to push priority to Jira when Incident saves with priority_id in update_fields
    but no incident_updated signal fired (e.g., admin edits). Skips when marked to avoid loops.
    """
    if created:
        return
    if update_fields and "priority_id" not in update_fields:
        return
    if getattr(instance, "_skip_priority_sync", False):
        logger.debug(
            "Skipping post_save priority sync for incident #%s due to skip flag",
            getattr(instance, "id", "unknown"),
        )
        return
    if not hasattr(instance, "jira_ticket") or instance.jira_ticket is None:
        logger.debug(
            "Skipping post_save priority sync: incident #%s has no Jira ticket",
            getattr(instance, "id", "unknown"),
        )
        return
    if not instance.priority:
        logger.debug(
            "Skipping post_save priority sync: incident #%s priority missing",
            getattr(instance, "id", "unknown"),
        )
        return

    try:
        _set_impact_to_jira_cache(instance.id, "priority", instance.priority.value)
        client.update_issue_fields(
            instance.jira_ticket.id,
            customfield_11064={"value": str(instance.priority.value)},
        )
        logger.info(
            "Post-save synced priority %s to Jira ticket %s (customfield_11064) for incident #%s",
            instance.priority.value,
            instance.jira_ticket.id,
            getattr(instance, "id", "unknown"),
        )
    except Exception:
        logger.exception(
            "Failed post-save priority sync %s to Jira ticket %s for incident %s",
            instance.priority.value,
            instance.jira_ticket.id,
            getattr(instance, "id", "unknown"),
        )


@receiver(post_save, sender=Incident)
def incident_status_post_save_fallback(
    sender: Any,
    instance: Incident,
    *,
    created: bool,
    update_fields: set[str] | None,
    **kwargs: Any,
) -> None:
    """Fallback to push status to Jira when Incident saves with status in update_fields
    but no incident_updated signal fired (e.g., admin edits). Skips when marked to avoid loops.
    """
    if created:
        return
    if (
        update_fields
        and "_status" not in update_fields
        and "status" not in update_fields
    ):
        return
    if getattr(instance, "_skip_status_sync", False):
        logger.debug(
            "Skipping post_save status sync for incident #%s due to skip flag",
            getattr(instance, "id", "unknown"),
        )
        return
    if not hasattr(instance, "jira_ticket") or instance.jira_ticket is None:
        logger.debug(
            "Skipping post_save status sync: incident #%s has no Jira ticket",
            getattr(instance, "id", "unknown"),
        )
        return
    target_jira_status = IMPACT_TO_JIRA_STATUS_MAP.get(instance.status)
    if target_jira_status is None:
        logger.debug(
            "Skipping post_save status sync: no Jira mapping for status %s (incident #%s)",
            instance.status,
            getattr(instance, "id", "unknown"),
        )
        return
    try:
        _set_impact_to_jira_cache(instance.id, "status", target_jira_status)
        client.transition_issue_auto(
            instance.jira_ticket.id, target_jira_status, RAID_JIRA_WORKFLOW_NAME
        )
        logger.info(
            "Post-save synced status %s to Jira ticket %s for incident #%s",
            instance.status,
            instance.jira_ticket.id,
            getattr(instance, "id", "unknown"),
        )
    except Exception:
        logger.exception(
            "Failed post-save status sync %s to Jira ticket %s for incident %s",
            instance.status,
            instance.jira_ticket.id,
            getattr(instance, "id", "unknown"),
        )
