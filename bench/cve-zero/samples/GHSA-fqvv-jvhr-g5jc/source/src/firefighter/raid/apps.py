from __future__ import annotations

import logging

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class RaidConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    label = "raid"
    name = "firefighter.raid"
    verbose_name = "RAID"

    def ready(self) -> None:
        import firefighter.raid.tasks
        import firefighter.raid.urls
        from firefighter.raid.signals import (
            incident_updated,
        )
        from firefighter.slack.views.modals.open import INCIDENT_TYPES
        from firefighter.slack.views.modals.opening.details.unified import (
            OpeningUnifiedModal,
        )

        # Use unified form for all normal incidents (P4-P5)
        # This replaces the previous 5 separate forms (Customer/Seller/Internal/Doc/Feature)
        # STEP 3 (incident type selection) will be automatically hidden since len() == 1
        INCIDENT_TYPES["normal"] = {
            "normal": {
                "label": "Normal",
                "slack_form": OpeningUnifiedModal,
            },
        }

        return super().ready()
