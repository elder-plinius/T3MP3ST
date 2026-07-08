from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Final, Never

from django.conf import settings
from drf_spectacular.utils import OpenApiExample, extend_schema
from rest_framework import generics, mixins, permissions, status
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response

from firefighter.raid.models import JiraTicket
from firefighter.raid.serializers import (
    JiraWebhookCommentSerializer,
    JiraWebhookUpdateSerializer,
    LandbotIssueRequestSerializer,
)

RAID_DEFAULT_JIRA_QRAFT_USER_ID: Final[str] = settings.RAID_DEFAULT_JIRA_QRAFT_USER_ID


logger = logging.getLogger(__name__)
if TYPE_CHECKING:
    from rest_framework.request import Request


@extend_schema(
    examples=[
        OpenApiExample(
            "Create an issue",
            summary="Create an issue",
            description="Example of a working request coming from landbot. be careful, as you probably don't have a john.doe user and thus may fallback to the default user.",
            value={
                "summary": "Swagger test",
                "description": "Description test where you want to depict your issue",
                "seller_contract_id": "12345678",
                "zoho": "https://crmplus.zoho.eu/mycrmlink/index.do/cxapp/agent/mycompany/all/tickets/details/123456789",
                "zendesk": "12345",
                "platform": "FR",
                "reporter_email": "john.doe@mycompany.com",
                "incident_category": "Payment Processing",
                "project": "SBI",
                "labels": ["originBot", "ProductsMerge"],
                "environments": ["PRD", "STG"],
                "issue_type": "Incident",
                "business_impact": "High",
                "priority": 4,
                "attachments": [
                    "https://storage.googleapis.com/media.landbot.io/123456/customers/123456789/ABCDEFGHIJKLMNOPQRSTUVWXYZ123456.png",
                    "https://storage.googleapis.com/media.landbot.io/123456/customers/123456780/ABCDEFGHIJKLMNOPQRSTUVWXYZ123450.png",
                ],
            },
            request_only=True,  # signal that example only applies to requests
            response_only=False,  # signal that example only applies to responses
        ),
        OpenApiExample(
            "Create incident response",
            status_codes=["201"],
            value={"https://mycompany.atlassian.net/browse/1234567"},
            request_only=False,
            response_only=True,
        ),
    ]
)
class CreateJiraBotView(
    mixins.CreateModelMixin,
    generics.GenericAPIView[JiraTicket],
):
    queryset = JiraTicket.objects.all().select_related(
        "assignee",
        "reporter",
        "incident",
        "jiraissue_ptr",
    )
    serializer_class = LandbotIssueRequestSerializer
    permission_classes = [permissions.AllowAny]
    renderer_classes = [JSONRenderer]

    def post(self, request: Request, *args: Never, **kwargs: Never) -> Response:
        """Allow to create a Jira ticket through Landbot.
        Requires a valid Bearer token, that you can create in the back-office if you have the right permissions.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data.get("key"), status=status.HTTP_201_CREATED, headers=headers
        )


class JiraUpdateAlertView(
    generics.CreateAPIView[Any],
):
    serializer_class = JiraWebhookUpdateSerializer
    # XXX: Work on webhook token for authentication_classes
    authentication_classes = []
    permission_classes = [permissions.AllowAny]
    renderer_classes = [JSONRenderer]

    def post(self, request: Request, *args: Never, **kwargs: Never) -> Response:
        """Allow to send a message in Slack when some fields ("Priority", "project", "description", "status") of a Jira ticket are updated.
        Requires a valid Bearer token, that you can create in the back-office if you have the right permissions.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response()


class JiraCommentAlertView(
    generics.CreateAPIView[Any],
):
    serializer_class = JiraWebhookCommentSerializer
    # XXX: Work on webhook token for authentication_classes
    authentication_classes = []
    permission_classes = [permissions.AllowAny]
    renderer_classes = [JSONRenderer]

    def post(self, request: Request, *args: Never, **kwargs: Never) -> Response:
        """Allow to send a message in Slack when a comment in a Jira ticket is created or modified.
        Requires a valid Bearer token, that you can create in the back-office if you have the right permissions.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response()
