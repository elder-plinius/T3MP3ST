from __future__ import annotations

from django.apps import apps
from django.urls import path

from firefighter.api.urls import urlpatterns as api_urlspatterns
from firefighter.raid import views

# Patch `api` app router, if installed
if apps.is_installed("firefighter.api"):
    api_urlspatterns.append(
        path(
            "raid/jira_bot",
            views.CreateJiraBotView.as_view(),  # pyright: ignore[reportGeneralTypeIssues]
            name="jira_bot",
        ),
    )

    api_urlspatterns.append(
        path(
            "raid/jira_comment",
            views.JiraCommentAlertView.as_view(),  # pyright: ignore[reportGeneralTypeIssues]
            name="jira_comment",
        ),
    )

    api_urlspatterns.append(
        path(
            "raid/jira_update",
            views.JiraUpdateAlertView.as_view(),  # pyright: ignore[reportGeneralTypeIssues]
            name="jira_update",
        ),
    )
