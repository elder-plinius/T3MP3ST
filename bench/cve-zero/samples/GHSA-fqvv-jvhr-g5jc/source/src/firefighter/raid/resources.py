from __future__ import annotations

from import_export import resources

from firefighter.raid.models import FeatureTeam


class FeatureTeamResource(resources.ModelResource):
    class Meta:
        model = FeatureTeam
        skip_unchanged = True
        report_skipped = False
        fields = ("id", "name", "jira_project_key")
        import_order = ("name", "jira_project_key")
        export_order = ("name", "jira_project_key")
