import datetime
import time
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.monitor import MonitorAdapter
from app.azure.resources import ResourcesAdapter
from app.utils.resource_ids import parse_azure_resource_id

from app.utils.environment import resolve_environment

class ResourcesWithoutLogsAssessment(BaseAssessment):
    assessment_id = "resources_without_logs"
    code = "SEC-03"
    category = "security"
    name = "Resources Missing Diagnostic Logs"
    description = "Identify cloud resources lacking required diagnostic logging or audit streaming based on evaluation scope."
    purpose = "Ensure compliance with observability and security auditing policies across your cloud workloads."
    required_permissions = ["Microsoft.Insights/diagnosticSettings/read", "Microsoft.Resources/subscriptions/resources/read", "Monitoring Reader"]
    required_data_sources = ["Azure Monitor Diagnostic Settings API (2021-05-01-preview)"]

    def _matches_target_tags(self, resource: Dict[str, Any], sub_name: str, target_tags: List[str], prod_tags: List[str]) -> bool:
        tags = resource.get("tags") or {}
        res_name = str(resource.get("name") or "").strip()
        res_id = str(resource.get("id") or "").strip()
        parsed = parse_azure_resource_id(res_id)
        rg_name = str(parsed.get("resource_group") or "").strip()

        # 1. Pure tag-based scoping: If NO tags configured, evaluate ALL resources
        clean_target_tags = [str(tt).strip() for tt in (target_tags or []) if str(tt).strip()]
        if not clean_target_tags:
            return True

        # 2. If user configured target evaluation tags: match ONLY resources having the tag
        for tt in clean_target_tags:
            tt_lower = tt.lower()
            # Check resource tags (keys and values)
            for k, v in tags.items():
                if k is None:
                    continue
                k_str = str(k).strip()
                v_str = str(v).strip() if v is not None else ""
                tag_pair = f"{k_str}={v_str}".lower()
                if (
                    tt_lower == k_str.lower()
                    or tt_lower == v_str.lower()
                    or tt_lower == tag_pair
                    or tt_lower in tag_pair
                ):
                    return True

            # Also check resource group or resource name matching tag
            if tt_lower in rg_name.lower() or tt_lower in res_name.lower():
                return True

        return False

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        # Auditable resource types that require diagnostic settings in production (case-insensitive)
        target_types = {
            "microsoft.keyvault/vaults",
            "microsoft.storage/storageaccounts",
            "microsoft.sql/servers",
            "microsoft.network/applicationgateways",
            "microsoft.network/azurefirewalls",
            "microsoft.network/networksecuritygroups",
            "microsoft.containerservice/managedclusters"
        }

        for sub in context.subscriptions:
            # Discover resources
            resources = await ResourcesAdapter.get_subscription_resources(context.client, sub.subscription_id)
            if not resources:
                continue

            for res in resources:
                res_type = res.get("type", "")
                if res_type.lower() not in target_types:
                    continue

                if not self._matches_target_tags(res, sub.display_name, context.target_tags, context.prod_tags):
                    continue

                resources_evaluated += 1
                res_id = res.get("id", "")
                res_name = res.get("name", "Unknown")
                res_location = res.get("location", "global")
                parsed = parse_azure_resource_id(res_id)
                rg_name = parsed.get("resource_group") or "Unknown"
                env_label = resolve_environment(res.get("tags"), res_name, rg_name, prod_tags=context.prod_tags, test_tags=context.target_tags)
                if env_label == "Unassigned" and context.target_tags:
                    env_label = context.target_tags[0]

                # Fetch diagnostic settings
                diag_settings = await MonitorAdapter.get_diagnostic_settings(context.client, res_id)
                
                # Check diagnostic status
                is_gap = False
                diag_status = "Missing Diagnostic Settings"
                enabled_categories: List[str] = []
                workspace_target = "None Configured"
                storage_target = "None"

                if not diag_settings:
                    is_gap = True
                    diag_status = "Missing Diagnostic Settings"
                else:
                    # Evaluate whether logs are enabled and streaming to a verified target
                    has_active_log = False
                    for ds in diag_settings:
                        props = ds.get("properties", {})
                        ws_id = props.get("workspaceId")
                        st_id = props.get("storageAccountId")
                        if ws_id:
                            workspace_target = ws_id.split("/")[-1]
                        if st_id:
                            storage_target = st_id.split("/")[-1]

                        logs = props.get("logs", [])
                        for l in logs:
                            if l.get("enabled"):
                                has_active_log = True
                                cat = l.get("category") or l.get("categoryGroup")
                                if cat and cat not in enabled_categories:
                                    enabled_categories.append(cat)

                    if not has_active_log:
                        is_gap = True
                        diag_status = "Settings Configured (All Log Categories Disabled)"
                    elif workspace_target == "None Configured" and storage_target == "None":
                        is_gap = True
                        diag_status = "Settings Configured (No Ingestion Target)"

                # Only report resources with gaps
                if is_gap:
                    categories_str = ", ".join(enabled_categories) if enabled_categories else "None"
                    short_type = res_type.split("/")[-1]
                    f_impact = 2.0 if short_type in ("vaults", "servers", "applicationGateways") else 1.0

                    findings.append(
                        FindingModel(
                            finding_id=f"sec03-{sub.subscription_id[:8]}-{res_name[:12]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg_name,
                            resource_name=res_name,
                            resource_type=res_type,
                            resource_id=res_id,
                            region=res_location,
                            severity="High" if short_type in ("vaults", "servers", "applicationGateways") else "Medium",
                            status=diag_status,
                            current_configuration=f"Diagnostic logging gap on {short_type}: {diag_status}",
                            measured_value=diag_status,
                            recommended_configuration=f"Configure diagnostic settings streaming audit logs to Log Analytics Workspace",
                            recommendation=f"Resource '{res_name}' ({short_type}) has diagnostic logging gaps: {diag_status}. In Azure Monitor, navigate to Diagnostic settings for this resource and configure audit log streaming to a central Log Analytics workspace.",
                            metric_period="Current configuration",
                            data_source="Azure Monitor Diagnostic Settings API",
                            evidence={
                                "environment": env_label,
                                "diagnostic_status": diag_status,
                                "enabled_log_categories": categories_str,
                                "workspace_name": workspace_target,
                                "storage_destination": storage_target,
                                "resource_type_short": short_type,
                                "security_control": "Enable diagnostic logging",
                                "potential_score_increase": f"+{f_impact:.1f}%",
                            },
                            security_score_impact=f_impact,
                            collected_at=now_str
                        )
                    )

        status = AssessmentStatus.COMPLETED if findings else AssessmentStatus.NO_FINDINGS
        total_score_impact = round(sum(f.security_score_impact for f in findings if f.security_score_impact), 1) if findings else None

        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=max(resources_evaluated, len(context.subscriptions)),
            findings_count=len(findings),
            findings=findings,
            errors=errors,
            security_score_improvement=total_score_impact,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
