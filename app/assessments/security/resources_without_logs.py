import datetime
import time
from typing import List, Dict, Any, Optional
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.monitor import MonitorAdapter
from app.azure.resources import ResourcesAdapter
from app.utils.resource_ids import parse_azure_resource_id
from app.utils.environment import resolve_environment


def classify_target_service(res_type: str) -> Optional[Dict[str, Any]]:
    """
    Classifies a resource type into one of the 5 official diagnostic log audit categories.
    Any resource type not matching these 5 categories is strictly excluded to prevent report bloat.
    """
    res_type_lower = (res_type or "").lower().strip()

    # 1. Logic Apps
    if res_type_lower == "microsoft.logic/workflows":
        return {
            "category": "logic_apps",
            "friendly_label": "Logic Apps",
            "headline": "Diagnostic logs in Logic Apps should be enabled",
            "severity": "Medium",
            "impact": 1.5,
        }

    # 2. Key Vault
    if res_type_lower == "microsoft.keyvault/vaults":
        return {
            "category": "key_vault",
            "friendly_label": "Key Vault",
            "headline": "Diagnostic logs in Key Vault should be enabled",
            "severity": "High",
            "impact": 2.5,
        }

    # 3. App Service (Web Apps & Function Apps)
    if res_type_lower == "microsoft.web/sites":
        return {
            "category": "app_service",
            "friendly_label": "App Service",
            "headline": "Diagnostic logs in App Service should be enabled",
            "severity": "Medium",
            "impact": 1.5,
        }

    # 4. Microsoft Foundry resources (Azure AI, Cognitive Services, Machine Learning, AI Studio)
    if (
        res_type_lower in (
            "microsoft.cognitiveservices/accounts",
            "microsoft.machinelearningservices/workspaces",
            "microsoft.aistudio/workspaces",
        )
        or any(k in res_type_lower for k in ("foundry", "cognitiveservices", "machinelearningservices", "aistudio"))
    ):
        return {
            "category": "foundry",
            "friendly_label": "Microsoft Foundry resources",
            "headline": "Diagnostic logs in Microsoft Foundry resources should be enabled",
            "severity": "Medium",
            "impact": 2.0,
        }

    # 5. Kubernetes services (AKS)
    if res_type_lower == "microsoft.containerservice/managedclusters":
        return {
            "category": "kubernetes",
            "friendly_label": "Kubernetes services",
            "headline": "Diagnostic logs in Kubernetes services should be enabled",
            "severity": "High",
            "impact": 2.5,
        }

    return None


class ResourcesWithoutLogsAssessment(BaseAssessment):
    assessment_id = "resources_without_logs"
    code = "SEC-03"
    category = "security"
    name = "Resources Missing Diagnostic Logs"
    description = (
        "Identify critical cloud resources lacking required diagnostic logging or audit streaming across: "
        "Logic Apps, Key Vault, App Service, Microsoft Foundry resources, and Kubernetes services."
    )
    purpose = (
        "Ensure compliance with observability and security auditing policies across the 5 core services: "
        "Logic Apps, Key Vault, App Service, Microsoft Foundry, and Kubernetes services."
    )
    required_permissions = [
        "Microsoft.Insights/diagnosticSettings/read",
        "Microsoft.Resources/subscriptions/resources/read",
        "Monitoring Reader",
    ]
    required_data_sources = ["Azure Monitor Diagnostic Settings API (2021-05-01-preview)"]

    def _matches_target_tags(self, resource: Dict[str, Any], sub_name: str, target_tags: List[str], prod_tags: List[str]) -> bool:
        tags = resource.get("tags") or {}
        res_name = str(resource.get("name") or "").strip()
        res_id = str(resource.get("id") or "").strip()
        parsed = parse_azure_resource_id(res_id)
        rg_name = str(parsed.get("resource_group") or "").strip()

        # Pure tag-based scoping: If NO tags configured, evaluate all in target services
        clean_target_tags = [str(tt).strip() for tt in (target_tags or []) if str(tt).strip()]
        if not clean_target_tags:
            return True

        for tt in clean_target_tags:
            tt_lower = tt.lower()
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

            if tt_lower in rg_name.lower() or tt_lower in res_name.lower():
                return True

        return False

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        for sub in context.subscriptions:
            resources = await ResourcesAdapter.get_subscription_resources(context.client, sub.subscription_id)
            if not resources:
                continue

            for res in resources:
                res_type = res.get("type", "")
                
                # STRICT SCOPE FILTER:
                # Only evaluate the 5 required target services.
                # All other resource types (storage accounts, NSGs, SQL servers, etc.) are strictly excluded.
                service_info = classify_target_service(res_type)
                if not service_info:
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

                # Fetch live diagnostic settings from Azure Monitor
                diag_settings = await MonitorAdapter.get_diagnostic_settings(context.client, res_id)

                is_gap = False
                diag_status = "Missing Diagnostic Settings"
                enabled_categories: List[str] = []
                workspace_target = "None Configured"
                storage_target = "None"
                event_hub_target = ""

                if not diag_settings:
                    is_gap = True
                    diag_status = "Missing Diagnostic Settings"
                else:
                    has_active_log = False
                    for ds in diag_settings:
                        props = ds.get("properties", {}) or {}
                        ws_id = props.get("workspaceId")
                        st_id = props.get("storageAccountId")
                        eh_id = props.get("eventHubAuthorizationRuleId") or props.get("eventHubName")
                        if ws_id:
                            workspace_target = ws_id.split("/")[-1]
                        if st_id:
                            storage_target = st_id.split("/")[-1]
                        if eh_id:
                            event_hub_target = eh_id.split("/")[-1]

                        logs = props.get("logs", []) or []
                        for l in logs:
                            if l.get("enabled"):
                                has_active_log = True
                                cat = l.get("category") or l.get("categoryGroup")
                                if cat and cat not in enabled_categories:
                                    enabled_categories.append(cat)

                    has_destination = bool(workspace_target != "None Configured" or storage_target != "None" or event_hub_target)

                    if not has_active_log:
                        is_gap = True
                        diag_status = "Settings Configured (All Log Categories Disabled)"
                    elif not has_destination:
                        is_gap = True
                        diag_status = "Settings Configured (No Ingestion Target)"

                # Only report resources with genuine diagnostic logging gaps
                if is_gap:
                    categories_str = ", ".join(enabled_categories) if enabled_categories else "None"
                    headline = service_info["headline"]
                    friendly_label = service_info["friendly_label"]
                    severity = service_info["severity"]
                    f_impact = service_info["impact"]

                    dest_str = storage_target
                    if event_hub_target:
                        dest_str = f"EventHub: {event_hub_target}" if storage_target == "None" else f"{storage_target}, EventHub: {event_hub_target}"

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
                            severity=severity,
                            status=diag_status,
                            current_configuration=f"{headline}: {diag_status}",
                            measured_value=diag_status,
                            recommended_configuration="Enable diagnostic settings routing audit logs to Log Analytics Workspace",
                            recommendation=(
                                f"{headline}. Resource '{res_name}' ({friendly_label}) in resource group '{rg_name}' "
                                f"has diagnostic logging gap: {diag_status}. Navigate to Azure Monitor Diagnostic Settings "
                                f"for this resource and configure audit log streaming to a centralized Log Analytics workspace."
                            ),
                            metric_period="Current configuration",
                            data_source="Azure Monitor Diagnostic Settings API",
                            evidence={
                                "recommendation_headline": headline,
                                "friendly_label": friendly_label,
                                "environment": env_label,
                                "diagnostic_status": diag_status,
                                "enabled_log_categories": categories_str,
                                "workspace_name": workspace_target,
                                "storage_destination": dest_str,
                                "resource_type_short": friendly_label,
                                "security_control": "Enable audit and logging",
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

