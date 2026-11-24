import datetime
import time
import logging
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.defender import DefenderAdapter
from app.utils.resource_ids import parse_azure_resource_id

logger = logging.getLogger("azure_finsecops.assessments.attack_paths")

class AttackPathsAssessment(BaseAssessment):
    assessment_id = "attack_paths"
    code = "SEC-07"
    category = "security"
    name = "Attack Paths"
    description = "Identify exposed lateral movement attack paths, internet-exposed assets, and high-risk exploitation vectors from Defender CSPM."
    purpose = "Discover multi-hop exploitation vectors that attackers can traverse to compromise critical cloud workloads and databases."
    required_permissions = [
        "Microsoft.Security/attackPaths/read",
        "Microsoft.Security/assessments/read",
        "Security Reader"
    ]
    required_data_sources = ["Defender CSPM Attack Paths API & Defender for Cloud Lateral Movement Analysis"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        seen_path_ids = set()

        for sub in context.subscriptions:
            # 1. Primary: Direct Defender CSPM Attack Paths API
            resp = await DefenderAdapter.get_attack_paths(context.client, sub.subscription_id)
            paths = resp.get("value", []) if resp.get("success") else []

            # 2. Secondary: Fallback to Azure Resource Graph for Attack Paths
            if not paths:
                try:
                    arg_url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
                    arg_payload = {
                        "subscriptions": [sub.subscription_id],
                        "query": (
                            f"securityresources "
                            f"| where subscriptionId =~ '{sub.subscription_id}' "
                            f"| where type =~ 'microsoft.security/attackpaths' "
                            f"| project id, name, type, properties"
                        ),
                        "options": {
                            "resultFormat": "objectArray"
                        }
                    }
                    arg_resp = await context.client.execute_request("POST", arg_url, json_data=arg_payload)
                    if arg_resp.status_code == 200:
                        arg_data = arg_resp.json().get("data", [])
                        if isinstance(arg_data, list):
                            paths = arg_data
                except Exception as ex:
                    logger.debug("ARG query for attack paths in sub %s: %s", sub.subscription_id, ex)

            # Process discovered CSPM attack paths
            for path in paths:
                path_id = path.get("id") or path.get("name")
                if path_id in seen_path_ids:
                    continue
                seen_path_ids.add(path_id)
                resources_evaluated += 1

                props = path.get("properties", {}) or {}
                display_name = props.get("displayName") or path.get("name", "Exposed Attack Path")
                target_id = props.get("targetResourceId") or ""
                parsed_target = parse_azure_resource_id(target_id) if target_id else {}
                rg_name = parsed_target.get("resource_group") or "DefenderCSPM"
                target_name = parsed_target.get("resource_name") or (target_id.split("/")[-1] if target_id else "High-Value Asset")
                res_type = parsed_target.get("resource_type") or "Microsoft.Security/attackPaths"

                entry_point = props.get("entryPoint") or "Internet / Public Endpoint"
                risk_level = str(props.get("riskLevel") or props.get("severity") or "Critical")
                techniques = props.get("techniques")
                tech_str = ", ".join(techniques) if isinstance(techniques, list) and techniques else (
                    str(techniques) if techniques else "--"
                )
                recs = props.get("recommendations")
                rec_str = recs[0] if (isinstance(recs, list) and recs) else (str(recs) if recs else "--")

                findings.append(
                    FindingModel(
                        finding_id=f"sec07-{sub.subscription_id[:8]}-{path.get('name', '')[:10]}",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group=rg_name,
                        resource_name=display_name,
                        resource_type=res_type,
                        resource_id=path.get("id") or target_id,
                        region=path.get("location", "global"),
                        severity=risk_level.capitalize() if risk_level else "Critical",
                        status="Active Attack Path",
                        current_configuration=f"Exposed attack path to target '{target_name}'",
                        measured_value=f"Risk Level: {risk_level}",
                        recommended_configuration=rec_str,
                        recommendation=f"Remediate attack path '{display_name}' targeting asset '{target_name}'. {rec_str}",
                        metric_period="Active CSPM analysis",
                        data_source="Defender CSPM Attack Paths API",
                        evidence={
                            "attack_path_name": display_name,
                            "source_resource": entry_point,
                            "target_resource": target_name,
                            "affected_resource": target_name,
                            "risk_level": risk_level,
                            "attack_techniques": tech_str,
                            "recommendation": rec_str
                        },
                        collected_at=now_str
                    )
                )

            # 3. Tertiary: Inspect Defender for Cloud lateral movement, perimeter exposure, and attack vector recommendations
            assessments_resp = await DefenderAdapter.get_security_assessments(context.client, sub.subscription_id, max_items=300)
            if assessments_resp.get("success"):
                for ass in assessments_resp.get("value", []):
                    ass_id = ass.get("id", "")
                    if ass_id in seen_path_ids:
                        continue

                    props = ass.get("properties", {}) or {}
                    meta = props.get("metadata", {}) or {}
                    title = meta.get("displayName") or props.get("displayName", "")
                    cats = meta.get("categories", [])
                    cat_str = " ".join(cats).lower() if isinstance(cats, list) else str(cats).lower()
                    status_code = str(props.get("status", {}).get("code", "")).lower()

                    if status_code not in ("unhealthy", "open"):
                        continue

                    title_lower = title.lower()
                    is_attack_path_rec = any(
                        kw in title_lower for kw in [
                            "attack path", "lateral movement", "lateral tool", "internet-exposed",
                            "internet exposed", "public-facing", "management ports", "network exposure"
                        ]
                    ) or any(ck in cat_str for ck in ["attackpath", "lateralmovement", "perimeter"])

                    if is_attack_path_rec:
                        seen_path_ids.add(ass_id)
                        resources_evaluated += 1

                        target_id = props.get("resourceDetails", {}).get("Id") or props.get("resourceDetails", {}).get("id") or ass_id
                        parsed_target = parse_azure_resource_id(target_id)
                        rg_name = parsed_target.get("resource_group") or "DefenderCSPM"
                        target_name = parsed_target.get("resource_name") or target_id.split("/")[-1] or "High-Value Asset"
                        res_type = parsed_target.get("resource_type") or "Microsoft.Security/assessments"
                        remediation_desc = meta.get("remediationDescription") or meta.get("description") or "Remediate lateral movement entry point."
                        sev = meta.get("severity", "High").capitalize()

                        findings.append(
                            FindingModel(
                                finding_id=f"sec07-{sub.subscription_id[:8]}-{ass.get('name', '')[:10]}",
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group=rg_name,
                                resource_name=title,
                                resource_type=res_type,
                                resource_id=ass_id,
                                region="global",
                                severity=sev,
                                status="Active Attack Path Risk",
                                current_configuration=f"Lateral movement vector: '{title}'",
                                measured_value=f"Risk Level: {sev}",
                                recommended_configuration="Break attack path chain by remediating entry-point vulnerabilities",
                                recommendation=remediation_desc,
                                metric_period="Active CSPM analysis",
                                data_source="Microsoft Defender for Cloud Lateral Movement Analysis",
                                evidence={
                                    "attack_path_name": title,
                                    "source_resource": "Public Endpoint / Perimeter",
                                    "target_resource": target_name,
                                    "affected_resource": target_name,
                                    "risk_level": sev,
                                    "attack_techniques": "Exploit Public-Facing Application (T1190), Lateral Movement (TA0008)",
                                    "recommendation": remediation_desc
                                },
                                collected_at=now_str
                            )
                        )

        if findings:
            status = AssessmentStatus.COMPLETED
        elif errors and any("Permission" in e for e in errors):
            status = AssessmentStatus.PERMISSION_MISSING
        elif errors and not findings:
            status = AssessmentStatus.FAILED
        else:
            status = AssessmentStatus.NO_FINDINGS

        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=max(resources_evaluated, len(context.subscriptions)),
            findings_count=len(findings),
            findings=findings,
            errors=errors,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
