import datetime
import time
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.defender import DefenderAdapter

class SubscriptionSecurityScoreAssessment(BaseAssessment):
    assessment_id = "subscription_security_score"
    code = "SEC-01"
    category = "security"
    name = "Subscription Security Score"
    description = "Obtain official Defender for Cloud Secure Score and security control breakdown across enabled subscriptions."
    purpose = "Establish baseline security posture and track official Microsoft Secure Score compliance."
    required_permissions = ["Microsoft.Security/secureScores/read", "Microsoft.Security/secureScores/secureScoreControls/read", "Reader"]
    required_data_sources = ["Defender for Cloud Secure Score & Secure Score Controls API (2020-01-01)"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        controls_evaluated = 0

        for sub in context.subscriptions:
            # 1. Authoritative Subscription-Level Secure Score (matches Cloud_Secure_Score_Overall.txt)
            sub_score = await DefenderAdapter.get_secure_score(context.client, sub.subscription_id)
            controls_evaluated += 1

            if sub_score.get("success"):
                cur = float(sub_score["current_score"])
                mx = float(sub_score["max_score"])
                pct = float(sub_score["percentage"])
                weight = float(sub_score.get("weight", mx if mx > 0 else 1.0))

                # Fetch individual security controls from Defender secureScoreControls API
                controls_list = []
                try:
                    ctrl_resp = await DefenderAdapter.get_secure_score_controls(context.client, sub.subscription_id)
                    if ctrl_resp.get("success"):
                        controls_list = ctrl_resp.get("value", [])
                except Exception as ex:
                    errors.append(f"Failed to fetch secure score controls for {sub.display_name}: {ex}")

                # Evaluate controls and calculate exact score contribution
                control_findings = []
                total_contributing_points = 0.0
                total_unhealthy_contributing_resources = 0

                for c in controls_list:
                    controls_evaluated += 1
                    props = c.get("properties", {})
                    control_name = props.get("displayName") or c.get("name", "Unknown Control")
                    score_info = props.get("score", {})
                    c_current = float(score_info.get("current", 0.0))
                    c_maximum = float(score_info.get("max", 0.0))
                    c_pct = round((c_current / c_maximum * 100.0), 1) if c_maximum > 0 else 0.0
                    unhealthy_count = int(props.get("unhealthyResourceCount", 0))
                    healthy_count = int(props.get("healthyResourceCount", 0))

                    # Points that can be gained by remediating unhealthy resources under this control
                    points_to_gain = max(0.0, c_maximum - c_current)

                    # Mathematical impact on the subscription's overall secure score:
                    # Gaining `points_to_gain` out of `mx` total subscription points increases the subscription score by:
                    # (points_to_gain / mx) * 100%
                    if mx > 0 and c_maximum > 0:
                        score_impact_pct = round((points_to_gain / mx * 100.0), 1)
                    else:
                        score_impact_pct = 0.0

                    if unhealthy_count > 0 or points_to_gain > 0:
                        if score_impact_pct > 0:
                            total_contributing_points += points_to_gain
                            total_unhealthy_contributing_resources += unhealthy_count
                            rec_text = (
                                f"Remediate {unhealthy_count} unhealthy resource(s) under security control '{control_name}' "
                                f"in Microsoft Defender for Cloud to gain up to +{points_to_gain:.1f} point(s) (+{score_impact_pct:.1f}% score increase)."
                            )
                            recommended_cfg = f"Remediate {unhealthy_count} resource(s) to earn +{points_to_gain:.1f} pts (+{score_impact_pct:.1f}%)"
                        else:
                            rec_text = (
                                f"Security control '{control_name}' has {unhealthy_count} unhealthy resource(s). "
                                "This is an informational baseline recommendation that does not award points toward the numeric Secure Score in Defender."
                            )
                            recommended_cfg = f"Remediate {unhealthy_count} resource(s) (Informational baseline)"

                        severity = "High" if c_pct < 50.0 else ("Medium" if c_pct < 80.0 else "Low")
                        f_id = f"sec01-{sub.subscription_id[:8]}-{c.get('name', '')[:12]}"

                        control_findings.append(
                            FindingModel(
                                finding_id=f_id,
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group="Microsoft.Security",
                                resource_name=control_name,
                                resource_type="Microsoft.Security/secureScores/secureScoreControls",
                                resource_id=c.get("id", f"/subscriptions/{sub.subscription_id}/providers/Microsoft.Security/secureScores/ascScore/secureScoreControls/{c.get('name')}"),
                                region="global",
                                severity=severity,
                                status="Unhealthy" if unhealthy_count > 0 else "Needs Improvement",
                                current_configuration=f"Control Score: {c_current:.1f}/{c_maximum:.1f} pts ({c_pct}%) | Unhealthy Resources: {unhealthy_count}",
                                measured_value=f"{c_pct}%",
                                recommended_configuration=recommended_cfg,
                                recommendation=rec_text,
                                metric_period="Current snapshot",
                                data_source="Defender for Cloud Secure Score Controls API (2020-01-01)",
                                evidence={
                                    "security_control": control_name,
                                    "current_score": c_current,
                                    "max_score": c_maximum,
                                    "percentage": c_pct,
                                    "points_to_gain": points_to_gain,
                                    "subscription_max_score": mx,
                                    "potential_increase": score_impact_pct,
                                    "security_score_impact": score_impact_pct,
                                    "unhealthy_resources_count": unhealthy_count,
                                    "healthy_resources_count": healthy_count,
                                },
                                security_score_impact=score_impact_pct,
                                security_score_basis="Microsoft Defender ascScore Control Points Contribution",
                                collected_at=now_str
                            )
                        )

                # Total potential score increase strictly from genuine contributing controls
                if mx > 0 and total_contributing_points > 0:
                    total_potential_inc = round((total_contributing_points / mx * 100.0), 1)
                else:
                    total_potential_inc = 0.0

                achievable_pct = min(100.0, round(pct + total_potential_inc, 1))

                # Record the subscription-level secure score finding
                findings.append(
                    FindingModel(
                        finding_id=f"sec01-{sub.subscription_id[:8]}-ascScore",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group="Microsoft.Security",
                        resource_name="Microsoft Defender Overall Secure Score",
                        resource_type="Microsoft.Security/secureScores",
                        resource_id=f"/subscriptions/{sub.subscription_id}/providers/Microsoft.Security/secureScores/ascScore",
                        region="global",
                        severity="High" if pct < 50.0 else ("Medium" if pct < 80.0 else "Low"),
                        status="Compliant" if total_potential_inc == 0.0 else "Needs Improvement",
                        current_configuration=f"Current Score: {cur:.1f}/{mx:.1f} pts ({pct}%)",
                        measured_value=f"{pct}%",
                        recommended_configuration=f"Achieve {achievable_pct:.0f}% by remediating active Defender recommendations",
                        recommendation=(
                            f"Subscription secure score is {pct}%. Remediate active recommendations in Microsoft Defender for Cloud "
                            f"to gain up to +{total_contributing_points:.1f} points, raising your score to {achievable_pct:.1f}% (+{total_potential_inc:.1f}% potential increase)."
                            if total_potential_inc > 0 else
                            f"Subscription secure score is {pct}%. All security controls with score impact are currently healthy."
                        ),
                        metric_period="Current snapshot",
                        data_source="Defender for Cloud ascScore API (2020-01-01)",
                        evidence={
                            "security_control": "Microsoft Defender Overall Secure Score",
                            "current_score": cur,
                            "max_score": mx,
                            "percentage": pct,
                            "calculated_percentage": pct,
                            "weight": weight,
                            "potential_points_available": total_contributing_points,
                            "potential_increase": total_potential_inc,
                            "achievable_score": achievable_pct,
                            "unhealthy_resources_count": total_unhealthy_contributing_resources,
                            "healthy_resources_count": 1 if total_potential_inc == 0 else 0,
                        },
                        security_score_impact=total_potential_inc,
                        security_score_basis="Microsoft Defender for Cloud Secure Score",
                        collected_at=now_str
                    )
                )

                # Add all evaluated control findings
                findings.extend(control_findings)
            else:
                err_msg = sub_score.get("error", "Unknown error")
                status_code = sub_score.get("status_code", 500)
                if status_code in (401, 403):
                    errors.append(f"Subscription '{sub.display_name}': Permission Missing (Microsoft.Security/secureScores/read required)")
                elif status_code == 404:
                    errors.append(f"Subscription '{sub.display_name}': Microsoft Defender for Cloud is not enabled")
                else:
                    errors.append(f"Subscription '{sub.display_name}': {err_msg}")

        # Determine accurate status
        if errors and not findings:
            if any("Permission" in e for e in errors):
                status = AssessmentStatus.PERMISSION_MISSING
            elif any("not enabled" in e for e in errors):
                status = AssessmentStatus.NOT_SUPPORTED
            else:
                status = AssessmentStatus.FAILED
        elif errors and findings:
            status = AssessmentStatus.COMPLETED_WITH_WARNINGS
        elif findings:
            status = AssessmentStatus.COMPLETED
        else:
            status = AssessmentStatus.NO_FINDINGS

        max_pot = max((float(f.security_score_impact) for f in findings if f.security_score_impact is not None), default=None)

        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=max(controls_evaluated, len(context.subscriptions)),
            findings_count=len(findings),
            findings=findings,
            errors=errors,
            security_score_improvement=max_pot,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
