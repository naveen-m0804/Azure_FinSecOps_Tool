from typing import List, Dict, Any
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.intelligence.savings_deduplication import SavingsDeduplicationEngine

class AssessmentAggregator:
    @staticmethod
    def aggregate_results(results: Dict[str, AssessmentResult], default_currency: str = "USD") -> Dict[str, Any]:
        all_findings: List[FindingModel] = []
        security_findings: List[FindingModel] = []
        cost_findings: List[FindingModel] = []

        total_modules = len(results)
        completed_modules = 0
        failed_modules = 0

        for aid, res in results.items():
            if res.status == AssessmentStatus.FAILED or getattr(res.status, "value", str(res.status)) == "Failed":
                failed_modules += 1
            else:
                completed_modules += 1

            for f in res.findings:
                all_findings.append(f)
                if f.category == "security":
                    security_findings.append(f)
                else:
                    cost_findings.append(f)

        # Deduplicate cost savings
        unique_cost_findings, unique_monthly_savings, unique_annual_savings = (
            SavingsDeduplicationEngine.deduplicate_savings(cost_findings)
        )

        # Security counts by severity
        sec_severity_counts = {
            "Critical": sum(1 for f in security_findings if f.severity == "Critical"),
            "High": sum(1 for f in security_findings if f.severity == "High"),
            "Medium": sum(1 for f in security_findings if f.severity == "Medium"),
            "Low": sum(1 for f in security_findings if f.severity == "Low"),
            "Informational": sum(1 for f in security_findings if f.severity == "Informational"),
        }

        # Cost savings by confidence
        cost_by_confidence = {
            "High": round(sum((f.estimated_monthly_savings or 0.0) for f in unique_cost_findings if f.confidence == "High"), 2),
            "Medium": round(sum((f.estimated_monthly_savings or 0.0) for f in unique_cost_findings if f.confidence == "Medium"), 2),
            "Low": round(sum((f.estimated_monthly_savings or 0.0) for f in unique_cost_findings if f.confidence == "Low"), 2),
        }

        # Calculate cross-subscription security score if SEC-01 findings exist
        sec01_findings = [
            f for f in security_findings
            if f.assessment_id in ("subscription_security_score", "secure_score", "SEC-01")
        ]
        overall_sec_score = None
        achievable_sec_score = None

        if sec01_findings:
            # Look for overall subscription score findings first (Microsoft Defender Overall Secure Score / ascScore Overall)
            sub_overall_findings = [
                f for f in sec01_findings
                if (f.evidence and (f.evidence.get("security_control") in ["Microsoft Defender Overall Secure Score", "ascScore Overall"] or "ascScore" in str(f.finding_id)))
            ]
            target_findings = sub_overall_findings if sub_overall_findings else sec01_findings

            # Implement exact weighted formula from example_assessment/Cloud_Secure_Score_Overall.txt:
            # scoreRatio = current_score / max_score
            # weightedScore += scoreRatio * weight
            # calculationWeight += weight
            # overallScoreRaw = (weightedScore / calculationWeight) * 100.0
            # overallScore = round(overallScoreRaw, 1)
            total_weighted_ratio = 0.0
            total_weight = 0.0
            raw_percentages = []

            for f in target_findings:
                ev = f.evidence or {}
                cur = ev.get("current_score")
                mx = ev.get("max_score")
                wt = ev.get("weight")

                if cur is not None and mx is not None:
                    try:
                        cur_f = float(cur)
                        mx_f = float(mx)
                        wt_f = float(wt) if (wt is not None and float(wt) > 0) else (mx_f if mx_f > 0 else 1.0)
                        if mx_f > 0:
                            ratio = cur_f / mx_f
                            total_weighted_ratio += ratio * wt_f
                            total_weight += wt_f
                            raw_percentages.append(ratio * 100.0)
                    except (ValueError, TypeError):
                        pass
                else:
                    pct = ev.get("calculated_percentage")
                    if pct is None:
                        pct = ev.get("percentage")
                    if pct is None and f.measured_value:
                        try:
                            pct = float(str(f.measured_value).replace("%", "").strip())
                        except (ValueError, AttributeError):
                            pct = None

                    if pct is not None:
                        try:
                            pct_f = float(pct)
                            wt_f = float(wt) if (wt is not None and float(wt) > 0) else 1.0
                            total_weighted_ratio += (pct_f / 100.0) * wt_f
                            total_weight += wt_f
                            raw_percentages.append(pct_f)
                        except (ValueError, TypeError):
                            pass

            if total_weight > 0:
                overall_sec_score = round((total_weighted_ratio / total_weight) * 100.0)
            elif raw_percentages:
                overall_sec_score = round(sum(raw_percentages) / len(raw_percentages))

        # Calculate cumulative score potential strictly from detected recommendations that contribute to Defender score
        recom_impact_total = 0.0
        seen_controls = set()
        for f in security_findings:
            # Skip the overall subscription secure score itself to avoid self-addition
            ev = f.evidence or {}
            sec_ctrl = ev.get("security_control") or f.resource_name
            if sec_ctrl in ["Microsoft Defender Overall Secure Score", "ascScore Overall"] or "ascScore" in str(f.finding_id):
                continue

            # Deduplicate control contributions
            if sec_ctrl and sec_ctrl in seen_controls:
                continue
            if sec_ctrl:
                seen_controls.add(sec_ctrl)

            imp = getattr(f, "security_score_impact", None)
            if imp is not None:
                try:
                    imp_f = float(imp)
                    if imp_f > 0:
                        recom_impact_total += imp_f
                except (ValueError, TypeError):
                    pass

        if overall_sec_score is not None:
            overall_sec_score = round(float(overall_sec_score))
            # Achievable score is strictly current score + genuine potential from contributing recommendations
            if recom_impact_total > 0:
                achievable_sec_score = min(100, round(overall_sec_score + recom_impact_total))
            else:
                achievable_sec_score = overall_sec_score

        current_cost_wastage = round(sum(float(f.current_monthly_cost or f.estimated_monthly_savings or 0.0) for f in unique_cost_findings), 2)
        if current_cost_wastage == 0.0 and unique_monthly_savings > 0.0:
            current_cost_wastage = unique_monthly_savings

        high_conf = round(sum((f.estimated_monthly_savings or 0.0) for f in unique_cost_findings if f.confidence == "High"), 2)
        med_conf = round(sum((f.estimated_monthly_savings or 0.0) for f in unique_cost_findings if f.confidence == "Medium"), 2)
        low_conf = round(sum((f.estimated_monthly_savings or 0.0) for f in unique_cost_findings if f.confidence == "Low"), 2)

        # Dynamic currency based on tenant findings and results
        non_usd_findings = [f.currency for f in cost_findings if getattr(f, "currency", None) and f.currency != "USD"]
        non_usd_results = [r.currency for r in results.values() if getattr(r, "currency", None) and r.currency != "USD"]
        all_curr_findings = [f.currency for f in cost_findings if getattr(f, "currency", None)]
        all_curr_results = [r.currency for r in results.values() if getattr(r, "currency", None)]

        if non_usd_findings:
            active_currency = non_usd_findings[0]
        elif non_usd_results:
            active_currency = non_usd_results[0]
        elif default_currency and default_currency != "USD":
            active_currency = default_currency
        elif all_curr_findings:
            active_currency = all_curr_findings[0]
        elif all_curr_results:
            active_currency = all_curr_results[0]
        else:
            active_currency = default_currency or "USD"

        return {
            "total_modules": total_modules,
            "completed_modules": completed_modules,
            "failed_modules": failed_modules,
            "total_findings": len(all_findings),
            "security_findings_count": len(security_findings),
            "cost_findings_count": len(cost_findings),
            "security_severity_counts": sec_severity_counts,
            "findings_by_severity": {k.lower(): v for k, v in sec_severity_counts.items()},
            "high_severity_findings": sec_severity_counts.get("High", 0),
            "medium_severity_findings": sec_severity_counts.get("Medium", 0),
            "low_severity_findings": sec_severity_counts.get("Low", 0),
            "security_score": overall_sec_score,
            "current_security_score": overall_sec_score,
            "overall_security_score": overall_sec_score,
            "achievable_security_score": achievable_sec_score,
            "current_cost_wastage": current_cost_wastage,
            "unique_monthly_savings": unique_monthly_savings,
            "unique_annual_savings": unique_annual_savings,
            "total_monthly_savings": unique_monthly_savings,
            "total_annual_savings": unique_annual_savings,
            "high_confidence_monthly_savings": high_conf,
            "scenario_monthly_savings": med_conf + low_conf,
            "cost_by_confidence": cost_by_confidence,
            "currency": active_currency
        }
