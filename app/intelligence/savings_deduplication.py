from typing import List, Dict, Any, Tuple
from app.schemas.finding import FindingModel
from app.utils.resource_ids import normalize_resource_id

class SavingsDeduplicationEngine:
    @staticmethod
    def deduplicate_savings(findings: List[FindingModel]) -> Tuple[List[FindingModel], float, float]:
        """
        Deduplicates savings opportunities for identical underlying resources.
        E.g. If a VM is flagged for both underutilized_vms and auto_shutdown,
        take the maximum single achievable saving rather than double-counting compute.
        Returns (deduped_findings_ranked, unique_total_monthly, unique_total_annual).
        """
        seen_resources: Dict[str, FindingModel] = {}
        non_resource_savings: List[FindingModel] = []
        
        # Reference/evidence-only modules that must NOT be added to total savings (R6, R7, R10)
        _non_additive_assessments = {
            "top_20_opportunities",
            "top_opportunities",
            "disk_space",
            "cost_comparison",
        }

        for f in findings:
            if f.assessment_id in _non_additive_assessments:
                continue
            ann_sav = (f.estimated_annual_savings or 0.0) or ((f.estimated_monthly_savings or 0.0) * 12.0)
            if f.category != "cost" or ann_sav <= 0:
                continue

            res_id = normalize_resource_id(f.resource_id)
            if not res_id:
                non_resource_savings.append(f)
                continue

            if res_id not in seen_resources:
                seen_resources[res_id] = f
            else:
                # Keep the higher annual saving finding as primary for financial deduplication
                existing = seen_resources[res_id]
                ex_ann = (existing.estimated_annual_savings or 0.0) or ((existing.estimated_monthly_savings or 0.0) * 12.0)
                if ann_sav > ex_ann:
                    seen_resources[res_id] = f

        unique_findings = list(seen_resources.values()) + non_resource_savings
        # Sort by annual savings descending
        unique_findings.sort(key=lambda x: ((x.estimated_annual_savings or 0.0) or ((x.estimated_monthly_savings or 0.0) * 12.0)), reverse=True)

        total_annual = sum(((f.estimated_annual_savings or 0.0) or ((f.estimated_monthly_savings or 0.0) * 12.0)) for f in unique_findings)
        total_monthly = sum(((f.estimated_monthly_savings or 0.0) or ((f.estimated_annual_savings or 0.0) / 12.0)) for f in unique_findings)

        return unique_findings, round(total_monthly, 2), round(total_annual, 2)
