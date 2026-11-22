from typing import List, Dict, Any, Optional

class SecurityScoringEngine:
    @staticmethod
    def calculate_weighted_overall_score(sub_scores: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Preserves the source script calculation from Cloud_Secure_Score_Overall.txt:
        SubscriptionPercentage = (CurrentScore / MaxScore) * 100
        WeightedOverall = SUM((CurrentScore / MaxScore) * SubscriptionWeight) / SUM(SubscriptionWeight) * 100
        """
        total_weighted_ratio = 0.0
        total_weight = 0.0
        successful_subs = 0
        failed_subs = 0

        for s in sub_scores:
            if s.get("success", False) and s.get("max_score", 0) > 0:
                current = float(s.get("current_score", 0.0))
                maximum = float(s.get("max_score", 0.0))
                weight = float(s.get("weight", 1.0))
                
                ratio = current / maximum
                total_weighted_ratio += (ratio * weight)
                total_weight += weight
                successful_subs += 1
            else:
                failed_subs += 1

        weighted_overall = (total_weighted_ratio / total_weight * 100.0) if total_weight > 0 else 0.0

        return {
            "overall_calculated_score": round(weighted_overall, 2),
            "total_subscriptions_evaluated": len(sub_scores),
            "successful_subscriptions": successful_subs,
            "failed_subscriptions": failed_subs,
            "total_weight": round(total_weight, 2),
            "methodology": "Source script weighted model: SUM((Current/Max)*Weight) / SUM(Weight) * 100"
        }
