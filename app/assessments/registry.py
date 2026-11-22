from typing import Dict, List, Optional
from app.assessments.base import BaseAssessment
from app.schemas.assessment import AssessmentDefinition

# Security Assessments (14 modules)
from app.assessments.security import (
    SubscriptionSecurityScoreAssessment,
    NewSecurityRecommendationsAssessment,
    ResourcesWithoutLogsAssessment,
    HighPriorityRecommendationsAssessment,
    ServiceRetirementAssessment,
    HighSecurityAlertsAssessment,
    AttackPathsAssessment,
    VmOsVersionAssessment,
    VmPatchingAssessment,
    SoftwareUpgradesAssessment,
    DiskEncryptionAssessment,
    TlsVersionAssessment,
    KeyVaultRbacAssessment,
    ContributorRbacAssessment,
)

# Cost Assessments (19 modules)
from app.assessments.cost import (
    UnderutilizedVmsAssessment,
    OrphanResourcesAssessment,
    UnderutilizedDataDisksAssessment,
    UnderutilizedOsDisksAssessment,
    CostComparisonAssessment,
    Top20OpportunitiesAssessment,
    VmLicenseAhbAssessment,
    AutoShutdownAssessment,
    DiskSpaceAssessment,
    DatabaseUsageAssessment,
    NewUnusedResourcesAssessment,
    StorageLifecycleAssessment,
    DatabaseAllocatedUsageAssessment,
    DatabaseSkuAssessment,
    BackupStatusAssessment,
    OldSnapshotsAssessment,
    FunctionAppsAssessment,
    AutoStartVmAssessment,
    NonLrsStorageRedundancyAssessment,
)

class AssessmentRegistry:
    def __init__(self):
        self._assessments: Dict[str, BaseAssessment] = {}
        self._register_all()

    def _register_all(self):
        # 14 Security
        sec_classes = [
            SubscriptionSecurityScoreAssessment,
            NewSecurityRecommendationsAssessment,
            ResourcesWithoutLogsAssessment,
            HighPriorityRecommendationsAssessment,
            ServiceRetirementAssessment,
            HighSecurityAlertsAssessment,
            AttackPathsAssessment,
            VmOsVersionAssessment,
            VmPatchingAssessment,
            SoftwareUpgradesAssessment,
            DiskEncryptionAssessment,
            TlsVersionAssessment,
            KeyVaultRbacAssessment,
            ContributorRbacAssessment,
        ]
        for cls in sec_classes:
            instance = cls()
            self._assessments[instance.assessment_id] = instance

        # 19 Cost
        cost_classes = [
            UnderutilizedVmsAssessment,
            OrphanResourcesAssessment,
            UnderutilizedDataDisksAssessment,
            UnderutilizedOsDisksAssessment,
            CostComparisonAssessment,
            Top20OpportunitiesAssessment,
            VmLicenseAhbAssessment,
            AutoShutdownAssessment,
            DiskSpaceAssessment,
            DatabaseUsageAssessment,
            NewUnusedResourcesAssessment,
            StorageLifecycleAssessment,
            DatabaseAllocatedUsageAssessment,
            DatabaseSkuAssessment,
            BackupStatusAssessment,
            OldSnapshotsAssessment,
            FunctionAppsAssessment,
            AutoStartVmAssessment,
            NonLrsStorageRedundancyAssessment,
        ]
        for cls in cost_classes:
            instance = cls()
            self._assessments[instance.assessment_id] = instance

    def get_assessment(self, assessment_id: str) -> Optional[BaseAssessment]:
        return self._assessments.get(assessment_id)

    def get_all_assessments(self) -> List[BaseAssessment]:
        return list(self._assessments.values())

    def get_security_assessments(self) -> List[BaseAssessment]:
        return [a for a in self._assessments.values() if a.category == "security"]

    def get_cost_assessments(self) -> List[BaseAssessment]:
        return [a for a in self._assessments.values() if a.category == "cost"]

    def get_all_definitions(self) -> List[AssessmentDefinition]:
        return [a.get_definition() for a in self._assessments.values()]

    def get_security_definitions(self) -> List[AssessmentDefinition]:
        return [a.get_definition() for a in self._assessments.values() if a.category == "security"]

    def get_cost_definitions(self) -> List[AssessmentDefinition]:
        return [a.get_definition() for a in self._assessments.values() if a.category == "cost"]

# Singleton instance
assessment_registry = AssessmentRegistry()
