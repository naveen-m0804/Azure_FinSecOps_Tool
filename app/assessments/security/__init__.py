from .secure_score import SubscriptionSecurityScoreAssessment
from .new_recommendations import NewSecurityRecommendationsAssessment
from .resources_without_logs import ResourcesWithoutLogsAssessment
from .high_priority_recommendations import HighPriorityRecommendationsAssessment
from .service_retirement import ServiceRetirementAssessment
from .security_alerts import HighSecurityAlertsAssessment
from .attack_paths import AttackPathsAssessment
from .vm_os_version import VmOsVersionAssessment
from .vm_patching import VmPatchingAssessment
from .software_upgrades import SoftwareUpgradesAssessment
from .disk_encryption import DiskEncryptionAssessment
from .tls_version import TlsVersionAssessment
from .keyvault_rbac import KeyVaultRbacAssessment
from .contributor_rbac import ContributorRbacAssessment

__all__ = [
    "SubscriptionSecurityScoreAssessment",
    "NewSecurityRecommendationsAssessment",
    "ResourcesWithoutLogsAssessment",
    "HighPriorityRecommendationsAssessment",
    "ServiceRetirementAssessment",
    "HighSecurityAlertsAssessment",
    "AttackPathsAssessment",
    "VmOsVersionAssessment",
    "VmPatchingAssessment",
    "SoftwareUpgradesAssessment",
    "DiskEncryptionAssessment",
    "TlsVersionAssessment",
    "KeyVaultRbacAssessment",
    "ContributorRbacAssessment",
]
