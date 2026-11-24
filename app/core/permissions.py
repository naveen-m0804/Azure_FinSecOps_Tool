from typing import Dict, List

ASSESSMENT_PERMISSIONS_MATRIX: Dict[str, List[str]] = {
    # Security Assessments
    "subscription_security_score": ["Microsoft.Security/secureScores/read", "Reader"],
    "new_security_recommendations": ["Microsoft.Security/assessments/read", "Security Reader"],
    "resources_without_logs": ["Microsoft.Insights/diagnosticSettings/read", "Monitoring Reader"],
    "high_priority_recommendations": ["Microsoft.Security/assessments/read", "Security Reader"],
    "service_retirement": ["Microsoft.Resources/subscriptions/resources/read", "Reader"],
    "high_security_alerts": ["Microsoft.Security/alerts/read", "Security Reader"],
    "attack_paths": ["Microsoft.Security/attackPaths/read", "Security Reader"],
    "vm_os_version": ["Microsoft.Compute/virtualMachines/read", "Reader"],
    "vm_patching": ["Microsoft.Compute/virtualMachines/assessPatches/action", "Reader"],
    "software_upgrades": ["Microsoft.Compute/virtualMachines/read", "Reader"],
    "disk_encryption": ["Microsoft.Compute/disks/read", "Reader"],
    "tls_version": ["Microsoft.Web/sites/read", "Microsoft.Storage/storageAccounts/read", "Reader"],
    "keyvault_rbac": ["Microsoft.KeyVault/vaults/read", "Reader"],
    "contributor_rbac": ["Microsoft.Authorization/roleAssignments/read", "Reader"],

    # Cost Assessments
    "underutilized_vms": ["Microsoft.Compute/virtualMachines/read", "Microsoft.Insights/metrics/read", "Monitoring Reader"],
    "orphan_resources": ["Microsoft.Compute/disks/read", "Microsoft.Network/publicIPAddresses/read", "Microsoft.Network/networkInterfaces/read", "Microsoft.Web/serverfarms/read", "Reader"],
    "underutilized_data_disks": ["Microsoft.Compute/virtualMachines/read", "Microsoft.Compute/disks/read", "Microsoft.Insights/metrics/read", "Monitoring Reader"],
    "underutilized_os_disks": ["Microsoft.Compute/virtualMachines/read", "Microsoft.Compute/disks/read", "Microsoft.Insights/metrics/read", "Monitoring Reader"],
    "cost_comparison": ["Microsoft.CostManagement/query/action", "Cost Management Reader"],
    "top_optimization": ["Microsoft.CostManagement/query/action", "Cost Management Reader"],
    "vm_license_ahb": ["Microsoft.Compute/virtualMachines/read", "Reader"],
    "auto_shutdown": ["Microsoft.Compute/virtualMachines/read", "Microsoft.DevTestLab/schedules/read", "Reader"],
    "disk_space": ["Microsoft.Compute/virtualMachines/read", "Microsoft.Insights/metrics/read", "Monitoring Reader"],
    "database_usage": ["Microsoft.Sql/servers/databases/read", "Microsoft.Insights/metrics/read", "Monitoring Reader"],
    "new_unused_resources": ["Microsoft.Resources/subscriptions/resources/read", "Microsoft.Insights/metrics/read", "Reader"],
    "storage_lifecycle": ["Microsoft.CostManagement/query/action", "Microsoft.Storage/storageAccounts/managementPolicies/read", "Cost Management Reader", "Reader"],
    "database_allocated_usage": ["Microsoft.Sql/servers/databases/read", "Microsoft.Insights/metrics/read", "Reader"],
    "backup_status": ["Microsoft.RecoveryServices/vaults/read", "Reader"],
    "old_snapshots": ["Microsoft.Compute/snapshots/read", "Microsoft.CostManagement/query/action", "Cost Management Reader", "Reader"],
    "function_apps": ["Microsoft.Web/sites/read", "Microsoft.Insights/metrics/read", "Reader"],
    "auto_start_vm": ["Microsoft.Compute/virtualMachines/read", "Reader"],
}
