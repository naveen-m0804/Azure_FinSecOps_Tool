from .underutilized_vms import UnderutilizedVmsAssessment
from .orphan_resources import OrphanResourcesAssessment
from .underutilized_data_disks import UnderutilizedDataDisksAssessment
from .underutilized_os_disks import UnderutilizedOsDisksAssessment
from .cost_comparison import CostComparisonAssessment
from .top_20_opportunities import Top20OpportunitiesAssessment
from .vm_license_ahb import VmLicenseAhbAssessment
from .auto_shutdown import AutoShutdownAssessment
from .disk_space import DiskSpaceAssessment
from .database_usage import DatabaseUsageAssessment
from .new_unused_resources import NewUnusedResourcesAssessment
from .storage_lifecycle import StorageLifecycleAssessment
from .database_allocated_usage import DatabaseAllocatedUsageAssessment
from .backup_status import BackupStatusAssessment
from .old_snapshots import OldSnapshotsAssessment
from .function_apps import FunctionAppsAssessment
from .auto_start_vm import AutoStartVmAssessment
from .non_lrs_storage_redundancy import NonLrsStorageRedundancyAssessment

__all__ = [
    "UnderutilizedVmsAssessment",
    "OrphanResourcesAssessment",
    "UnderutilizedDataDisksAssessment",
    "UnderutilizedOsDisksAssessment",
    "CostComparisonAssessment",
    "Top20OpportunitiesAssessment",
    "VmLicenseAhbAssessment",
    "AutoShutdownAssessment",
    "DiskSpaceAssessment",
    "DatabaseUsageAssessment",
    "NewUnusedResourcesAssessment",
    "StorageLifecycleAssessment",
    "DatabaseAllocatedUsageAssessment",
    "BackupStatusAssessment",
    "OldSnapshotsAssessment",
    "FunctionAppsAssessment",
    "AutoStartVmAssessment",
    "NonLrsStorageRedundancyAssessment",
]
