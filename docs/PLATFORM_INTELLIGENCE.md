# Azure FinSecOps Platform - Assessment Intelligence & Evaluation Methodology Guide

> **Document Version:** 3.0.0  
> **Target Audience:** Chief Information Security Officers (CISOs), FinOps Practitioners, Cloud Architects, and Enterprise Leadership  
> **Author:** Principal Cloud Architect & Senior Project Delivery Manager  
> **Scope:** Complete Technical Reference for all 32 Core Assessment Modules (14 Security + 18 Cost)  

---

## 1. Executive Summary & Core Intelligence Architecture

The **Azure FinSecOps Platform** continuously evaluates Azure cloud estates to answer two fundamental executive questions:
1. **"What is our true cloud risk posture, and how can we systematically increase our security score?"**
2. **"Where is financial capital leaking, and what are our defensible, non-disruptive cloud savings?"**

Rather than relying on basic alert dumps or arbitrary static rules, the platform applies **deterministic telemetry correlation**. It connects Azure Resource Graph (ARG), Azure Monitor Metric baselines, Microsoft Defender for Cloud Secure Score APIs, and Azure Cost Management billing pipelines into a unified mathematical evaluation framework.

```mermaid
flowchart LR
    subgraph DataIngestion["Telemetry Ingestion"]
        ARG["Azure Resource Graph\n(Live Resource Metadata)"]
        CostAPI["Cost Management API\n(Actual Pre-Tax Spend)"]
        Metrics["Azure Monitor Metrics\n(CPU, IOPS, Memory, Storage)"]
        Defender["Defender for Cloud\n(Controls, Alerts, Attack Paths)"]
    end

    subgraph IntelligenceEngine["Core Platform Intelligence"]
        ProdFilter["Case-Insensitive Production Detection\n(is_production_resource)"]
        Deduplicator["Cross-Module Deduplication Engine\n(Confidence Weighting)"]
        SecCalc["Secure Score Engine\n(Defender ascScore & Control Breakdown)"]
        CostCalc["Defensible Savings Modeling\n(Strict Prohibition of MTD × 12)"]
    end

    subgraph BusinessOutput["Executive Deliverables"]
        SecKPI["Microsoft Defender Overall Secure Score"]
        CostKPI["Wastage, Monthly Savings & Annual Savings"]
        Reports["Landscape PDF & Multi-Tab Excel Deliverables"]
    end

    DataIngestion --> IntelligenceEngine
    IntelligenceEngine --> BusinessOutput
```

---

## 2. Core Mathematical & Deduplication Principles

### 2.1 The Secure Score Evaluation Model
The platform models security posture directly against Microsoft Defender for Cloud Secure Score standards:
* **Current Security Score ($S_{\text{current}}$):** Weighted aggregate of passed security controls divided by total healthy + unhealthy control weights across active subscriptions fetched live via `Microsoft.Security/secureScores/ascScore`:
  $$S_{\text{current}} = \left( \frac{\sum \text{Healthy Control Scores}}{\sum \text{Total Control Weights}} \right) \times 100$$
* **Control Security Breakdown:** Each identified control exposes the exact percentage and potential score gain achievable by remediating that specific risk:
  $$\Delta S_i = \left( \frac{\text{Weight of Control } i}{\sum \text{Total Control Weights}} \right) \times 100$$
* **Isolated Overall Secure Score Presentation:** The overall secure score is presented in a dedicated executive scorecard and standalone table row, cleanly decoupled from granular sub-control lists.

### 2.2 Defensible Cost Modeling vs. Naive "MTD $\times$ 12" Calculations
A common failure of automated FinOps scripts is simply taking a resource's Month-to-Date (MTD) cost and multiplying it by 12. This creates inflated, indefensible estimates that fail financial audit. 

The platform enforces **strict defensible savings modeling**:
1. **Right-Sizing Delta Modeling (`COST-01`, `COST-10`):** When a virtual machine or database is underutilized, savings are modeled as the delta between the *Current SKU Rate* and the *Recommended Target SKU Rate* based on performance baselines.
2. **Deallocation & Idle Off-Hours Modeling (`COST-08`, `COST-17`):** For non-production workloads running 24/7 without shutdown policies, savings represent the 128 off-peak weekly hours (evenings and weekends) where compute charges are eliminated:
   $$\text{Monthly Savings} = \text{Hourly VM Rate} \times 128\ \text{hours} \times 4.33\ \text{weeks}$$
3. **Storage Tiering & Redundancy Delta (`COST-12`, `COST-18`):** Savings represent the difference between premium/redundant storage (e.g., GRS at \$0.045/GB) and standard local storage (LRS at \$0.019/GB).
4. **Standard Display Format:** All cost savings are displayed as:
   $$\mathbf{\$X,XXX.XX\ \ (\$YY.YY/\text{month})}$$

### 2.3 Production vs. Non-Production Resolution Engine
To protect mission-critical environments, cost assessments that apply aggressive shutdowns or redundancy downgrades strictly exclude production workloads. The platform incorporates a comprehensive case-insensitive detection engine (`is_production_resource`):
* Detects production across resource names, resource group names, and resource tags.
* Identifies all case variants: `PROD`, `prod`, `Production`, `PRODUCTION`, `Prd`, `live`, `prd-01`, `rg-prod-east`.
* Differentiates delimited formats: `env:production`, `environment=prod`, `app-production-db`.
* Strictly limits auto-shutdown and non-LRS storage recommendations to validated non-production and testing environments (`Dev`, `QA`, `Test`, `Stage`, `Sandbox`).

### 2.4 Multi-Currency Dynamic Ingestion
The platform queries the active currency code directly from the Azure Cost Management query response (e.g., `USD`, `EUR`, `GBP`, `INR`, `AUD`, `CAD`, `JPY`). All KPI cards, module metrics, PDF tables, and Excel sheets dynamically render the corresponding currency symbol without hardcoding `$`.

---

## 3. Pillar 1: Security Governance & Compliance (14 Modules)

```
SEC-01: Subscription Security Score          SEC-08: VM Operating System Version
SEC-02: New Security Recommendations         SEC-09: VM Patching & Missing Updates
SEC-03: Production Resources Missing Logs    SEC-10: Software Version Upgrades
SEC-04: High Priority Recommendations        SEC-11: Managed Disk Encryption
SEC-05: Service Retirement                   SEC-12: Transport Layer Security (TLS)
SEC-06: High Security Alerts                 SEC-13: Key Vault RBAC Migration
SEC-07: Critical Attack Paths                SEC-14: Contributor RBAC Review
```

### [SEC-01] Subscription Security Score
* **Core Intelligence:** Ingests Defender for Cloud Secure Score controls across all accessible subscriptions via `Microsoft.Security/secureScores/ascScore` and `Microsoft.Security/secureScores/ascScore/secureScoreControls`.
* **Isolated Score Presentation:** Displays the **"Microsoft Defender Overall Secure Score"** in a dedicated executive card and standalone table record, cleanly separated from individual controls.
* **Calculation:** Identifies individual controls (e.g., *Restrict unauthorized network access*, *Remediate security configurations*, *Manage access and permissions*) and computes exact control scores, current percentages, and potential gain per subscription.
* **Example Finding:**
  - *Resource:* `Subscription: Enterprise-Production-Global`
  - *Overall Score:* `64.2% (38.5 / 60.0 Max)`
  - *Control:* `Restrict unauthorized network access` | *Current Score:* `75.0%` | *Potential Gain:* `+2.1%`
  - *Remediation:* Address top failing sub-assessments across NSGs and endpoints.

### [SEC-02] New Security Recommendations
* **Core Intelligence:** Queries `Microsoft.Security/assessments` for new recommendations detected within the **last 30 days** that remain unresolved (`Unhealthy` or `Open`).
* **Calculation:** Evaluates `status.firstEvaluationDate`, cleanly parsing ISO 8601 timestamps into dynamic `YYYY-MM-DD` First Detected Dates.
* **Example Finding:**
  - *Resource:* `storage-app-eastus-01` (`Microsoft.Storage/storageAccounts`)
  - *Recommendation:* `Public network access on storage accounts should be disabled`
  - *First Detected Date:* `2026-11-04` | *Status:* `Unhealthy (Active)`
  - *Severity:* `High` | *Score Impact:* `+2.4%`

### [SEC-03] Production Resources Missing Diagnostic Logs
* **Core Intelligence:** Interrogates Azure Monitor Diagnostic Settings (`Microsoft.Insights/diagnosticSettings`) across critical cloud workloads.
* **Comprehensive Resource Audit Scope:**
  - **Logic Apps:** Diagnostic logs in Logic Apps (`microsoft.logic/workflows`) should be enabled.
  - **Key Vault:** Diagnostic logs in Key Vault (`microsoft.keyvault/vaults`) should be enabled.
  - **App Service:** Diagnostic logs in App Service (`microsoft.web/sites`) should be enabled.
  - **Microsoft Foundry:** Diagnostic logs in Foundry resources (`cognitiveservices`, `machinelearningservices`, `aistudio`) should be enabled.
  - **Kubernetes:** Diagnostic logs in Kubernetes services (`managedclusters`) should be enabled.
* **Calculation:** Identifies active resources where diagnostic settings are absent, log categories are disabled, or no Log Analytics Workspace target is configured.
* **Example Finding:**
  - *Resource:* `kv-corp-production-01` (`Microsoft.KeyVault/vaults`)
  - *Status:* `Diagnostic logs in Key Vault should be enabled`
  - *Remediation:* Forward `AuditEvent` logs to centralized Log Analytics Workspace.

### [SEC-04] High Priority Security Recommendations
* **Core Intelligence:** Leverages KQL queries via Azure Resource Graph (`securityresources`) with resilient fallback to `Microsoft.Security/assessments`, strictly filtered to **High** severity matching the Azure Portal Microsoft Defender for Cloud Recommendations blade.
* **Dynamic Target Resolution:** Strips `/providers/Microsoft.Security/assessments/.*` tails to accurately resolve the true target resource, real resource group, and actual resource name (avoiding erroneous subscription-scope fallbacks).
* **Metadata Cache Enrichment:** Dynamically populates **Description**, **Azure Remediation**, **Recommendation**, and **Related Security Control** using live Azure assessment metadata without static or hardcoded placeholders.
* **Example Finding:**
  - *Resource:* `vm-web-frontend-01` (`Microsoft.Compute/virtualMachines`)
  - *Recommendation:* `Management ports should be closed (RDP 3389 / SSH 22 exposed to 0.0.0.0/0)`
  - *Severity:* `High` | *Security Control:* `Restrict unauthorized network access`
  - *Remediation:* Restrict inbound traffic using Network Security Groups or Azure Bastion.

### [SEC-05] Azure Service Retirement & Runtime Deprecation
* **Core Intelligence:** Queries official Azure Advisor Service Upgrade & Retirement advisories and live Azure Service Health events (`Microsoft.ResourceHealth/events`), eliminating synthetic scans over standard infrastructure.
* **Protocol & Stack Deprecation:** Continuously monitors retirement notices, including deprecated TLS / TLC security protocols and officially retired legacy platform architectures.
* **Example Finding:**
  - *Resource:* `pg-legacy-prod` (`Microsoft.DBforPostgreSQL/servers`)
  - *Retirement Notice:* `Azure Database for PostgreSQL - Single Server retired`
  - *Status:* `Service Retired`
  - *Remediation:* Migrate to Azure Database for PostgreSQL Flexible Server.

### [SEC-06] High Security Alerts
* **Core Intelligence:** Queries `Microsoft.Security/alerts` for unresolved alerts with severity `High` or `Critical`.
* **Calculation:** Extracts attacker MITRE ATT&CK tactics, techniques, compromised entities, and remediation instructions.
* **Example Finding:**
  - *Resource:* `vm-db-connector-01`
  - *Alert Name:* `Suspicious process execution detected via PowerShell`
  - *Attack Tactics:* `MITRE ATT&CK T1059.001 (Command and Scripting Interpreter)`
  - *Status:* `Active (Unresolved)`

### [SEC-07] Critical Cloud Attack Paths
* **Core Intelligence:** Evaluates Defender for Cloud Cloud Security Graph Attack Path engine (`Microsoft.Security/attackPaths`) via Azure Resource Graph.
* **Calculation:** Analyzes multi-hop vulnerability chains connecting internet entry points to high-value assets and presents break-the-chain remediation.
* **Example Finding:**
  - *Resource:* `vm-dmz-proxy` $\rightarrow$ `kv-prod-secrets` $\rightarrow$ `sqldb-orders`
  - *Attack Path:* `Internet-exposed VM with high-severity vulnerability has managed identity with Key Vault Reader permissions`
  - *Risk Level:* `Critical` | *Remediation:* Remove unneeded role assignment from VM Managed Identity.

### [SEC-08] Virtual Machine Operating System Version
* **Core Intelligence:** Queries compute instance OS profile (`osProfile`) and guest extensions (`instanceView`) to evaluate operating system versions against a modern **2025 baseline**.
* **Modern 2025 Baseline Evaluation:** Any Windows Server release prior to 2025 (2022, 2019, 2016, 2012, 2008) or Linux distribution releases prior to 2025 (Ubuntu <= 24.04 LTS, CentOS, RHEL <= 9) are flagged.
* **Streamlined Columns:** Populates the 8 clean columns: **Subscription Name**, **Resource Group Name**, **Virtual Machine Name**, **Region**, **Operating System**, **OS Version**, **OS Build** (dynamically resolved from instanceView and SKU mappings), and **Publisher** (omits redundant Image Version "latest" and support date columns).
* **Example Finding:**
  - *Virtual Machine:* `vm-legacy-app-02`
  - *Operating System:* `Windows Server 2022 Datacenter` | *OS Version:* `21H2` | *OS Build:* `20348`
  - *Publisher:* `MicrosoftWindowsServer`

### [SEC-09] VM Patching & Missing Security Updates
* **Core Intelligence:** Interfaces with Azure Update Manager (`Microsoft.Compute/virtualMachines/patchAssessmentResults/latest`) to retrieve pending security and critical patch counts.
* **Calculation:** Identifies VMs with missing security updates $> 5$ or critical patches $> 0$.
* **Example Finding:**
  - *Resource:* `vm-batch-worker-01`
  - *Missing Security Updates:* `14` | *Missing Critical Updates:* `6`
  - *Reboot Required:* `Yes` | *Status:* `Non-Compliant`

### [SEC-10] Outdated Software Versions on Azure Virtual Machines
* **Core Intelligence:** Queries Defender Vulnerability Management subassessments on virtual machines.
* **"Update" Keyword Filtering:** Filters strictly to items whose recommendation or package name starts with `"Update"` to focus exclusively on actionable software package upgrades.
* **Example Finding:**
  - *Resource:* `vm-web-cluster-03`
  - *Recommendation:* `Update OpenSSL on Linux virtual machines`
  - *Affected Software:* `OpenSSL 1.1.1t` $\rightarrow$ `Update to 3.0.12+`
  - *Severity:* `High`

### [SEC-11] Managed Disk Encryption Configuration Gaps
* **Core Intelligence:** Inspects disk properties for `encryption.type` and Customer-Managed Keys (CMK) / Azure Disk Encryption (ADE).
* **Dynamic Host Encryption Check:** Interrogates attached virtual machines dynamically to resolve live `securityProfile.encryptionAtHost` status rather than assuming disabled.
* **Example Finding:**
  - *Resource:* `disk-prod-database-data` (`Microsoft.Compute/disks`)
  - *Encryption Type:* `PMK (Platform-Managed Key Only)`
  - *Encryption at Host Status:* `Disabled`
  - *Remediation:* Enable host-based encryption or attach Disk Encryption Set backed by Azure Key Vault HSM.

### [SEC-12] Azure Services Using Insecure TLS Configurations
* **Core Intelligence:** Audits App Services, Storage Accounts, SQL Servers, and Cosmos DB for minimum allowed TLS protocol versions.
* **Calculation:** Identifies resources configured with `minimumTlsVersion` below `TLS1_2`.
* **Example Finding:**
  - *Resource:* `saecommerceassets` (`Microsoft.Storage/storageAccounts`)
  - *Configured TLS:* `TLS 1.0` | *Required Standard:* `TLS 1.2+`
  - *Remediation:* Enforce `minimumTlsVersion = 'TLS1_2'` via ARM configuration.

### [SEC-13] Azure Key Vaults Using Access Policy Authorization
* **Core Intelligence:** Evaluates Key Vault authorization models (`enableRbacAuthorization`).
* **Live IAM Verification:** Dynamically queries Azure IAM (`Microsoft.Authorization/roleAssignments`) at the vault scope to report real role assignment counts and assigned role names, recommending migration from legacy access policies.
* **Example Finding:**
  - *Resource:* `kv-corporate-keys-01`
  - *Authorization Model:* `Vault Access Policy (Legacy)`
  - *IAM Role Assignments:* `3 active assignments`
  - *Remediation:* Transition vault authorization to Azure Role-Based Access Control (`Key Vault Secrets User`, `Key Vault Crypto Officer`).

### [SEC-14] Azure Contributor Role Assignments Requiring Review
* **Core Intelligence:** Analyzes role assignments (`Microsoft.Authorization/roleAssignments`) at subscription and resource group scopes.
* **Strict Contributor Scope:** Filters strictly to **Contributor assignments only** (excluding Owner and custom roles) to enforce least-privilege principles and flag direct human user assignments.
* **Example Finding:**
  - *Resource:* `Assignment: user-contractor@corp.com`
  - *Role Assigned:* `Contributor (Subscription Scope)`
  - *Remediation:* Revoke permanent subscription Contributor assignment; replace with Resource-Group-scoped custom role or Azure PIM eligible role assignment.

---

## 4. Pillar 2: Financial Optimization & Savings (18 Modules)

```
COST-01: Underutilized Virtual Machines         COST-10: Database Performance Thresholds
COST-02: Orphan & Unattached Cloud Resources   COST-11: New & Unused Resources
COST-03: Underutilized Managed Data Disks      COST-12: Storage Account Lifecycle Policy
COST-04: Underutilized OS Disks                COST-13: Database Storage vs Allocation
COST-05: Monthly Billing Cost Comparison       COST-14: Backup Policy & Retention Alignment
COST-06: Top 20 Optimization Opportunities     COST-15: Stale Disk Snapshots
COST-07: VM Licensing & Hybrid Benefit (AHB)   COST-16: Function App Hosting Plans
COST-08: VM Auto-Shutdown Enforcement          COST-17: VM Auto-Start Off-Hours Impact
COST-09: Managed Disk Capacity Alerts          COST-18: Non-LRS Storage Redundancy Optimization
```

### [COST-01] Underutilized Virtual Machines
* **Data Sources:** Azure Monitor Metric Ingestion (`Percentage CPU`, `Available Memory Bytes`) aggregated over 30-day timeframes combined with Azure Cost Management actual spend.
* **Detection Criteria:** VMs running with average CPU utilization $< 5.0\%$ and memory utilization $< 30\%$ over the measurement window.
* **Formula:**
  $$\text{Monthly Savings} = \text{Current MTD Cost} - \text{Right-Sized SKU Cost}$$
  $$\text{Annual Savings} = \text{Monthly Savings} \times 12$$
* **Example Finding:**
  - *VM Name:* `vm-batch-worker-02` (`Standard_D4s_v5` at \$140.16/mo)
  - *Telemetry:* `0.32% Average CPU over 90 days`, `22.4% Memory`
  - *Recommendation:* Downsize to `Standard_D2s_v5` (\$30.37/mo)
  - *Savings:* **\$1,317.48 ($109.79/month)**

### [COST-02] Orphan & Unattached Cloud Resources
* **Data Sources:** Azure Resource Graph query detecting disks, public IPs, network interfaces, and load balancers unattached to active compute instances.
* **Detection Criteria:**
  - Disks: `managedBy == null` and `diskState == 'Unattached'`.
  - Public IPs: `ipConfiguration == null`.
* **Formula:** Full elimination of idle resource monthly charge:
  $$\text{Monthly Savings} = \text{Current Monthly Cost}$$
* **Example Finding:**
  - *Resource:* `disk-unattached-backup-old` (1024 GiB Premium SSD P30)
  - *Status:* `Unattached Managed Disk for 142 days`
  - *Cost:* `\$73.22/mo`
  - *Savings:* **\$878.64 ($73.22/month)**

### [COST-03] Underutilized Managed Data Disks
* **Data Sources:** Azure Monitor Metrics (`Composite Disk Read Bytes/sec`, `Disk Write Bytes/sec`, `Disk Operations/sec`).
* **Detection Criteria:** Premium SSD (P30, P40, P50) disks provisioned for high IOPS where consumed throughput averages $< 100$ IOPS ($< 2\%$ of provisioned threshold).
* **Formula:** Delta between provisioned Premium tier and Standard SSD:
  $$\text{Monthly Savings} = \text{Cost}_{\text{Premium}} - \text{Cost}_{\text{Standard SSD}}$$
* **Example Finding:**
  - *Disk:* `data-disk-analytics-01` (1024 GiB Premium SSD P30)
  - *IOPS Telemetry:* `12.4 Average IOPS (0.25% Utilization)`
  - *Recommendation:* Switch tier from Premium SSD to Standard SSD E30
  - *Savings:* **\$710.04 ($59.17/month)**

### [COST-04] Underutilized Operating System Disks
* **Data Sources:** Disk resource specifications and attached VM compute tier.
* **Detection Criteria:** OS disks provisioned as Premium SSD (P10, P15, P20) on development, testing, or low-throughput VMs where Standard SSD provides equivalent user response times.
* **Formula:** Delta between Premium SSD and Standard SSD rate.
* **Example Finding:**
  - *Resource:* `osdisk-dev-tester-01` (128 GiB Premium SSD P10)
  - *Environment:* `Development`
  - *Recommendation:* Downgrade OS disk tier to Standard SSD (E10)
  - *Savings:* **\$225.84 ($18.82/month)**

### [COST-05] Monthly Billing & Service Cost Comparison
* **Data Sources:** Azure Cost Management monthly billing aggregation grouping by service and resource group over consecutive 30-day billing cycles.
* **Detection Criteria:** Flags any service, subscription, or resource group experiencing cost spikes $> 20\%$ period-over-period.
* **Analytical Purpose:** Identifies cost drift, forgotten proof-of-concepts, and runaway telemetry pipelines before invoice finalization.
* **Example Finding:**
  - *Resource:* `Service: Microsoft.CognitiveServices / OpenAI`
  - *Previous Period Cost:* `\$4,150.00` | *Current Period Cost:* `\$14,850.00`
  - *Cost Variance:* `+\$10,700.00 (+257.8%)`

### [COST-06] Top 20 Cloud Cost Optimization Opportunities
* **Data Sources:** Cross-module intelligence aggregator querying candidate opportunities across Compute, Storage, Database, Licensing, and Backup.
* **Detection & Sorting:** Aggregates all identified findings, deduplicates candidate resources, and **strictly sorts them in descending order from highest to lowest cost impact**.
* **Analytical Purpose:** Delivers an immediate executive hit-list prioritizing the top 20 actions that yield the greatest return on effort.

### [COST-07] VM Licensing & Azure Hybrid Benefit (AHB)
* **Data Sources:** Compute instance OS Profile (`windowsConfiguration`, `licenseType`) cross-referenced against Core counts and retail pricing.
* **Detection Criteria:** Windows Server or RHEL/SLES virtual machines billed under Pay-As-You-Go (PAYG) rates where enterprise license agreements or Software Assurance cover the base OS.
* **Formula:** Eliminates the software surcharge (approx. 40-48% of total VM cost):
  $$\text{Monthly Savings} = \text{PAYG Software Surcharge Rate} \times 730\ \text{hours}$$
* **Example Finding:**
  - *VM Name:* `vm-sql-cluster-01` (`Standard_D8s_v5` 8 vCPUs)
  - *Current License:* `PAYG (License Included)`
  - *Recommendation:* Enable Azure Hybrid Benefit for Windows Server
  - *Savings:* **\$1,611.84 ($134.32/month)**

### [COST-08] Virtual Machine Auto-Shutdown Enforcement
* **Data Sources:** Azure Compute schedule policies (`Microsoft.DevTestLab/schedules/shutdown-computevm-*`) and VM power state.
* **Detection Criteria:** Virtual machines located in verified non-production environments (`Dev`, `QA`, `Testing`, `Staging`) lacking an automated shutdown policy and running 24/7.
* **Formula:** Eliminates 128 off-peak hours per week (19:00 to 07:00 weekdays + 48 weekend hours):
  $$\text{Off-Hours Savings} = \text{Hourly VM Rate} \times 128\ \text{hours} \times 4.33\ \text{weeks}$$
* **Example Finding:**
  - *VM Name:* `vm-dev-integration-01` (`Standard_D4s_v5` at \$140.16/mo)
  - *Environment:* `Development` | *Auto-Shutdown:* `Not Configured`
  - *Recommendation:* Schedule automated shutdown at 19:00 UTC daily
  - *Savings:* **\$840.96 ($70.08/month)**

### [COST-09] Managed Disk Capacity & Utilization Alert
* **Data Sources:** Azure Monitor OS Guest telemetry (`Disk Free Space %`) correlated with provisioned disk size.
* **Detection Criteria:** Managed disks nearing physical saturation ($> 90\%$ used) requiring storage expansion, or severely over-provisioned disks ($< 10\%$ used) wasting reserved storage.
* **Example Finding:**
  - *Resource:* `disk-app-log-volume` (Provisioned 512 GB)
  - *Used Space:* `476 GB (93.0% Utilized)`
  - *Status:* `Capacity Warning - Action Required`

### [COST-10] Database CPU / DTU Performance & Sizing Threshold
* **Data Sources:** Azure SQL Monitor metrics (`dtu_consumption_percent`, `cpu_percent`) over a 30-day baseline.
* **Detection Criteria:** Azure SQL or PostgreSQL databases with average DTU/CPU utilization $< 5.0\%$.
* **Formula:** Delta between provisioned performance tier (e.g., Premium P4 / Standard S3) and right-sized target tier (e.g., Standard S1).
* **Example Finding:**
  - *Database:* `sqldb-reporting-replica` (`Standard S3` at \$147.20/mo)
  - *Average DTU:* `1.8% over 30 days`
  - *Recommendation:* Scale down to Standard S1 (\$29.44/mo)
  - *Savings:* **\$1,413.12 ($117.76/month)**

### [COST-11] Recently Provisioned Unused Resources
* **Data Sources:** Azure Activity Log (`createdTime` within last 14 days) combined with zero network ingress/egress bytes and zero CPU activity.
* **Detection Criteria:** Identifies test workloads, training environments, or forgotten sandboxes created within the last two weeks with zero recorded operational activity.
* **Example Finding:**
  - *Resource:* `vm-sandbox-test-temp` (`Standard_D4s_v5`)
  - *Creation Date:* `2026-11-02` | *Activity:* `0 bytes network I/O recorded`
  - *Recommendation:* Decommission unutilized temporary resource
  - *Savings:* **\$1,681.92 ($140.16/month)**

### [COST-12] Storage Account Lifecycle Policy Disabled Rules
* **Data Sources:** Azure Storage Management Policies (`Microsoft.Storage/storageAccounts/managementPolicies`).
* **Detection Criteria:** Storage accounts with active blobs $> 10$ TB where lifecycle management policies either do not exist or contain rules set to disabled (`enabled == false`), resulting in stale data remaining in expensive Hot tier storage.
* **Formula:** Cost differential between Hot Tier (\$0.018/GB) and Cool Tier (\$0.010/GB) or Archive Tier (\$0.0015/GB).
* **Example Finding:**
  - *Storage Account:* `sadiagnosticlogs01` (42 TB Hot GRS)
  - *Policy Status:* `3 Rules Configured but all Disabled`
  - *Recommendation:* Enable rule moving blobs $> 30$ days to Cool tier
  - *Savings:* **\$3,025.80 ($252.15/month)**

### [COST-13] Database Storage Allocation vs Actual Usage
* **Data Sources:** Azure SQL Metric `storage_percent` (`allocated_data_storage` vs `used_data_storage`).
* **Detection Criteria:** Databases where allocated storage is at least $4\times$ greater than actual consumed data volume ($< 25\%$ utilization).
* **Formula:** Reclaiming unused reserved GiB storage charges.
* **Example Finding:**
  - *Database:* `database-bi-dw-01` (Allocated 1000 GB, Used 45 GB)
  - *Utilization:* `4.5% storage consumed`
  - *Recommendation:* Shrink database and reduce allocated storage cap to 200 GB
  - *Savings:* **\$1,440.00 ($120.00/month)**

### [COST-14] Azure Backup Policy & Retention Cost Alignment
* **Data Sources:** Recovery Services Vaults (`Microsoft.RecoveryServices/vaults`) and Backup Policies (`backupPolicies`).
* **Detection Criteria:** Virtual machines or databases backed up under aggressive multi-year retention policies (e.g., 3650-day retention) on secondary non-critical workloads where compliance mandates only 30-day retention.
* **Formula:** Redundant backup storage consumption reduction.
* **Example Finding:**
  - *Vault:* `rsv-prod-central`
  - *Policy:* `Daily-3650Day-Retention (10-Year Daily Retention on Dev VMs)`
  - *Storage Consumed:* `4.2 TB GRS Vault Storage`
  - *Savings:* **\$2,232.00 ($186.00/month)**

### [COST-15] Aged & Stale Managed Disk Snapshots
* **Data Sources:** Azure Compute snapshot listings (`Microsoft.Compute/snapshots`).
* **Detection Criteria:** Disk snapshots older than 90 days that are unlinked from active disaster recovery policies or where the parent disk has already been deleted.
* **Formula:** Total snapshot GB storage rate elimination:
  $$\text{Monthly Savings} = \text{Snapshot Size (GB)} \times \text{GB Snapshot Rate}$$
* **Example Finding:**
  - *Snapshot Name:* `snap-vm-upgrade-prepatch-2023` (128 GiB)
  - *Snapshot Age:* `184 days` | *Parent Disk:* `Deleted`
  - *Recommendation:* Delete orphaned snapshot
  - *Savings:* **\$307.20 ($25.60/month)**

### [COST-16] Function App Execution Frequency & Hosting Plan
* **Data Sources:** Azure Monitor metric `FunctionExecutionCount` and `FunctionExecutionUnits` cross-referenced with App Service Plan hosting SKU.
* **Detection Criteria:** Serverless Function Apps hosted on dedicated App Service Plans (Basic, Standard, or Premium P1v3 costing \$70–\$150/mo) executing fewer than 500 times per month.
* **Formula:** Delta between dedicated App Service Plan hosting and pure Consumption Plan pricing:
  $$\text{Monthly Savings} = \text{Dedicated Plan Cost} - \text{Consumption Plan Cost} \approx \text{Dedicated Plan Cost}$$
* **Example Finding:**
  - *Function App:* `func-nightly-sync-qa` (Hosted on Dedicated P1v3 at \$72.50/mo)
  - *Telemetry:* `14 executions per month`
  - *Recommendation:* Migrate to Consumption Serverless Plan (Free tier covers $< 1\text{M}$ executions)
  - *Savings:* **\$870.00 ($72.50/month)**

### [COST-17] VM Auto-Start Schedule & Off-Hours Impact
* **Data Sources:** Azure Automation Runbooks, Logic Apps, and Scheduled Tasks configuring VM startup.
* **Detection Criteria:** Non-production virtual machines configured with automated start tasks triggering daily at 06:00, including Saturday and Sunday, where workloads remain idle during weekend windows.
* **Formula:** Eliminates 32 unutilized weekend operational hours:
  $$\text{Monthly Cost Impact} = \text{Hourly VM Rate} \times 32\ \text{hours} \times 4.33\ \text{weeks}$$
* **Example Finding:**
  - *VM Name:* `vm-dev-frontend-02` (`Standard_D2s_v5`)
  - *Configured Start:* `06:00 UTC (Monday through Sunday)`
  - *Recommendation:* Update cron trigger to execute strictly Monday through Friday
  - *Savings:* **\$387.00 ($32.25/month)**

### [COST-18] Non-LRS Storage Redundancy Optimization
* **Data Sources:** Storage Account resource model (`sku.name`).
* **Detection Criteria:** Storage accounts located in verified non-production or test environments configured with high-cost geo-redundant storage (GRS) or read-access geo-redundant storage (RA-GRS) instead of standard locally redundant storage (LRS).
* **Formula:** Cost delta between GRS (\$0.045/GB) and LRS (\$0.019/GB):
  $$\text{Monthly Savings} = \text{Capacity (GB)} \times (\text{Rate}_{\text{GRS}} - \text{Rate}_{\text{LRS}})$$
* **Example Finding:**
  - *Storage Account:* `satestdatawarehouse01` (12 TB in QA Environment)
  - *Configured Redundancy:* `Standard_GRS` | *Required:* `Standard_LRS`
  - *Recommendation:* Switch replication to LRS
  - *Savings:* **\$316.80 ($26.40/month)**

---

## 5. Summary of Platform Executive Deliverables

All 32 assessment modules feed directly into executive presentation outputs:
1. **Interactive Real-Time Single-Page Application:**
   - 6 KPI Scorecards: Total Subscriptions, Microsoft Defender Overall Secure Score, Total Critical / High Security Risks, Current Cost Wastage, Monthly Savings, and Annual Savings.
   - Dynamic currency rendering matching the evaluated tenant.
   - Instant search filtering and deep-dive finding modals for all 32 modules.
2. **Landscape Boardroom PDF Deliverable:**
   - Formatted in landscape Letter with 752 pt printable width.
   - Includes full executive status matrix, risk rankings, and exact assessment-specific finding tables.
3. **Enterprise Multi-Tab Excel Workbook:**
   - Standalone worksheets for every assessment module.
   - Color-coded severity indicators, formatted currency values, and auto-adjusted column dimensions.
