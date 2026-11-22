"""
FinSecOps Cloud Technology Knowledge Base (RAG context engine)
Provides authoritative technical context from official Microsoft Learn, CAF, WAF, MCSB, and FinOps guidelines.
"""
import re
from typing import List, Dict, Any, Optional

class CloudKnowledgeBase:
    _DOCUMENTS: List[Dict[str, Any]] = [
        {
            "id": "doc_pe_vs_se",
            "title": "Azure Private Endpoints vs Service Endpoints",
            "source": "Microsoft Learn / Azure Networking Architecture",
            "url": "https://learn.microsoft.com/azure/private-link/private-endpoint-overview",
            "topics": ["networking", "security", "private endpoint", "service endpoint", "vnet", "private link"],
            "content": (
                "**Private Endpoint vs Service Endpoint Comparison**:\n\n"
                "1. **Azure Private Endpoint (Azure Private Link)**:\n"
                "- **How it works**: Assigns a private IP address from your Virtual Network subnet directly to the target Azure PaaS resource.\n"
                "- **Traffic path**: Traffic stays strictly within the Microsoft Azure backbone network; public internet endpoint is completely disabled or bypassed.\n"
                "- **Data exfiltration protection**: Restricts traffic specifically to the single named resource (e.g. `storageaccount1`), preventing exfiltration to other accounts in the same tenant/region.\n"
                "- **Cross-network reachability**: Reachable over VNet Peering, ExpressRoute, VPN Gateways, and on-premises networks.\n"
                "- **Cost**: Incurs a minor hourly fee per private endpoint (~$0.01/hr) + inbound/outbound data processing fees (~$0.01/GB).\n\n"
                "2. **Azure Service Endpoint**:\n"
                "- **How it works**: Optimizes routing from your subnet to Azure service public IP addresses over the Microsoft backbone. Does not assign a private IP to the service.\n"
                "- **Traffic path**: Uses optimal routing over the backbone, but destination remains the service's public VIP.\n"
                "- **Data exfiltration**: Does not inherently prevent accessing unauthorized storage accounts within the same region unless paired with Service Endpoint Policies (where supported).\n"
                "- **Cross-network reachability**: Cannot be reached directly from on-premises via ExpressRoute or VPN without complex NAT/proxy architectures.\n"
                "- **Cost**: Free of charge; no data processing fee.\n\n"
                "**Recommendation**: Use **Private Endpoints** for enterprise zero-trust security and hybrid/on-premises connectivity; use Service Endpoints for internal dev/test workloads needing zero cost."
            )
        },
        {
            "id": "doc_vm_lifecycle_finops",
            "title": "Azure VM Power States & FinOps Cost Optimization",
            "source": "Microsoft Learn & Azure Architecture Center",
            "url": "https://learn.microsoft.com/azure/virtual-machines/states-billing",
            "topics": ["compute", "vm", "virtual machines", "power state", "deallocated", "stopped", "finops", "auto-shutdown"],
            "content": (
                "**Azure VM Power States and Billing Impact**:\n\n"
                "- **Stopped (Allocated)**: Occurs when a VM is shut down from inside the guest operating system (`shutdown -h now` or Windows Shut Down). The compute fabric still reserves hardware cores and memory. **Compute charges continue at 100%**! Only OS/data disks and public IPs are active.\n"
                "- **Stopped (Deallocated)**: Occurs when stopped via Azure Portal, CLI (`az vm deallocate`), PowerShell (`Stop-AzVM`), or Auto-Shutdown schedules. Hardware cores are released back to the Azure pool. **Compute charges drop to $0.00/hour**! Storage disks and static public IPs continue to accrue storage fees.\n"
                "- **Running**: Standard operational state. Full compute and storage billing applies.\n\n"
                "**Cost Optimization Levers**:\n"
                "1. **Auto-Shutdown**: Schedule daily shutdown for non-production VMs (e.g. 7 PM to 7 AM weekdays, all weekend) to save ~65% on compute fees.\n"
                "2. **Azure Hybrid Benefit (AHB)**: Leverage existing Windows Server and Red Hat/SUSE licenses with Software Assurance to save up to 49% on compute rates.\n"
                "3. **Reserved Instances (RI) & Savings Plans**: Commit to 1-year or 3-year consistent compute usage for 40% to 72% discounts over pay-as-you-go rates."
            )
        },
        {
            "id": "doc_managed_disks",
            "title": "Azure Managed Disks Architecture & Selection Guide",
            "source": "Azure Architecture Center",
            "url": "https://learn.microsoft.com/azure/virtual-machines/disks-types",
            "topics": ["storage", "disks", "managed disks", "iops", "throughput", "premium ssd", "standard ssd", "ultra disk"],
            "content": (
                "**Azure Managed Disks Comparison Matrix**:\n\n"
                "| Disk Tier | Max IOPS | Max Throughput | Latency Target | Workload Fit | Relative Cost |\n"
                "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
                "| **Standard HDD (Standard_LRS)** | Up to 2,000 | 500 MB/s | ~10-20ms | Non-critical backups, cold data | Lowest |\n"
                "| **Standard SSD (StandardSSD_LRS)** | Up to 6,000 | 750 MB/s | ~5-10ms | Dev/Test, light web workloads | Economy |\n"
                "| **Premium SSD v1 (Premium_LRS)** | Up to 20,000 | 900 MB/s | Single-digit ms | Production databases, ERP, high-IOPS | Enterprise Standard |\n"
                "| **Premium SSD v2 (PremiumV2_LRS)** | Up to 80,000 | 1,200 MB/s | Sub-millisecond | High-performance SQL, PostgreSQL, Cassandra | High Value / Elastic |\n"
                "| **Ultra Disk (UltraSSD_LRS)** | Up to 160,000 | 4,000 MB/s | Sub-millisecond | SAP HANA, top-tier transactional RDBMS | Highest |\n\n"
                "**FinOps Recommendation**: Switch Dev/Test OS disks from Premium SSD to Standard SSD to cut disk spend by ~60% with zero observable performance difference for development."
            )
        },
        {
            "id": "doc_storage_lifecycle_tiers",
            "title": "Azure Blob Storage Access Tiers & Lifecycle Management (LCM)",
            "source": "Microsoft Learn Storage Documentation",
            "url": "https://learn.microsoft.com/azure/storage/blobs/lifecycle-management-overview",
            "topics": ["storage", "blob", "lcm", "lifecycle", "hot", "cool", "cold", "archive"],
            "content": (
                "**Azure Blob Storage Access Tiers & Transition Rules**:\n\n"
                "- **Hot Tier**: Optimized for data that is in active use. Highest storage cost, lowest access/read costs.\n"
                "- **Cool Tier**: Optimized for data stored for at least 30 days and accessed infrequently. ~50% lower storage cost than Hot. Early deletion fee applies if deleted < 30 days.\n"
                "- **Cold Tier**: Optimized for data stored for at least 90 days. ~75% lower storage cost than Hot. Early deletion fee applies if deleted < 90 days.\n"
                "- **Archive Tier**: Offline tier for long-term retention (> 180 days). ~90% lower storage cost than Hot. Retrieval latency: up to 15 hours (standard) or 1 hour (high priority). Early deletion fee applies if deleted < 180 days.\n\n"
                "**Lifecycle Management (LCM) Best Practice**:\n"
                "Apply automated rules to transition base blobs:\n"
                "- Move to Cool after 30 days of inactivity.\n"
                "- Move to Cold after 90 days.\n"
                "- Move to Archive after 180 days.\n"
                "- Delete temporary log blobs after 365 days."
            )
        },
        {
            "id": "doc_defender_secure_score",
            "title": "Microsoft Defender for Cloud & Secure Score Architecture",
            "source": "Microsoft Security Documentation",
            "url": "https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls",
            "topics": ["security", "defender", "secure score", "recommendations", "attack paths", "mcsb"],
            "content": (
                "**Microsoft Defender for Cloud & Secure Score Calculation**:\n\n"
                "1. **Secure Score**: A numerical evaluation of security posture expressed as a percentage. It aggregates controls from the Microsoft Cloud Security Benchmark (MCSB).\n"
                "2. **Weighted Score Calculation**: Across multi-subscription estates, each subscription's score is weighted based on resource volume and subscription weight to determine the overall corporate posture.\n"
                "3. **Security Controls**: Grouped into major remediation domains: *Enable MFA*, *Restrict unauthorized network access*, *Apply system updates*, *Enable encryption at rest*, *Remediate security configurations*, and *Protect sensitive data*.\n"
                "4. **Attack Path Analysis**: Maps complex multi-stage vulnerabilities (e.g., Internet-exposed VM -> Managed Identity with Contributor RBAC -> Key Vault with sensitive credentials).\n"
                "5. **Remediation**: Prioritize Critical and High findings that provide the largest positive score gain while neutralizing active attack paths."
            )
        },
        {
            "id": "doc_hub_spoke_networking",
            "title": "Azure Hub-and-Spoke Network Architecture & Zero Trust",
            "source": "Azure Architecture Center",
            "url": "https://learn.microsoft.com/azure/architecture/reference-architectures/hybrid-networking/hub-spoke",
            "topics": ["networking", "hub and spoke", "vnet", "peering", "firewall", "nsg", "zero trust"],
            "content": (
                "**Enterprise Hub-and-Spoke Topology**:\n\n"
                "- **Hub Virtual Network**: Houses central shared services including Azure Firewall / NVA, Azure Bastion, VPN/ExpressRoute Gateways, and private DNS zones.\n"
                "- **Spoke Virtual Networks**: Isolate distinct workload environments (e.g. `spoke-prod`, `spoke-dev`, `spoke-shared-data`). Peered directly to the Hub.\n"
                "- **Default Route (0.0.0.0/0)**: Enforced via Route Tables (UDR) pointing all outbound spoke traffic through Azure Firewall in the Hub for deep packet inspection and threat intelligence.\n"
                "- **Network Security Groups (NSGs)**: Applied at the subnet level to restrict lateral east-west movement between application tiers (Web, App, Database)."
            )
        },
        {
            "id": "doc_aks_architecture",
            "title": "Azure Kubernetes Service (AKS) Enterprise Architecture",
            "source": "Azure Architecture Center",
            "url": "https://learn.microsoft.com/azure/aks/concepts-network",
            "topics": ["kubernetes", "aks", "container", "docker", "cni", "kubenet", "ingress"],
            "content": (
                "**AKS Enterprise Production Principles**:\n\n"
                "- **Network Plugin Selection**:\n"
                "  * **Azure CNI Overlay**: Recommended for large clusters. Pods get private IP addresses from an overlay subnet, avoiding IP address exhaustion in your enterprise VNet.\n"
                "  * **Azure CNI (VNet IP)**: Direct VNet IP per pod. Demands large subnet allocations.\n"
                "  * **Kubenet**: Basic NAT routing, limited to smaller deployments.\n"
                "- **Node Pools**: Separate system services (`System` pool with CriticalAddonsOnly taint) from application workloads (`User` pool with Spot instances for non-prod).\n"
                "- **Identity**: Utilize Microsoft Entra Workload ID for pod-to-Azure authentication, completely eliminating hardcoded secret keys."
            )
        },
        {
            "id": "doc_azure_databases",
            "title": "Azure Database Options Comparison (SQL, PostgreSQL, Cosmos DB)",
            "source": "Microsoft Learn Database Guide",
            "url": "https://learn.microsoft.com/azure/architecture/guide/technology-choices/data-store-decision-tree",
            "topics": ["database", "sql", "postgresql", "cosmos", "mysql", "databases"],
            "content": (
                "**Azure Database Decision Matrix**:\n\n"
                "- **Azure SQL Database / Managed Instance**: Best for enterprise transactional relational applications requiring 100% SQL Server compatibility, built-in AI index tuning, serverless auto-pause, and Active Directory authentication.\n"
                "- **Azure Database for PostgreSQL (Flexible Server)**: Best for open-source Linux stacks, microservices, and web workloads. Offers zone-redundant HA and pgvector support for AI search.\n"
                "- **Azure Cosmos DB**: Globally distributed multi-model NoSQL database. Guarantees single-digit millisecond read/write latencies at any scale with multi-region replication.\n\n"
                "**Security Standard**: Always enforce **Customer-Managed Keys (CMK)**, TLS 1.2+, and **Private Link** to disable all public internet access."
            )
        }
    ]

    @classmethod
    def search(cls, query: str, max_results: int = 3) -> List[Dict[str, Any]]:
        """
        Dynamically retrieves relevant technical architecture and best-practice documentation.
        Calculates relevance score based on token and topic matching.
        """
        q_tokens = set(re.findall(r"\b[a-zA-Z0-9_\-]{3,}\b", query.lower()))
        if not q_tokens:
            return cls._DOCUMENTS[:max_results]

        scored_docs = []
        for doc in cls._DOCUMENTS:
            score = 0
            # Check topics
            for topic in doc.get("topics", []):
                t_words = topic.lower().split()
                if any(tw in q_tokens for tw in t_words) or topic.lower() in query.lower():
                    score += 5

            # Check title
            title_words = doc.get("title", "").lower().split()
            for tw in title_words:
                if tw in q_tokens:
                    score += 3

            # Check content
            content_lower = doc.get("content", "").lower()
            for token in q_tokens:
                if token in content_lower:
                    score += 1

            if score > 0:
                scored_docs.append((score, doc))

        scored_docs.sort(key=lambda x: x[0], reverse=True)
        results = [d for _, d in scored_docs[:max_results]]
        return results if results else cls._DOCUMENTS[:1]
