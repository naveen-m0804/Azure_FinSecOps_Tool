"""
FinSecOps Dynamic Tool Registry & Execution Dispatcher
Provides structured OpenAI-compatible tool schemas and validated backend execution.
Strictly Read-Only, workspace-isolated, and uses live Azure SDKs/REST APIs and session reports.
"""
import os
import json
import logging
import datetime
from typing import Dict, Any, List, Optional, Callable, Awaitable

from app.core.config import settings
from app.core.authentication import AzureAuthService
from app.azure.client_base import AzureClientBase
from app.azure.compute import ComputeAdapter
from app.azure.storage import StorageAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.defender import DefenderAdapter
from app.azure.monitor import MonitorAdapter
from app.azure.network import NetworkAdapter
from app.azure.resources import ResourcesAdapter
from app.agent.guardrails import FinSecOpsGuardrails, SecurityPolicyViolationError
from app.agent.knowledge_base import CloudKnowledgeBase

logger = logging.getLogger("azure_finsecops.agent.tools")

class ToolExecutionContext:
    def __init__(self, connection_data: Optional[Dict[str, Any]] = None):
        self.connection_data = connection_data or {}
        self.workspace_name = self.connection_data.get("workspace_name", "Azure Workspace")
        self.tenant_id = self.connection_data.get("tenant_id")
        self.client_id = self.connection_data.get("client_id")
        self.client_secret = self.connection_data.get("client_secret")
        self.subscriptions = self.connection_data.get("subscriptions", [])
        self.cumulative_summary = self.connection_data.get("cumulative_summary", {})
        self.cumulative_results = self.connection_data.get("cumulative_results", {})
        self.currency = self.connection_data.get("currency", "USD")

    async def get_azure_client(self) -> Optional[AzureClientBase]:
        if not self.tenant_id or not self.client_id or not self.client_secret:
            return None
        token, err = await AzureAuthService.acquire_arm_token(
            self.tenant_id, self.client_id, self.client_secret
        )
        if not token:
            logger.error(f"Failed to acquire Azure ARM access token: {err}")
            return None
        return AzureClientBase(
            token=token,
            timeout=settings.azure_request_timeout_seconds,
            max_retries=settings.azure_max_retries
        )

    def get_authorized_subscription_ids(self) -> List[str]:
        sub_ids = []
        for s in self.subscriptions:
            sid = getattr(s, "subscription_id", None) or (s.get("subscription_id") if isinstance(s, dict) else str(s))
            if sid:
                sub_ids.append(sid)
        return sub_ids

    def get_subscription_display_name(self, subscription_id: str) -> str:
        for s in self.subscriptions:
            sid = getattr(s, "subscription_id", None) or (s.get("subscription_id") if isinstance(s, dict) else "")
            if sid.lower() == subscription_id.lower():
                return getattr(s, "display_name", None) or (s.get("display_name") if isinstance(s, dict) else sid)
        return subscription_id


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Dict[str, Any]] = {}
        self._handlers: Dict[str, Callable[[Dict[str, Any], ToolExecutionContext], Awaitable[Dict[str, Any]]]] = {}
        self._register_default_tools()

    def register(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        handler: Callable[[Dict[str, Any], ToolExecutionContext], Awaitable[Dict[str, Any]]],
        category: str = "azure"
    ):
        self._tools[name] = {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": parameters,
            },
            "category": category
        }
        self._handlers[name] = handler

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        return [
            {"type": t["type"], "function": t["function"]}
            for t in self._tools.values()
        ]

    async def execute_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        context: ToolExecutionContext
    ) -> Dict[str, Any]:
        """
        Validates read-only policy, checks permissions, and dispatches tool execution.
        """
        if name not in self._handlers:
            return {
                "success": False,
                "error": f"Tool '{name}' is not recognized in the FinSecOps tool registry."
            }

        # 1. Enforce backend Read-Only guardrails
        try:
            FinSecOpsGuardrails.validate_read_only_operation(name, arguments)
        except SecurityPolicyViolationError as sve:
            return {
                "success": False,
                "error": str(sve),
                "is_security_violation": True
            }

        # Clean null / None arguments so handlers receive clean kwargs
        cleaned_args = {k: v for k, v in (arguments or {}).items() if v is not None and v != "null"}

        # 2. Execute tool handler
        handler = self._handlers[name]
        try:
            result = await handler(cleaned_args, context)
            return result
        except Exception as ex:
            logger.error(f"Error executing tool '{name}': {ex}", exc_info=True)
            return {
                "success": False,
                "error": f"Tool execution failed: {str(ex)}"
            }

    def _register_default_tools(self):
        # -------------------------------------------------------------
        # 1. Azure Resource Graph (ARG)
        # -------------------------------------------------------------
        self.register(
            name="azure_resource_graph_query",
            description=(
                "Executes a read-only KQL query across the customer's authorized Azure subscriptions using Azure Resource Graph. "
                "Use for resource inventory, counting by type, finding resources missing tags, discovering resource groups, "
                "locations, public IPs, and discovering any ARM resource type. Query must be pure read-only KQL."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Read-only KQL query (e.g. 'Resources | summarize count() by type | top 20 by count_' or 'Resources | where type =~ \"microsoft.compute/virtualmachines\" | project name, resourceGroup, location, properties.hardwareProfile.vmSize')"
                    },
                    "subscriptions": {
                        "type": ["array", "null"],
                        "items": {"type": "string"},
                        "description": "Optional subset of subscription IDs to scope the query. Pass null or omit if querying all verified subscriptions."
                    }
                },
                "required": ["query"]
            },
            handler=self._handle_resource_graph_query,
            category="azure_inventory"
        )

        # -------------------------------------------------------------
        # 2. Azure Compute / VM Inventory & PowerState
        # -------------------------------------------------------------
        self.register(
            name="azure_get_vm_inventory",
            description=(
                "Retrieves actual virtual machines across accessible Azure subscriptions, including real-time PowerState "
                "(running, stopped, deallocated), VM sizes/SKUs, OS version, OS disk, and attached network interfaces. "
                "Queries the real Azure Compute ARM API and instance views."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "subscription_id": {
                        "type": ["string", "null"],
                        "description": "Optional subscription ID to filter VMs. Pass null or omit if querying across all subscriptions."
                    },
                    "status_filter": {
                        "type": ["string", "null"],
                        "enum": ["all", "running", "deallocated", "stopped", None],
                        "description": "Filter by power state. Use 'deallocated' or 'stopped' to find stopped instances, 'running' for active machines."
                    }
                }
            },
            handler=self._handle_get_vm_inventory,
            category="azure_compute"
        )

        # -------------------------------------------------------------
        # 3. Azure Storage Accounts & Policies
        # -------------------------------------------------------------
        self.register(
            name="azure_get_storage_accounts",
            description=(
                "Retrieves real storage accounts in customer subscriptions, including SKU redundancy (LRS, GRS, ZRS), "
                "access tier (Hot/Cool), HTTPS-only enforcement, public network access settings, and blob lifecycle management (LCM) rules."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "subscription_id": {
                        "type": ["string", "null"],
                        "description": "Optional subscription ID filter. Pass null or omit if querying across all subscriptions."
                    }
                }
            },
            handler=self._handle_get_storage_accounts,
            category="azure_storage"
        )

        # -------------------------------------------------------------
        # 4. Azure Cost Management
        # -------------------------------------------------------------
        self.register(
            name="azure_get_cost_analysis",
            description=(
                "Queries Azure Cost Management API for actual customer spending, cost breakdowns by service name, "
                "resource group, or subscription, and compares spending across billing periods or last 30 days."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "subscription_id": {
                        "type": ["string", "null"],
                        "description": "Optional subscription ID filter. Pass null or omit if querying all subscriptions."
                    },
                    "timeframe": {
                        "type": ["string", "null"],
                        "enum": ["MonthToDate", "BillingMonthToDate", "TheLastMonth", "TheLast30Days", None],
                        "description": "Billing period timeframe to analyze. Defaults to TheLast30Days."
                    },
                    "group_by": {
                        "type": ["string", "null"],
                        "enum": ["ServiceName", "ResourceGroupName", "ResourceLocation", "SubscriptionId", None],
                        "description": "Dimension to group spending by. Defaults to ServiceName."
                    }
                }
            },
            handler=self._handle_get_cost_analysis,
            category="azure_finops"
        )

        # -------------------------------------------------------------
        # 5. Microsoft Defender for Cloud & Security Posture
        # -------------------------------------------------------------
        self.register(
            name="azure_get_defender_security_posture",
            description=(
                "Retrieves live Microsoft Defender for Cloud Secure Score percentage, point breakdown, and active "
                "security recommendations / assessments across customer subscriptions."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "subscription_id": {
                        "type": ["string", "null"],
                        "description": "Optional subscription ID filter. Pass null or omit if querying all subscriptions."
                    }
                }
            },
            handler=self._handle_get_defender_posture,
            category="azure_security"
        )

        # -------------------------------------------------------------
        # 6. Azure Monitor / Resource Metrics
        # -------------------------------------------------------------
        self.register(
            name="azure_get_resource_metrics",
            description=(
                "Retrieves Azure Monitor host platform performance metrics (such as 'Percentage CPU', 'Network In Total', 'Network Out Total', 'Disk Read Bytes', 'Disk Write Bytes') "
                "directly from the Azure hypervisor without requiring in-guest agents (AMA, WAD, or DCR). "
                "Use to verify actual compute, network, or disk utilization."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "resource_id": {
                        "type": "string",
                        "description": "Full ARM resource ID or VM name of the target resource."
                    },
                    "metric_names": {
                        "type": "string",
                        "description": "Comma-separated metric names (e.g. 'Percentage CPU' or 'Percentage CPU,Network In Total,Disk Read Bytes')."
                    },
                    "hours": {
                        "type": ["integer", "null"],
                        "description": "Number of past hours to inspect (default 24)."
                    }
                },
                "required": ["resource_id", "metric_names"]
            },
            handler=self._handle_get_resource_metrics,
            category="azure_monitor"
        )

        # -------------------------------------------------------------
        # 7. Azure Advisor Recommendations
        # -------------------------------------------------------------
        self.register(
            name="azure_get_advisor_recommendations",
            description=(
                "Queries official Azure Advisor recommendations for Cost, Security, High Availability, Performance, "
                "and Operational Excellence across accessible subscriptions."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "subscription_id": {
                        "type": ["string", "null"],
                        "description": "Optional subscription ID filter. Pass null or omit if querying all subscriptions."
                    },
                    "category": {
                        "type": ["string", "null"],
                        "enum": ["Cost", "Security", "HighAvailability", "Performance", "OperationalExcellence", None],
                        "description": "Advisor category to filter."
                    }
                }
            },
            handler=self._handle_get_advisor_recommendations,
            category="azure_advisor"
        )

        # -------------------------------------------------------------
        # 8. Azure Networking & Exposure
        # -------------------------------------------------------------
        self.register(
            name="azure_get_network_topology",
            description=(
                "Retrieves network security groups (NSGs), public IP addresses, and virtual network topology to identify "
                "public internet exposure and firewall configurations."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "subscription_id": {
                        "type": ["string", "null"],
                        "description": "Optional subscription ID filter. Pass null or omit if querying all subscriptions."
                    }
                }
            },
            handler=self._handle_get_network_topology,
            category="azure_networking"
        )

        # -------------------------------------------------------------
        # 9. FinSecOps Session Assessment Summary
        # -------------------------------------------------------------
        self.register(
            name="assessment_get_summary",
            description=(
                "Retrieves the active FinSecOps assessment report summary from the current workspace session, "
                "including overall security posture score, baseline score, achievable score, total identified annual and monthly savings, "
                "and finding counts categorized by severity (Critical, High, Medium, Low)."
            ),
            parameters={
                "type": "object",
                "properties": {}
            },
            handler=self._handle_assessment_summary,
            category="finsecops_assessment"
        )

        # -------------------------------------------------------------
        # 10. FinSecOps Session Findings & Modules
        # -------------------------------------------------------------
        self.register(
            name="assessment_get_findings",
            description=(
                "Retrieves actual detailed findings from previously executed FinSecOps assessment modules in the active workspace. "
                "Filter by category ('security' or 'cost'), severity ('Critical', 'High', 'Medium', 'Low'), or module code "
                "(e.g. 'underutilized_vms', 'orphan_resources', 'storage_lifecycle', 'disk_encryption', 'attack_paths')."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "category": {
                        "type": ["string", "null"],
                        "enum": ["all", "security", "cost", None],
                        "description": "Pillar category filter. Defaults to all."
                    },
                    "severity": {
                        "type": ["string", "null"],
                        "enum": ["Critical", "High", "Medium", "Low", None],
                        "description": "Optional severity filter."
                    },
                    "module_id": {
                        "type": ["string", "null"],
                        "description": "Optional specific assessment ID (e.g. 'underutilized_vms', 'disk_encryption', 'orphan_resources')."
                    },
                    "limit": {
                        "type": ["integer", "null"],
                        "description": "Maximum number of findings to retrieve (default 25)."
                    }
                }
            },
            handler=self._handle_assessment_findings,
            category="finsecops_assessment"
        )

        # -------------------------------------------------------------
        # 11. Custom FinSecOps Report Generation
        # -------------------------------------------------------------
        self.register(
            name="generate_custom_report",
            description=(
                "Generates a downloadable FinSecOps report (PDF or Excel) using actual assessment data or live tenant inventory. "
                "Returns the official download URL and document details."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "report_type": {
                        "type": "string",
                        "enum": [
                            "combined_pdf", "security_pdf", "cost_pdf",
                            "combined_excel", "security_excel", "cost_excel"
                        ],
                        "description": "Format and scope of the deliverable report to generate."
                    }
                },
                "required": ["report_type"]
            },
            handler=self._handle_generate_report,
            category="report_generation"
        )

        # -------------------------------------------------------------
        # 12. Technical Cloud Knowledge Base (RAG)
        # -------------------------------------------------------------
        self.register(
            name="search_cloud_knowledge",
            description=(
                "Searches the authoritative technical cloud knowledge base for Microsoft Azure Architecture Center, "
                "Well-Architected Framework (WAF), Cloud Adoption Framework (CAF), Microsoft Cloud Security Benchmark (MCSB), "
                "and FinOps best practices. Use for general cloud questions, service comparisons, architectural patterns, "
                "and configuration best practices."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Technical search query (e.g. 'private endpoint vs service endpoint', 'blob lifecycle management rules', 'vm sizing b-series vs d-series', 'aks network cni')."
                    }
                },
                "required": ["query"]
            },
            handler=self._handle_search_knowledge,
            category="knowledge_base"
        )

        # -------------------------------------------------------------
        # 13. Dynamic Generic Azure Resource Manager (ARM) Query
        # -------------------------------------------------------------
        self.register(
            name="azure_generic_arm_query",
            description=(
                "Executes a dynamic, read-only Azure Resource Manager REST API GET query for ANY Azure resource type, "
                "management endpoint, or platform service (e.g. Key Vaults, AKS Clusters, SQL Databases, Cosmos DB, "
                "Application Gateways, Role Assignments, Diagnostic Settings, etc.) across authorized subscriptions. "
                "Use when the user asks about an Azure service or property not covered by other specific tools."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "subscription_id": {
                        "type": "string",
                        "description": "Target subscription GUID (optional; uses first authorized subscription if omitted)."
                    },
                    "relative_path": {
                        "type": "string",
                        "description": "Relative ARM URI path (e.g. '/providers/Microsoft.KeyVault/vaults', '/resourceGroups/rg1/providers/Microsoft.Sql/servers', '/providers/Microsoft.Authorization/roleAssignments')."
                    },
                    "api_version": {
                        "type": "string",
                        "description": "Target Azure Resource Provider API version (e.g. '2023-07-01', '2022-05-01-preview', '2021-04-01')."
                    },
                    "query_params": {
                        "type": "object",
                        "description": "Optional query string parameters (e.g. {'$filter': '...', '$expand': '...'})"
                    }
                },
                "required": ["relative_path"]
            },
            handler=self._handle_generic_arm_query,
            category="azure_dynamic"
        )

        # -------------------------------------------------------------
        # 14. Dynamic On-Demand Assessment Execution
        # -------------------------------------------------------------
        self.register(
            name="azure_run_assessment_module",
            description=(
                "Dynamically executes any of the 32 real-time FinSecOps assessment modules on demand "
                "(e.g. 'service_retirement', 'vm_os_version', 'disk_encryption', 'underutilized_vms', "
                "'backup_status', 'tls_version', 'keyvault_rbac', 'contributor_rbac', etc.) against the customer's "
                "connected subscriptions. Returns live findings, compliance posture, and remediation recommendations."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "assessment_id": {
                        "type": "string",
                        "description": "Identifier of the assessment module to execute (e.g. 'service_retirement', 'vm_os_version', 'disk_encryption', 'underutilized_vms', 'tls_version', 'backup_status', etc.)."
                    },
                    "target_subscription_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of subscription IDs to scope the assessment to."
                    }
                },
                "required": ["assessment_id"]
            },
            handler=self._handle_run_assessment_module,
            category="assessment_execution"
        )

        # -------------------------------------------------------------
        # 15. Dynamic Multi-Vector Cloud Investigation Agent
        # -------------------------------------------------------------
        self.register(
            name="azure_dynamic_environment_analyst",
            description=(
                "Autonomous dynamic investigation agent: conducts an in-depth, multi-dimensional audit of any arbitrary "
                "resource group, service category (e.g., 'databases', 'containers', 'keyvaults', 'networking'), "
                "or security/cost domain. Correlates resource inventories, live Defender security alerts, Advisor recommendations, "
                "and configurations across the specified scope and produces an actionable, consolidated report."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "focus_area": {
                        "type": "string",
                        "description": "The specific area or service to investigate (e.g. 'key vaults', 'databases', 'aks', 'public IP exposure', 'rg-production', 'unattached disks')."
                    },
                    "scope_type": {
                        "type": "string",
                        "enum": ["resource_group", "service_type", "security_posture", "cost_anomaly", "custom_kql"],
                        "description": "Category of investigation."
                    },
                    "scope_filter": {
                        "type": "string",
                        "description": "Optional specific resource group name or service filter."
                    }
                },
                "required": ["focus_area"]
            },
            handler=self._handle_dynamic_investigation,
            category="autonomous_agent"
        )

    # --------------------------------------------------------------------------
    # TOOL HANDLERS
    # --------------------------------------------------------------------------
    async def _handle_resource_graph_query(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        client = await ctx.get_azure_client()
        if not client:
            return {
                "success": False,
                "error": "No active Azure connection in this workspace. Please connect using your Tenant ID and Service Principal."
            }

        kql = args.get("query", "").strip()
        if not kql:
            return {"success": False, "error": "Query cannot be empty."}

        target_subs = args.get("subscriptions") or ctx.get_authorized_subscription_ids()
        validated_subs = FinSecOpsGuardrails.validate_subscription_access(target_subs, ctx.subscriptions)
        if not validated_subs:
            return {"success": False, "error": "No authorized subscriptions accessible for this query."}

        url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
        payload = {
            "subscriptions": validated_subs,
            "query": kql,
            "options": {
                "resultFormat": "objectArray",
                "$top": 50
            }
        }

        try:
            resp = await client.execute_request("POST", url, json_data=payload)
            if resp.status_code == 200:
                data = resp.json()
                rows = data.get("data", [])
                total = data.get("totalRecords", len(rows))
                return {
                    "success": True,
                    "data": rows[:50],
                    "total_records": total,
                    "subscriptions_queried": len(validated_subs),
                    "is_live_data": True,
                    "source": "Azure Resource Graph (ARG)"
                }
            return {
                "success": False,
                "error": f"Azure Resource Graph returned HTTP {resp.status_code}: {resp.text[:300]}"
            }
        except Exception as ex:
            return {"success": False, "error": f"ARG execution error: {str(ex)}"}

    async def _handle_get_vm_inventory(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        client = await ctx.get_azure_client()
        if not client:
            return {
                "success": False,
                "error": "No active Azure connection in this workspace. Please connect using your Tenant ID and Service Principal."
            }

        sub_filter = args.get("subscription_id")
        status_filter = (args.get("status_filter") or "all").lower()

        target_subs = [sub_filter] if sub_filter else ctx.get_authorized_subscription_ids()
        validated_subs = FinSecOpsGuardrails.validate_subscription_access(target_subs, ctx.subscriptions)

        all_vms = []
        for sid in validated_subs:
            sub_name = ctx.get_subscription_display_name(sid)
            try:
                vms = await ComputeAdapter.get_vms(client, sid, expand_instance_view=True)
                for v in vms:
                    props = v.get("properties", {})
                    vm_name = v.get("name", "Unknown")
                    res_id = v.get("id", "")
                    location = v.get("location", "")
                    rg = res_id.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in res_id else "Default"
                    vm_size = props.get("hardwareProfile", {}).get("vmSize", "Unknown")
                    os_profile = props.get("storageProfile", {}).get("osDisk", {})
                    os_type = os_profile.get("osType", "Linux")
                    os_disk_size = os_profile.get("diskSizeGB", 128)
                    os_disk_sku = os_profile.get("managedDisk", {}).get("storageAccountType", "Standard_LRS")

                    # Instance view for power state
                    inst_view = props.get("instanceView", {})
                    statuses = inst_view.get("statuses", [])
                    power_state = "Unknown"
                    for s in statuses:
                        code = s.get("code", "")
                        if code.startswith("PowerState/"):
                            power_state = s.get("displayStatus", code.split("/")[-1])
                            break

                    # Fallback if instanceView was not populated in list call
                    if power_state == "Unknown" and res_id:
                        iv_res = await ComputeAdapter.get_vm_instance_view(client, res_id)
                        if iv_res.get("success"):
                            power_state = iv_res.get("power_state", "Unknown")

                    ps_lower = power_state.lower()
                    if status_filter == "running" and "running" not in ps_lower:
                        continue
                    if status_filter in ["deallocated", "stopped"] and ("deallocated" not in ps_lower and "stopped" not in ps_lower):
                        continue

                    all_vms.append({
                        "name": vm_name,
                        "resource_id": res_id,
                        "subscription_id": sid,
                        "subscription_name": sub_name,
                        "resource_group": rg,
                        "location": location,
                        "vm_size": vm_size,
                        "os_type": os_type,
                        "power_state": power_state,
                        "os_disk_size_gb": os_disk_size,
                        "os_disk_sku": os_disk_sku
                    })
            except Exception as ex:
                logger.warning(f"Error querying VMs for subscription {sid}: {ex}")

        return {
            "success": True,
            "vms": all_vms,
            "total_count": len(all_vms),
            "status_filter": status_filter,
            "is_live_data": True,
            "source": "Azure Compute ARM & InstanceView"
        }

    async def _handle_get_storage_accounts(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        client = await ctx.get_azure_client()
        if not client:
            return {"success": False, "error": "No active Azure connection in workspace."}

        sub_filter = args.get("subscription_id")
        target_subs = [sub_filter] if sub_filter else ctx.get_authorized_subscription_ids()
        validated_subs = FinSecOpsGuardrails.validate_subscription_access(target_subs, ctx.subscriptions)

        storage_list = []
        for sid in validated_subs:
            sub_name = ctx.get_subscription_display_name(sid)
            try:
                accounts = await StorageAdapter.get_storage_accounts(client, sid)
                for acc in accounts:
                    props = acc.get("properties", {})
                    sku = acc.get("sku", {}).get("name", "Standard_LRS")
                    acc_id = acc.get("id", "")
                    rg = acc_id.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in acc_id else ""

                    # Inspect LCM policy
                    lcm = await StorageAdapter.get_lifecycle_policy(client, acc_id)
                    lcm_status = lcm.get("status", "Not Configured")

                    storage_list.append({
                        "name": acc.get("name"),
                        "subscription_name": sub_name,
                        "subscription_id": sid,
                        "resource_group": rg,
                        "location": acc.get("location"),
                        "sku": sku,
                        "access_tier": props.get("accessTier", "Hot"),
                        "https_only": props.get("supportsHttpsTrafficOnly", True),
                        "public_network_access": props.get("publicNetworkAccess", "Enabled"),
                        "allow_blob_public_access": props.get("allowBlobPublicAccess", False),
                        "lifecycle_management_status": lcm_status
                    })
            except Exception as ex:
                logger.warning(f"Error querying storage for {sid}: {ex}")

        return {
            "success": True,
            "storage_accounts": storage_list,
            "total_count": len(storage_list),
            "is_live_data": True,
            "source": "Azure Storage ARM & ManagementPolicies"
        }

    async def _handle_get_cost_analysis(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        client = await ctx.get_azure_client()
        if not client:
            return {"success": False, "error": "No active Azure connection in workspace."}

        sub_filter = args.get("subscription_id")
        target_subs = [sub_filter] if sub_filter else ctx.get_authorized_subscription_ids()
        validated_subs = FinSecOpsGuardrails.validate_subscription_access(target_subs, ctx.subscriptions)

        timeframe = args.get("timeframe", "TheLast30Days")
        group_by = args.get("group_by", "ServiceName")

        results_by_sub = []
        for sid in validated_subs:
            sub_name = ctx.get_subscription_display_name(sid)
            url = f"https://management.azure.com/subscriptions/{sid}/providers/Microsoft.CostManagement/query?api-version=2023-11-01"
            payload = {
                "type": "ActualCost",
                "timeframe": timeframe,
                "dataset": {
                    "granularity": "None",
                    "aggregation": {
                        "totalCost": {
                            "name": "Cost",
                            "function": "Sum"
                        }
                    },
                    "grouping": [
                        {
                            "type": "Dimension",
                            "name": group_by
                        }
                    ]
                }
            }

            try:
                resp = await client.execute_request("POST", url, json_data=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    props = data.get("properties", {})
                    columns = [c.get("name") for c in props.get("columns", [])]
                    rows = props.get("rows", [])
                    
                    cost_idx = columns.index("Cost") if "Cost" in columns else 0
                    curr_idx = columns.index("Currency") if "Currency" in columns else 2
                    dim_idx = 1 if len(columns) > 1 else 0

                    breakdown = []
                    total_sub_cost = 0.0
                    sub_currency = ctx.currency

                    for r in rows:
                        cost_val = float(r[cost_idx]) if r[cost_idx] is not None else 0.0
                        dim_name = str(r[dim_idx]) if len(r) > dim_idx else "Unknown"
                        if len(r) > curr_idx and r[curr_idx]:
                            sub_currency = r[curr_idx]
                        total_sub_cost += cost_val
                        breakdown.append({
                            "name": dim_name,
                            "cost": round(cost_val, 2)
                        })

                    breakdown.sort(key=lambda x: x["cost"], reverse=True)
                    results_by_sub.append({
                        "subscription_id": sid,
                        "subscription_name": sub_name,
                        "total_cost": round(total_sub_cost, 2),
                        "currency": sub_currency,
                        "top_cost_contributors": breakdown[:15]
                    })
                else:
                    results_by_sub.append({
                        "subscription_id": sid,
                        "subscription_name": sub_name,
                        "error": f"HTTP {resp.status_code}: Cost Management query returned error."
                    })
            except Exception as ex:
                results_by_sub.append({
                    "subscription_id": sid,
                    "subscription_name": sub_name,
                    "error": str(ex)
                })

        return {
            "success": True,
            "cost_analysis": results_by_sub,
            "timeframe": timeframe,
            "group_by": group_by,
            "is_live_data": True,
            "source": "Azure Cost Management API"
        }

    async def _handle_get_defender_posture(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        client = await ctx.get_azure_client()
        if not client:
            return {"success": False, "error": "No active Azure connection in workspace."}

        sub_filter = args.get("subscription_id")
        target_subs = [sub_filter] if sub_filter else ctx.get_authorized_subscription_ids()
        validated_subs = FinSecOpsGuardrails.validate_subscription_access(target_subs, ctx.subscriptions)

        posture_results = []
        for sid in validated_subs:
            sub_name = ctx.get_subscription_display_name(sid)
            score_data = await DefenderAdapter.get_secure_score(client, sid)
            recs_data = await DefenderAdapter.get_security_assessments(client, sid, max_items=25)

            top_recs = []
            if recs_data.get("success"):
                for item in recs_data.get("value", [])[:20]:
                    props = item.get("properties", {})
                    meta = props.get("metadata", {})
                    status = props.get("status", {}).get("code", "Unhealthy")
                    if status != "Healthy":
                        top_recs.append({
                            "display_name": props.get("displayName", meta.get("displayName", "Security Recommendation")),
                            "severity": meta.get("severity", "Medium"),
                            "status": status,
                            "impact": meta.get("userImpact", "Moderate"),
                            "description": meta.get("description", "")[:250]
                        })

            posture_results.append({
                "subscription_id": sid,
                "subscription_name": sub_name,
                "secure_score_percentage": score_data.get("percentage") if score_data.get("success") else None,
                "current_points": score_data.get("current_score") if score_data.get("success") else None,
                "max_points": score_data.get("max_score") if score_data.get("success") else None,
                "unhealthy_recommendations_count": len(top_recs),
                "top_recommendations": top_recs[:10]
            })

        return {
            "success": True,
            "posture": posture_results,
            "is_live_data": True,
            "source": "Microsoft Defender for Cloud (ascScore & assessments)"
        }

    async def _handle_get_resource_metrics(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        client = await ctx.get_azure_client()
        if not client:
            return {"success": False, "error": "No active Azure connection in workspace."}

        res_id = str(args.get("resource_id", "")).strip()
        metric_names = str(args.get("metric_names", "Percentage CPU")).strip()
        hours = int(args.get("hours") or 24)

        # 1. Dynamically resolve simple VM or resource name to full ARM resource ID if necessary
        if res_id and not res_id.lower().startswith("/subscriptions/") and not res_id.lower().startswith("subscriptions/"):
            resolved_id = None
            for sid in ctx.get_authorized_subscription_ids():
                try:
                    from app.azure.compute import ComputeAdapter
                    vms = await ComputeAdapter.get_vms(client, sid)
                    for vm in vms:
                        if vm.get("name", "").lower() == res_id.lower():
                            resolved_id = vm.get("id")
                            break
                    if resolved_id:
                        break
                except Exception:
                    pass
            if resolved_id:
                res_id = resolved_id

        if not res_id:
            return {"success": False, "error": "Missing or invalid resource_id parameter."}

        now = datetime.datetime.now(datetime.timezone.utc)
        start = now - datetime.timedelta(hours=hours)
        start_str = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        # 2. Query Azure Monitor Metrics API
        res = await MonitorAdapter.get_metrics(
            client=client,
            resource_id=res_id,
            metric_names=metric_names,
            start_time=start_str,
            end_time=end_str,
            time_grain="PT1H",
            aggregation="Average"
        )

        # 3. Fallback for Virtual Machines: if initial query failed, query standard host platform metrics
        # Host platform metrics are emitted directly by the Azure hypervisor without AMA, WAD, or DCR.
        if (not res.get("success") or not res.get("metrics")) and "/virtualmachines/" in res_id.lower():
            fallback_metrics = "Percentage CPU,Network In Total,Network Out Total,Disk Read Bytes,Disk Write Bytes"
            res = await MonitorAdapter.get_metrics(
                client=client,
                resource_id=res_id,
                metric_names=fallback_metrics,
                start_time=start_str,
                end_time=end_str,
                time_grain="PT1H",
                aggregation="Average"
            )

        if not res.get("success"):
            err_msg = res.get("error") or "Azure Monitor Metrics query failed."
            return {
                "success": False,
                "error": err_msg,
                "resource_id": res_id,
                "note": "Host platform metrics (Percentage CPU, Disk I/O, Network I/O) are collected by default from the Azure hypervisor without agents."
            }

        return {
            "success": True,
            "resource_id": res_id,
            "metrics": res.get("metrics", {}),
            "hours": hours,
            "is_live_data": True,
            "source": "Azure Monitor Metrics API (Hypervisor Host Platform Metrics)",
            "telemetry_note": "Host platform metrics (CPU, Disk, Network) are retrieved directly from the Azure hypervisor without needing Azure Monitor Agent (AMA), WAD, or Data Collection Rules (DCR)."
        }

    async def _handle_get_advisor_recommendations(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        client = await ctx.get_azure_client()
        if not client:
            return {"success": False, "error": "No active Azure connection in workspace."}

        sub_filter = args.get("subscription_id")
        target_subs = [sub_filter] if sub_filter else ctx.get_authorized_subscription_ids()
        validated_subs = FinSecOpsGuardrails.validate_subscription_access(target_subs, ctx.subscriptions)
        category_filter = args.get("category")

        recommendations = []
        for sid in validated_subs:
            sub_name = ctx.get_subscription_display_name(sid)
            url = f"https://management.azure.com/subscriptions/{sid}/providers/Microsoft.Advisor/recommendations?api-version=2020-01-01"
            if category_filter:
                url += f"&$filter=Category eq '{category_filter}'"

            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    for rec in resp.json().get("value", [])[:20]:
                        props = rec.get("properties", {})
                        recommendations.append({
                            "subscription_id": sid,
                            "subscription_name": sub_name,
                            "category": props.get("category"),
                            "impact": props.get("impact"),
                            "short_description": props.get("shortDescription", {}).get("solution"),
                            "impacted_field": props.get("impactedField"),
                            "impacted_value": props.get("impactedValue")
                        })
            except Exception as ex:
                logger.warning(f"Error querying Advisor for {sid}: {ex}")

        return {
            "success": True,
            "recommendations": recommendations,
            "total_count": len(recommendations),
            "is_live_data": True,
            "source": "Azure Advisor API"
        }

    async def _handle_get_network_topology(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        client = await ctx.get_azure_client()
        if not client:
            return {"success": False, "error": "No active Azure connection in workspace."}

        sub_filter = args.get("subscription_id")
        target_subs = [sub_filter] if sub_filter else ctx.get_authorized_subscription_ids()
        validated_subs = FinSecOpsGuardrails.validate_subscription_access(target_subs, ctx.subscriptions)

        public_ips_list = []
        for sid in validated_subs:
            sub_name = ctx.get_subscription_display_name(sid)
            try:
                pips = await NetworkAdapter.get_public_ips(client, sid)
                for pip in pips:
                    props = pip.get("properties", {})
                    public_ips_list.append({
                        "name": pip.get("name"),
                        "subscription_id": sid,
                        "subscription_name": sub_name,
                        "ip_address": props.get("ipAddress", "Dynamic/Unassigned"),
                        "allocation_method": props.get("publicIPAllocationMethod"),
                        "is_assigned": props.get("ipConfiguration") is not None,
                        "associated_to": props.get("ipConfiguration", {}).get("id", "Unassociated")
                    })
            except Exception as ex:
                logger.warning(f"Error querying network topology for {sid}: {ex}")

        return {
            "success": True,
            "public_ips": public_ips_list,
            "total_public_ips": len(public_ips_list),
            "unassociated_public_ips": sum(1 for p in public_ips_list if not p["is_assigned"]),
            "is_live_data": True,
            "source": "Azure Virtual Network / PublicIPAddresses API"
        }

    async def _handle_assessment_summary(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        summary = ctx.cumulative_summary or {}
        results = ctx.cumulative_results or {}

        if not summary and not results:
            return {
                "success": True,
                "has_executed_assessments": False,
                "message": (
                    f"No assessment scans have been executed in current workspace '{ctx.workspace_name}' yet. "
                    "Use 'Run All Assessments' or 'Run Security Assessment' on the execution bar to run multi-pillar scans."
                ),
                "is_historical_assessment": True
            }

        sec_score = summary.get("current_security_score") or summary.get("security_score")
        baseline = summary.get("baseline_security_score")
        achievable = summary.get("achievable_security_score")
        annual_savings = summary.get("total_annual_savings", 0.0) or summary.get("unique_annual_savings", 0.0)
        monthly_savings = summary.get("total_monthly_savings", 0.0) or summary.get("unique_monthly_savings", 0.0)
        total_findings = summary.get("total_findings", 0)

        # Evaluated modules summary
        evaluated_modules = []
        for ass_id, res in results.items():
            if isinstance(res, dict):
                evaluated_modules.append({
                    "module_id": ass_id,
                    "code": res.get("code", ass_id),
                    "name": res.get("name", ass_id),
                    "category": res.get("category", "unknown"),
                    "status": res.get("status", "Completed"),
                    "findings_count": res.get("findings_count", len(res.get("findings", []))),
                    "savings_annual": res.get("savings_annual", 0.0),
                    "score_improvement": res.get("security_score_improvement", 0.0)
                })
            else:
                evaluated_modules.append({
                    "module_id": ass_id,
                    "code": getattr(res, "code", ass_id),
                    "name": getattr(res, "name", ass_id),
                    "category": getattr(res, "category", "unknown"),
                    "status": getattr(res, "status", "Completed"),
                    "findings_count": getattr(res, "findings_count", 0),
                    "savings_annual": getattr(res, "savings_annual", 0.0),
                    "score_improvement": getattr(res, "security_score_improvement", 0.0)
                })

        return {
            "success": True,
            "has_executed_assessments": True,
            "workspace_name": ctx.workspace_name,
            "currency": ctx.currency,
            "current_security_score": sec_score,
            "baseline_security_score": baseline,
            "achievable_security_score": achievable,
            "total_annual_savings": annual_savings,
            "total_monthly_savings": monthly_savings,
            "total_findings": total_findings,
            "critical_findings": summary.get("critical_findings", 0),
            "high_findings": summary.get("high_findings", 0),
            "medium_findings": summary.get("medium_findings", 0),
            "low_findings": summary.get("low_findings", 0),
            "evaluated_modules_count": len(evaluated_modules),
            "evaluated_modules": evaluated_modules,
            "is_historical_assessment": True,
            "source": "FinSecOps Session Assessment Engine"
        }

    async def _handle_assessment_findings(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        results = ctx.cumulative_results or {}
        if not results:
            return {
                "success": True,
                "findings": [],
                "total_count": 0,
                "message": "No assessment findings available in current session."
            }

        cat_filter = (args.get("category") or "all").lower()
        sev_filter = (args.get("severity") or "").capitalize()
        mod_filter = args.get("module_id")
        limit = args.get("limit", 25)

        collected = []
        for ass_id, res in results.items():
            if mod_filter and mod_filter.lower() not in ass_id.lower():
                continue

            findings = (res.get("findings", []) if isinstance(res, dict) else getattr(res, "findings", [])) or []
            for f in findings:
                is_dict = isinstance(f, dict)
                f_cat = (f.get("category", "unknown") if is_dict else getattr(f, "category", "unknown")).lower()
                f_sev = f.get("severity", "Medium") if is_dict else getattr(f, "severity", "Medium")

                if cat_filter != "all" and f_cat != cat_filter:
                    continue
                if sev_filter and f_sev != sev_filter:
                    continue

                collected.append({
                    "assessment_id": ass_id,
                    "category": f_cat,
                    "severity": f_sev,
                    "resource_name": f.get("resource_name", "Unknown") if is_dict else getattr(f, "resource_name", "Unknown"),
                    "resource_type": f.get("resource_type", "") if is_dict else getattr(f, "resource_type", ""),
                    "subscription_name": f.get("subscription_name", "") if is_dict else getattr(f, "subscription_name", ""),
                    "recommendation": f.get("recommendation", "") if is_dict else getattr(f, "recommendation", ""),
                    "annual_savings": f.get("estimated_annual_savings", 0.0) if is_dict else getattr(f, "estimated_annual_savings", 0.0),
                    "monthly_savings": f.get("estimated_monthly_savings", 0.0) if is_dict else getattr(f, "estimated_monthly_savings", 0.0),
                    "confidence": f.get("confidence", "High") if is_dict else getattr(f, "confidence", "High")
                })

        return {
            "success": True,
            "findings": collected[:limit],
            "total_matching": len(collected),
            "filters_applied": {
                "category": cat_filter,
                "severity": sev_filter or None,
                "module_id": mod_filter
            },
            "is_historical_assessment": True,
            "source": "FinSecOps Assessment Database/Session"
        }

        return {
            "success": True,
            "findings": collected[:limit],
            "total_matching": len(collected),
            "filters_applied": {
                "category": cat_filter,
                "severity": sev_filter or None,
                "module_id": mod_filter
            },
            "is_historical_assessment": True,
            "source": "FinSecOps Assessment Database/Session"
        }

    async def _handle_generate_report(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        report_type = args.get("report_type", "combined_pdf")
        
        # Check active session reports in app.py / session_store
        import uuid
        from app.reports.pdf.security_pdf import generate_security_pdf
        from app.reports.pdf.cost_pdf import generate_cost_pdf
        from app.reports.pdf.combined_pdf import generate_combined_pdf
        from app.reports.excel.security_excel import generate_security_excel
        from app.reports.excel.cost_excel import generate_cost_excel
        from app.reports.excel.combined_excel import generate_combined_excel

        summary = ctx.cumulative_summary or {}
        results = ctx.cumulative_results or {}
        ws_name = ctx.workspace_name
        curr = ctx.currency

        try:
            if report_type == "security_pdf":
                raw_bytes = generate_security_pdf(summary, results, ws_name)
                mime = "application/pdf"
                fname = f"Azure_FinSecOps_Security_Report_{ws_name.replace(' ', '_')}.pdf"
            elif report_type == "cost_pdf":
                raw_bytes = generate_cost_pdf(summary, results, ws_name, curr)
                mime = "application/pdf"
                fname = f"Azure_FinSecOps_Cost_Report_{ws_name.replace(' ', '_')}.pdf"
            elif report_type == "combined_excel":
                raw_bytes = generate_combined_excel(summary, results, ws_name, curr)
                mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                fname = f"Azure_FinSecOps_Executive_Report_{ws_name.replace(' ', '_')}.xlsx"
            elif report_type == "security_excel":
                raw_bytes = generate_security_excel(summary, results, ws_name)
                mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                fname = f"Azure_FinSecOps_Security_Matrix_{ws_name.replace(' ', '_')}.xlsx"
            elif report_type == "cost_excel":
                raw_bytes = generate_cost_excel(summary, results, ws_name, curr)
                mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                fname = f"Azure_FinSecOps_Cost_Matrix_{ws_name.replace(' ', '_')}.xlsx"
            else: # combined_pdf
                raw_bytes = generate_combined_pdf(summary, results, ws_name, curr)
                mime = "application/pdf"
                fname = f"Azure_FinSecOps_Executive_Report_{ws_name.replace(' ', '_')}.pdf"

            # Register in Flask/FastAPI report store
            report_id = str(uuid.uuid4())
            
            # Store in Flask global REPORTS if available
            try:
                import sys
                flask_main = sys.modules.get("flask_main") or sys.modules.get("__main__")
                if flask_main and hasattr(flask_main, "REPORTS") and hasattr(flask_main, "STORE_LOCK"):
                    with flask_main.STORE_LOCK:
                        flask_main.REPORTS[report_id] = {
                            "bytes": raw_bytes,
                            "filename": fname,
                            "content_type": mime,
                            "created_at": datetime.datetime.now().isoformat()
                        }
            except Exception:
                pass

            download_url = f"/api/reports/download/{report_id}"
            return {
                "success": True,
                "report_id": report_id,
                "filename": fname,
                "download_url": download_url,
                "content_type": mime,
                "size_bytes": len(raw_bytes),
                "message": f"Successfully compiled '{fname}'. Download is ready.",
                "is_report_deliverable": True
            }
        except Exception as ex:
            return {"success": False, "error": f"Failed to generate report deliverable: {str(ex)}"}

    async def _handle_search_knowledge(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        query = args.get("query", "")
        docs = CloudKnowledgeBase.search(query, max_results=3)
        return {
            "success": True,
            "query": query,
            "documents": docs,
            "source": "Microsoft Learn & Azure Architecture Center (Knowledge Base)"
        }

    async def _handle_generic_arm_query(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        client = await ctx.get_azure_client()
        if not client:
            return {
                "success": False,
                "error": "No active Azure connection in this workspace. Please connect using your Tenant ID and Service Principal."
            }

        authorized_subs = ctx.get_authorized_subscription_ids()
        if not authorized_subs:
            return {"success": False, "error": "No authorized Azure subscriptions in active workspace context."}

        target_sub = args.get("subscription_id") or authorized_subs[0]
        try:
            validated_subs = FinSecOpsGuardrails.validate_subscription_access([target_sub], ctx.subscriptions)
            sub_id = validated_subs[0]
        except SecurityPolicyViolationError as sve:
            return {"success": False, "error": str(sve), "is_security_violation": True}

        rel_path = str(args.get("relative_path") or "").strip()
        if not rel_path.startswith("/"):
            rel_path = f"/{rel_path}"

        if rel_path.lower().startswith("/subscriptions/"):
            url = f"https://management.azure.com{rel_path}"
        else:
            url = f"https://management.azure.com/subscriptions/{sub_id}{rel_path}"

        params: Dict[str, str] = {}
        api_ver = args.get("api_version")
        if api_ver:
            params["api-version"] = str(api_ver).strip()
        elif "api-version" not in url.lower():
            params["api-version"] = "2021-04-01"

        query_params = args.get("query_params") or {}
        if isinstance(query_params, dict):
            for k, v in query_params.items():
                params[k] = str(v)

        try:
            resp = await client.execute_request("GET", url, params=params if params and "?" not in url else None)
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("value") if isinstance(data, dict) and "value" in data else data
                item_count = len(items) if isinstance(items, list) else 1
                return {
                    "success": True,
                    "subscription_id": sub_id,
                    "target_url": url,
                    "count": item_count,
                    "data": items,
                    "source": "Azure Resource Manager REST API"
                }
            return {
                "success": False,
                "error": f"Azure ARM returned HTTP {resp.status_code}: {resp.text[:300]}",
                "status_code": resp.status_code
            }
        except Exception as ex:
            return {"success": False, "error": f"ARM query execution failed: {str(ex)}"}

    async def _handle_run_assessment_module(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        client = await ctx.get_azure_client()
        if not client:
            return {
                "success": False,
                "error": "No active Azure connection in this workspace. Please connect using your Tenant ID and Service Principal."
            }

        from app.assessments.registry import assessment_registry
        from app.assessments.base import AssessmentContext

        assessment_id = str(args.get("assessment_id") or "").strip().lower()
        ass = assessment_registry.get_assessment(assessment_id)
        if not ass:
            available = [a.assessment_id for a in assessment_registry.get_all_assessments()]
            return {
                "success": False,
                "error": f"Assessment '{assessment_id}' not found. Available modules: {', '.join(available[:10])}..."
            }

        target_subs = args.get("target_subscription_ids") or []
        validated_subs = FinSecOpsGuardrails.validate_subscription_access(target_subs, ctx.subscriptions)
        sub_models = [s for s in ctx.subscriptions if getattr(s, "subscription_id", None) in validated_subs or (isinstance(s, dict) and s.get("subscription_id") in validated_subs)]

        assessment_ctx = AssessmentContext(
            connection_id=ctx.connection_data.get("connection_id", "live-query"),
            workspace_name=ctx.workspace_name,
            tenant_id=ctx.tenant_id or "",
            subscriptions=sub_models,
            client=client,
            currency=ctx.currency
        )

        try:
            res = await ass.run(assessment_ctx)
            top_findings = [f.model_dump() if hasattr(f, "model_dump") else str(f) for f in res.findings[:8]]
            return {
                "success": True,
                "assessment_id": res.assessment_id,
                "code": res.code,
                "category": res.category,
                "name": res.name,
                "status": res.status.value if hasattr(res.status, "value") else str(res.status),
                "findings_count": res.findings_count,
                "resources_evaluated": res.resources_evaluated,
                "execution_time_seconds": res.execution_time_seconds,
                "sample_findings": top_findings,
                "source": f"Live FinSecOps Assessment Engine ({res.code} - {res.name})"
            }
        except Exception as ex:
            return {"success": False, "error": f"Assessment execution failed: {str(ex)}"}

    async def _handle_dynamic_investigation(self, args: Dict[str, Any], ctx: ToolExecutionContext) -> Dict[str, Any]:
        client = await ctx.get_azure_client()
        if not client:
            return {
                "success": False,
                "error": "No active Azure connection in this workspace. Please connect using your Tenant ID and Service Principal."
            }

        focus_area = str(args.get("focus_area") or "").strip()
        scope_type = str(args.get("scope_type") or "custom_kql").lower()
        scope_filter = str(args.get("scope_filter") or "").strip()

        authorized_subs = ctx.get_authorized_subscription_ids()
        if not authorized_subs:
            return {"success": False, "error": "No authorized Azure subscriptions in active workspace context."}

        focus_lower = focus_area.lower()
        if "rg" in focus_lower or "resource group" in focus_lower or scope_type == "resource_group":
            rg_name = scope_filter or focus_area.replace("resource group", "").replace("rg", "").strip().strip("'-_ ")
            kql = f"resources | where resourceGroup =~ '{rg_name}' | project id, name, type, location, tags, properties"
        elif "key vault" in focus_lower or "vault" in focus_lower:
            kql = "resources | where type =~ 'microsoft.keyvault/vaults' | project id, name, type, location, properties"
        elif "sql" in focus_lower or "database" in focus_lower:
            kql = "resources | where type in~ ('microsoft.sql/servers', 'microsoft.sql/servers/databases', 'microsoft.dbforpostgresql/flexibleservers', 'microsoft.dbformysql/flexibleservers') | project id, name, type, location, sku, properties"
        elif "aks" in focus_lower or "kubernetes" in focus_lower or "container" in focus_lower:
            kql = "resources | where type in~ ('microsoft.containerservice/managedclusters', 'microsoft.containerinstance/containergroups') | project id, name, type, location, properties"
        elif "public ip" in focus_lower or "network" in focus_lower:
            kql = "resources | where type in~ ('microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/applicationgateways', 'microsoft.network/loadbalancers') | project id, name, type, location, properties"
        else:
            kql = f"resources | where name contains '{focus_area}' or type contains '{focus_area}' or resourceGroup contains '{focus_area}' | take 50 | project id, name, type, resourceGroup, location, properties"

        rg_result = await self._handle_resource_graph_query({"query": kql}, ctx)
        discovered_resources = rg_result.get("data", []) if rg_result.get("success") else []

        adv_result = await self._handle_advisor_recommendations({}, ctx)
        advisor_recs = adv_result.get("recommendations", []) if adv_result.get("success") else []
        matching_advisor = [r for r in advisor_recs if any(term in str(r).lower() for term in [focus_lower, scope_filter.lower()])][:5]

        def_result = await self._handle_defender_posture({"scope": "assessments"}, ctx)
        defender_findings = def_result.get("assessments", []) if def_result.get("success") else []
        matching_defender = [d for d in defender_findings if any(term in str(d).lower() for term in [focus_lower, scope_filter.lower()])][:5]

        return {
            "success": True,
            "investigation_focus": focus_area,
            "scope_type": scope_type,
            "resources_found_count": len(discovered_resources),
            "discovered_resources": discovered_resources[:20],
            "correlated_advisor_recommendations": matching_advisor,
            "correlated_defender_assessments": matching_defender,
            "source": "Dynamic Cloud Investigation Agent (ARG + Advisor + Defender)"
        }

# Global singleton instance of tool registry
tool_registry = ToolRegistry()
