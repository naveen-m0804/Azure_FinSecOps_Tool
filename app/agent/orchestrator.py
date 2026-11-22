"""
FinSecOps Agent Orchestrator
Central intelligence coordinator managing intent classification, scope enforcement,
conversation memory, Groq multi-step tool execution, and rich response presentation.
"""
import os
import re
import json
import time
import datetime
import logging
from typing import Dict, Any, List, Optional

from app.core.config import settings
from app.agent.guardrails import FinSecOpsGuardrails, SecurityPolicyViolationError
from app.agent.provider import get_ai_provider, BaseLLMProvider, AIProviderError, GroqProviderError
from app.agent.tools.registry import tool_registry, ToolExecutionContext

logger = logging.getLogger("azure_finsecops.agent.orchestrator")

class FinSecOpsAgentOrchestrator:
    # 10 Logical Intent Categories
    INTENT_AZURE_LIVE_QUERY = "AZURE_LIVE_QUERY"
    INTENT_AZURE_ENVIRONMENT_ANALYSIS = "AZURE_ENVIRONMENT_ANALYSIS"
    INTENT_FINOPS_ANALYSIS = "FINOPS_ANALYSIS"
    INTENT_SECOPS_ANALYSIS = "SECOPS_ANALYSIS"
    INTENT_ASSESSMENT_REPORT_QUERY = "ASSESSMENT_REPORT_QUERY"
    INTENT_REPORT_GENERATION = "REPORT_GENERATION"
    INTENT_AZURE_REMEDIATION_GUIDANCE = "AZURE_REMEDIATION_GUIDANCE"
    INTENT_CLOUD_TECHNOLOGY_KNOWLEDGE = "CLOUD_TECHNOLOGY_KNOWLEDGE"
    INTENT_CLARIFICATION_REQUIRED = "CLARIFICATION_REQUIRED"
    INTENT_OUT_OF_SCOPE = "OUT_OF_SCOPE"

    @classmethod
    def classify_intent(cls, user_message: str, has_connection: bool = False) -> str:
        """
        Dynamically classifies user intent into one of the 10 logical categories.
        Uses semantic indicators rather than fixed keyword mappings.
        """
        if not FinSecOpsGuardrails.is_in_scope(user_message):
            return cls.INTENT_OUT_OF_SCOPE

        msg_lower = user_message.lower().strip()

        # How-to & Remediation guidance intent
        how_to_patterns = [
            "how to", "how do i", "how can i", "steps to", "guide to",
            "how to create", "how to configure", "how to implement", "how to enable", "how to set up",
            "how to fix", "how to remediate", "remediation steps", "step by step", "how to secure"
        ]
        if any(p in msg_lower for p in how_to_patterns):
            return cls.INTENT_AZURE_REMEDIATION_GUIDANCE

        # Report generation intent
        if any(w in msg_lower for w in ["generate report", "download report", "export report", "create report", "produce report", "pdf report", "excel report"]):
            return cls.INTENT_REPORT_GENERATION

        # Assessment report query intent
        if any(w in msg_lower for w in [
            "latest assessment", "assessment report", "previous assessment", "assessment findings",
            "my findings", "score of current", "posture score", "overall score", "security score",
            "secure score", "my score", "current score", "currert score", "assessment results"
        ]):
            return cls.INTENT_ASSESSMENT_REPORT_QUERY

        # FinOps analysis intent
        if any(w in msg_lower for w in ["spending", "savings", "budget", "expensive", "finops", "underutilized", "orphan", "downsize"]) or re.search(r'\bcost\b', msg_lower):
            return cls.INTENT_FINOPS_ANALYSIS

        # SecOps analysis intent
        if any(w in msg_lower for w in ["security", "defender", "vulnerability", "attack path", "unencrypted", "public access", "firewall", "tls", "secops"]):
            return cls.INTENT_SECOPS_ANALYSIS

        # Azure Live Query vs Environment Analysis (use regex word boundaries to avoid 'account' matching 'count')
        live_patterns = r'\b(list|show|get all|inventory|which vms|which storage|instances|virtual machines)\b'
        if re.search(live_patterns, msg_lower) or (re.search(r'\bcount\b', msg_lower) and not re.search(r'\baccount\b', msg_lower)):
            return cls.INTENT_AZURE_LIVE_QUERY

        if any(w in msg_lower for w in ["architecture of my", "analyze my tenant", "posture of my environment", "compliance of my"]):
            return cls.INTENT_AZURE_ENVIRONMENT_ANALYSIS

        # General Cloud Knowledge
        return cls.INTENT_CLOUD_TECHNOLOGY_KNOWLEDGE

    @classmethod
    def _build_system_prompt(cls, ctx: ToolExecutionContext, has_connection: bool) -> str:
        """
        Constructs the comprehensive system instruction for the all-rounder agentic AI engine.
        Seamlessly balances:
        1. Fast in-memory session assessment data (instant response, zero redundant latency)
        2. Live read-only Azure API/Resource Graph tools (dynamic cloud querying)
        3. Architectural best practice knowledge and hands-on remediation guidance
        """
        ws_name = ctx.workspace_name
        subs = ctx.subscriptions
        sub_count = len(subs)
        sub_names = [getattr(s, "display_name", None) or (s.get("display_name") if isinstance(s, dict) else str(s)) for s in subs[:6]]
        sub_list_str = ", ".join(sub_names) if sub_names else "None connected"
        if len(subs) > 6:
            sub_list_str += f" and {len(subs) - 6} more"

        summary = ctx.cumulative_summary or {}
        results = ctx.cumulative_results or {}

        sec_score = summary.get("current_security_score") or summary.get("security_score")
        achievable_score = summary.get("achievable_security_score")
        annual_sav = summary.get("total_annual_savings", 0.0) or summary.get("unique_annual_savings", 0.0)
        monthly_sav = summary.get("total_monthly_savings", 0.0) or summary.get("unique_monthly_savings", 0.0)
        findings_count = summary.get("total_findings", 0)
        sev_counts = summary.get("security_severity_counts") or summary.get("findings_by_severity") or {}
        crit_count = sev_counts.get("Critical", 0)
        high_count = sev_counts.get("High", 0)
        med_count = sev_counts.get("Medium", 0)
        low_count = sev_counts.get("Low", 0)

        # Evaluated modules summary from session
        modules_summary = []
        for aid, res in results.items():
            if isinstance(res, dict):
                code = res.get("code", aid)
                name = res.get("name", aid)
                cat = res.get("category", "")
                f_count = res.get("findings_count", len(res.get("findings", [])))
                sav = res.get("savings_annual", 0.0)
                status = res.get("status", "Completed")
            else:
                code = getattr(res, "code", aid)
                name = getattr(res, "name", aid)
                cat = getattr(res, "category", "")
                f_count = getattr(res, "findings_count", 0)
                sav = getattr(res, "savings_annual", 0.0)
                status = getattr(res, "status", "Completed")

            line = f"- [{code}] {name} ({cat.upper()}): {status} | {f_count} finding(s)"
            if sav > 0:
                line += f" | ${sav:,.2f}/yr savings"
            modules_summary.append(line)

        prompt_lines = [
            "You are FinSecOps AI, an autonomous, highly specialized, all-rounder agentic AI assistant for Microsoft Azure FinOps, SecOps, and Cloud Architecture.",
            "You operate with STRICT READ-ONLY access to the customer's authenticated Azure environment.",
            "",
            "### CURRENT WORKSPACE & SESSION CONTEXT:",
            f"- Workspace Name: {ws_name}",
            f"- Azure Connected: {'YES' if has_connection else 'NO (No live Azure connection established yet)'}",
            f"- Accessible Subscriptions ({sub_count}): {sub_list_str}",
            f"- Default Currency: {ctx.currency}"
        ]

        if results or summary:
            prompt_lines.append("\n### ACTIVE SESSION ASSESSMENT POSTURE (Already Evaluated in Memory):")
            if sec_score is not None:
                ach_txt = f" (Potential Achievable: {achievable_score:.0f}%)" if achievable_score else ""
                prompt_lines.append(f"- Microsoft Defender Overall Secure Score: {sec_score:.0f}%{ach_txt}")
            if annual_sav > 0 or monthly_sav > 0:
                prompt_lines.append(f"- Identified FinOps Savings: ${annual_sav:,.2f}/yr (${monthly_sav:,.2f}/month)")
            if findings_count > 0:
                prompt_lines.append(
                    f"- Identified Findings: {findings_count} items (Critical: {crit_count}, High: {high_count}, Medium: {med_count}, Low: {low_count})"
                )
            if modules_summary:
                prompt_lines.append(f"- Evaluated Assessment Modules ({len(modules_summary)}):")
                prompt_lines.extend(modules_summary[:15])

        prompt_lines.extend([
            "",
            "### CORE ALL-ROUNDER RESOLUTION ENGINE:",
            "1. TIER 1 - SESSION-FIRST RESOLUTION (Zero-Latency, Instant Response):",
            "   - If the user asks about security score, assessment posture, detected findings, or cost savings that have ALREADY been evaluated in the active session (see ACTIVE SESSION ASSESSMENT POSTURE above):",
            "     * ANSWER IMMEDIATELY and accurately from the session posture data (or call `assessment_get_findings` / `assessment_get_summary` if deep filtering is needed).",
            "     * Do NOT execute slow, redundant live Azure network queries when the authoritative answer was already computed in this session!",
            "     * Explicitly cite the provenance: e.g. '[Active Workspace Session Assessment]'.",
            "2. TIER 2 - DYNAMIC LIVE AZURE QUERIES (On-Demand Cloud Discovery):",
            "   - If the user asks for:",
            "     * Specific live resource inventories (e.g. 'list all VMs', 'show stopped VMs', 'find storage accounts with public access', 'list NSGs', 'show public IPs')",
            "     * Live metrics (e.g. CPU/network metrics)",
            "     * Real-time live cost analysis from Cost Management API",
            "     * Live Microsoft Defender re-evaluation (e.g. 'query live Defender from Azure now', 'refresh live score')",
            "     * OR any assessment or area that has NOT yet been run in this session:",
            "     * DYNAMICALLY SELECT and execute the appropriate live read-only tool (`azure_get_defender_security_posture`, `azure_get_vm_inventory`, `azure_get_storage_accounts`, `azure_get_cost_analysis`, `azure_resource_graph_query`, `azure_get_network_topology`, `azure_get_resource_metrics`, `azure_get_advisor_recommendations`).",
            "     * Explicitly cite the provenance: e.g. '[Live Azure Query]'.",
            "3. TIER 3 - GENERAL CLOUD ARCHITECTURE & HOW-TO GUIDANCE:",
            "   - For general architectural questions or how-to remediation instructions (e.g. 'How to create an LCM rule for blob storage', 'Explain private endpoints vs service endpoints', 'How to remediate unencrypted disks'):",
            "     * Provide authoritative, step-by-step guidance with Azure Portal instructions, Azure CLI / PowerShell scripts, or Terraform snippets directly.",
            "     * Do NOT execute live resource discovery tools unless the user specifically asks to inspect their resources.",
            "4. STRICT READ-ONLY ENFORCEMENT: You CANNOT modify, create, stop, start, restart, or delete Azure resources. If asked to remediate or delete, explain your read-only role, assess the risks, and give safe, step-by-step instructions.",
            "5. NO HARDCODED OR DUMMY DATA: All numbers and resource names must come from the actual session assessment data or live Azure queries. Never fabricate resource names or metrics."
        ])

        if not has_connection:
            prompt_lines.append(
                "\nNOTE: If the user asks for live Azure data (e.g. 'list my VMs') and no Azure connection exists, "
                "inform them that they must connect to their Azure tenant using the connection interface."
            )

        return "\n".join(prompt_lines)

    @classmethod
    async def process_request(
        cls,
        user_message: str,
        connection_data: Optional[Dict[str, Any]] = None,
        chat_history: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Main Agentic AI Execution Pipeline:
        1. Scope & Policy check.
        2. Intent classification.
        3. Context preparation & Tool schema injection.
        4. Multi-step tool execution loop with Groq.
        5. Response validation, step recording, and presentation formatting.
        """
        clean_query = (user_message or "").strip()
        if not clean_query:
            return {
                "reply": "Please enter a question or instruction related to Azure infrastructure, FinOps, or security.",
                "intent": cls.INTENT_CLARIFICATION_REQUIRED,
                "steps": [],
                "sources": [],
                "is_policy_blocked": False
            }

        # 1. SCOPE POLICY ENFORCEMENT
        if not FinSecOpsGuardrails.is_in_scope(clean_query):
            logger.info(f"Query blocked by FinSecOps Usage Policy: '{clean_query[:80]}'")
            return {
                "reply": FinSecOpsGuardrails.USAGE_POLICY_MESSAGE,
                "intent": cls.INTENT_OUT_OF_SCOPE,
                "steps": [],
                "sources": ["FinSecOps Security Policy Engine"],
                "is_policy_blocked": True,
                "is_live_data": False
            }

        # 2. CONTEXT & INTENT
        ctx = ToolExecutionContext(connection_data)
        has_connection = bool(ctx.tenant_id and ctx.client_id and ctx.client_secret)
        intent = cls.classify_intent(clean_query, has_connection)

        # Handle simple greetings without consuming LLM credits
        if clean_query.lower() in ["hi", "hello", "hey", "greetings"] or (clean_query.lower().startswith("hello") and len(clean_query.split()) <= 2):
            sub_count = len(ctx.subscriptions)
            greeting = (
                f"Hello! I am your **FinSecOps Agentic AI** connected to **{ctx.workspace_name}** "
                f"({sub_count} active subscription(s)).\n\n"
                "I dynamically query your live Azure tenant, evaluate FinSecOps assessment findings, and provide cloud architectural guidance. You can ask me:\n"
                "- **Live Azure Queries**: *'List all VMs in my Azure environment'*, *'Show stopped VMs'*, *'List storage accounts and check public access'*, *'Show public IPs'*\n"
                "- **FinOps Analysis**: *'Why has my Azure cost increased?'*, *'Which resources have the highest spend?'*, *'Find orphan disks and underutilized instances'*\n"
                "- **SecOps & Defender**: *'What is my Defender secure score?'*, *'Show critical security recommendations'*, *'How to secure storage accounts?'*\n"
                "- **Reports & Assessments**: *'Summarize my latest assessment report'*, *'Generate a combined executive PDF report'*\n"
                "- **Cloud Architecture**: *'Explain the difference between a private endpoint and a service endpoint'*."
            )
            return {
                "reply": greeting,
                "intent": cls.INTENT_CLOUD_TECHNOLOGY_KNOWLEDGE,
                "steps": [],
                "sources": ["FinSecOps Agent Orchestrator"],
                "is_policy_blocked": False,
                "is_live_data": False
            }

        # Initialize Active Multi-Provider LLM
        provider = get_ai_provider()
        if not provider.is_configured():
            # API key not configured yet for the selected provider
            missing_key_msg = provider.get_config_guidance()
            return {
                "reply": missing_key_msg,
                "intent": intent,
                "steps": [],
                "sources": [f"{provider.get_provider_name()} Configuration Engine"],
                "is_policy_blocked": False,
                "is_live_data": False
            }

        # 3. BUILD CONVERSATION TURN ARRAY WITH CONVERSATION MEMORY
        system_prompt = cls._build_system_prompt(ctx, has_connection)
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": system_prompt}
        ]

        # Append last 6 history items for context resolution (e.g. "which of them are stopped", "secure those VMs")
        if chat_history:
            for item in chat_history[-6:]:
                role = item.get("role") or item.get("sender", "user")
                if role in ["assistant", "ai", "bot"]:
                    role = "assistant"
                else:
                    role = "user"
                content = item.get("content") or item.get("text") or ""
                if content and isinstance(content, str):
                    # Strip huge tables from historical context to protect token budget
                    trimmed_content = content[:1500]
                    messages.append({"role": role, "content": trimmed_content})

        messages.append({"role": "user", "content": clean_query})

        # 4. TOOL-CALLING MULTI-STEP EXECUTION LOOP
        tool_schemas = tool_registry.get_tool_schemas()
        execution_steps: List[Dict[str, Any]] = []
        sources_used: set = set()
        max_tool_iterations = settings.ai_max_tool_calls
        iteration = 0
        final_reply = ""
        total_tokens_used = 0

        while iteration < max_tool_iterations:
            iteration += 1
            t_start = time.time()

            try:
                response = await provider.chat_completion(
                    messages=messages,
                    tools=tool_schemas,
                    tool_choice="auto"
                )
            except (AIProviderError, GroqProviderError) as gpe:
                logger.error(f"{provider.get_provider_name()} error on iteration {iteration}: {gpe}")
                return {
                    "reply": f"### ⚠️ AI Inference Error ({provider.get_provider_name()})\n\n{str(gpe)}",
                    "intent": intent,
                    "steps": execution_steps,
                    "sources": list(sources_used),
                    "is_policy_blocked": False,
                    "is_live_data": False
                }

            # Track tokens
            usage = response.get("usage", {})
            total_tokens_used += usage.get("total_tokens", 0)

            msg = response.get("message", {})
            tool_calls = msg.get("tool_calls")

            # If no tool calls requested, we have the final answer!
            if not tool_calls:
                final_reply = msg.get("content") or ""
                break

            # Model requested one or more tool calls
            messages.append(msg)

            for tc in tool_calls:
                tc_id = tc.get("id", f"call_{iteration}")
                fn = tc.get("function", {})
                tool_name = fn.get("name", "")
                raw_args = fn.get("arguments", "{}")

                try:
                    args_dict = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                except Exception:
                    args_dict = {}

                step_entry = {
                    "step_number": len(execution_steps) + 1,
                    "tool_name": tool_name,
                    "status": "Running",
                    "timestamp": datetime.datetime.now().strftime("%H:%M:%S")
                }

                # Execute tool
                tool_result = await tool_registry.execute_tool(tool_name, args_dict, ctx)
                duration_ms = int((time.time() - t_start) * 1000)

                if tool_result.get("success"):
                    step_entry["status"] = "Success"
                    step_entry["duration_ms"] = duration_ms
                    src = tool_result.get("source", "Azure API")
                    sources_used.add(src)
                    step_entry["source"] = src
                    step_entry["summary"] = f"Retrieved data from {src}"
                else:
                    step_entry["status"] = "Failed"
                    step_entry["error"] = tool_result.get("error")
                    step_entry["summary"] = f"Execution failed: {tool_result.get('error', 'Unknown error')}"

                execution_steps.append(step_entry)

                # Return tool result to conversation array
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "name": tool_name,
                    "content": json.dumps(tool_result)
                })

        # Sanitize any secrets/tokens in final reply
        sanitized_reply = FinSecOpsGuardrails.sanitize_credentials(final_reply)

        # Contextual follow-up recommendations
        suggested_followups = cls._generate_followups(intent, clean_query, has_connection)

        return {
            "reply": sanitized_reply or "Analysis complete.",
            "intent": intent,
            "steps": execution_steps,
            "sources": list(sources_used) if sources_used else ["FinSecOps Technical Knowledge"],
            "is_live_data": any("Live" in s or "ARG" in s or "ARM" in s for s in sources_used),
            "is_policy_blocked": False,
            "tokens_used": total_tokens_used,
            "suggested_followups": suggested_followups
        }

    @classmethod
    def _generate_followups(cls, intent: str, query: str, has_connection: bool) -> List[str]:
        q_lower = query.lower()
        if "vm" in q_lower or "virtual machine" in q_lower:
            return [
                "Which of these VMs are currently deallocated or stopped?",
                "How can I set up daily auto-shutdown to cut compute costs?",
                "Show CPU utilization metrics for these machines"
            ]
        if "storage" in q_lower:
            return [
                "Which storage accounts have public network access enabled?",
                "How do I configure Lifecycle Management (LCM) rules to archive old blobs?",
                "Check data encryption and TLS versions on these accounts"
            ]
        if "cost" in q_lower or intent == cls.INTENT_FINOPS_ANALYSIS:
            return [
                "Which specific Azure services contribute the highest spend?",
                "What cost savings recommendations does Azure Advisor suggest?",
                "Generate a detailed FinOps cost optimization report"
            ]
        if "security" in q_lower or intent == cls.INTENT_SECOPS_ANALYSIS:
            return [
                "Explain the top critical security recommendations in simple terms",
                "What is the step-by-step remediation procedure for unencrypted disks?",
                "Show network security groups with exposed inbound ports"
            ]
        return [
            "List all VMs and their current power states",
            "Explain my latest security assessment findings",
            "Generate an executive combined FinSecOps report"
        ]
