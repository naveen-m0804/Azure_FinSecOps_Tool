import re
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("azure_finsecops.agent.guardrails")

class SecurityPolicyViolationError(Exception):
    """Raised when an operation violates the FinSecOps read-only or authorization guardrails."""
    pass

class FinSecOpsGuardrails:
    USAGE_POLICY_MESSAGE = (
        "FinSecOps Usage Policy\n\n"
        "This request is outside the supported scope of FinSecOps AI.\n\n"
        "I can assist with Azure infrastructure, FinOps, cloud security, cloud architecture, "
        "DevOps, networking, monitoring, resource analysis and cloud technology-related questions.\n\n"
        "Please ask a question related to these areas."
    )

    # Clearly out-of-scope intent patterns (entertainment, romance, creative fiction, personal life, unrelated recipes)
    _OUT_OF_SCOPE_PATTERNS = [
        r"\b(poem|poetry|rhyme|haiku|limerick)\b",
        r"\b(romantic|love letter|dating advice|girlfriend|boyfriend|crush)\b",
        r"\b(recipe|cook(?:ing)?|bake|baking|pizza|cake|pancake|sandwich|dinner menu)\b",
        r"\b(joke|riddle|standup comedy|funny story)\b",
        r"\b(movie review|celebrity gossip|actor|actress|hollywood|bollywood)\b",
        r"\b(horoscope|astrology|zodiac sign|fortune telling)\b",
        r"\b(cricket score|football match|soccer score|nba score|sports bet)\b",
        r"\b(write (an essay|a story|a novel|a song|lyrics|fiction) about (?!azure|cloud|devops|docker|kubernetes|terraform))\b",
    ]

    # Explicit cloud & technology signals that override potential false positives
    _CLOUD_TECH_SIGNALS = [
        "azure", "cloud", "finops", "secops", "vm", "virtual machine", "storage",
        "subscription", "resource", "cost", "security", "defender", "advisor",
        "network", "nsg", "vnet", "subnet", "firewall", "endpoint", "k8s",
        "kubernetes", "docker", "container", "devops", "ci/cd", "pipeline",
        "terraform", "bicep", "arm", "kql", "query", "log analytics", "monitor",
        "metric", "backup", "disaster recovery", "database", "sql", "cosmos",
        "iam", "rbac", "identity", "policy", "compliance", "assessment",
        "finding", "recommendation", "remediation", "patch", "encryption",
        "python", "bash", "powershell", "sdk", "cli", "rest api", "json", "yaml",
        "infrastructure", "architecture", "high availability", "scalability",
        "billing", "invoice", "saving", "budget", "underutilized", "orphan"
    ]

    @classmethod
    def is_in_scope(cls, user_message: str) -> bool:
        """
        Intelligently verifies whether user message is within FinSecOps / Cloud scope.
        Allows technical and cloud programming questions, rejects unrelated entertainment,
        romance, cooking, general creative writing, etc.
        """
        msg = (user_message or "").strip().lower()
        if len(msg) < 2:
            return False

        # If it contains explicit cloud/tech keywords, it is definitely in scope
        has_cloud_signal = any(sig in msg for sig in cls._CLOUD_TECH_SIGNALS)
        if has_cloud_signal:
            return True

        # Check for explicitly prohibited out-of-scope patterns
        for pattern in cls._OUT_OF_SCOPE_PATTERNS:
            if re.search(pattern, msg, re.IGNORECASE):
                return False

        # Common general conversational greetings and questions
        if re.match(r"^(hi|hello|hey|help|who are you|what can you do|good (morning|afternoon|evening))\b", msg):
            return True

        # General technical/programming queries (even if not explicitly mentioning "Azure") are allowed as cloud tech
        tech_words = [
            "code", "script", "api", "server", "linux", "windows", "database",
            "cluster", "node", "cpu", "ram", "memory", "disk", "iops", "latency",
            "port", "ssl", "tls", "cert", "token", "auth", "http", "git"
        ]
        if any(tw in msg for tw in tech_words):
            return True

        # If message doesn't match cloud signals or general tech, evaluate word length & structure
        words = msg.split()
        if len(words) <= 3 and any(w in ["what", "how", "list", "show", "describe", "explain", "check", "audit", "compare"] for w in words):
            return True

        # If ambiguous and non-technical without cloud keywords, classify as out of scope
        return False

    # Prohibited write / mutation operations
    _PROHIBITED_KQL_PATTERNS = [
        r"\.set", r"\.append", r"\.drop", r"\.alter", r"\.create",
        r"\.delete", r"\.purge", r"\.clear", r"\.ingest",
        r"\binsert\b", r"\bupdate\b", r"\bdelete\b", r"\bdrop\b", r"\balter\b"
    ]

    _PROHIBITED_WRITE_ACTIONS = [
        "create", "delete", "destroy", "update", "patch", "start", "stop",
        "restart", "deallocate", "reboot", "redeploy", "execute_script",
        "modify", "attach", "detach", "grant", "revoke", "assign_role",
        "terminate", "scale", "resize", "remediate_auto"
    ]

    @classmethod
    def validate_read_only_operation(cls, tool_name: str, tool_args: Dict[str, Any]) -> None:
        """
        Enforces strict read-only boundary at the backend.
        Never allows write, creation, modification, or deletion operations.
        """
        t_name = (tool_name or "").lower()

        # Reject any tool with write/modify terminology
        for action in cls._PROHIBITED_WRITE_ACTIONS:
            if action in t_name:
                raise SecurityPolicyViolationError(
                    f"Forbidden write operation '{tool_name}'. FinSecOps AI is strictly READ-ONLY "
                    f"and cannot modify or delete Azure resources. Manual remediation instructions are provided instead."
                )

        # If Azure Resource Graph query, inspect KQL for destructive statements
        if "resource_graph" in t_name or "kql" in t_name:
            query = tool_args.get("query", "")
            if not isinstance(query, str):
                raise SecurityPolicyViolationError("Invalid query argument format for Resource Graph.")

            for pat in cls._PROHIBITED_KQL_PATTERNS:
                if re.search(pat, query, re.IGNORECASE):
                    raise SecurityPolicyViolationError(
                        f"Resource Graph KQL query contains prohibited mutating statement: '{pat}'. "
                        f"Only read-only resource discovery queries are permitted."
                    )

    @classmethod
    def validate_subscription_access(
        cls,
        target_subscription_ids: List[str],
        authorized_subscriptions: List[Any]
    ) -> List[str]:
        """
        Enforces cross-workspace and subscription isolation.
        Returns validated subscription IDs that the current user has access to.
        """
        if not authorized_subscriptions:
            return []

        authorized_ids = set()
        for s in authorized_subscriptions:
            sid = getattr(s, "subscription_id", None) or (s.get("subscription_id") if isinstance(s, dict) else str(s))
            if sid:
                authorized_ids.add(sid.strip().lower())

        if not target_subscription_ids:
            # If no target specified, return all authorized subscriptions
            return list(authorized_ids)

        validated = []
        for tid in target_subscription_ids:
            clean_tid = str(tid).strip().lower()
            if clean_tid in authorized_ids:
                validated.append(clean_tid)
            else:
                logger.warning(f"Unauthorized cross-subscription access attempt blocked: '{clean_tid}'")

        if not validated and target_subscription_ids:
            raise SecurityPolicyViolationError(
                f"Access denied: Target subscription(s) are not authorized under your current workspace session."
            )

        return validated

    @classmethod
    def sanitize_credentials(cls, text: str) -> str:
        """
        Redacts API keys, client secrets, JWTs, and passwords from all outputs.
        """
        if not text:
            return ""
        text = re.sub(
            r'(?i)(client_secret|clientsecret|secret|password|bearer|authorization)\s*[:=]\s*["\']?[a-zA-Z0-9_\-\.~]{6,}["\']?',
            r'\1: [REDACTED_BY_SECURITY_POLICY]',
            text
        )
        text = re.sub(r'gsk_[a-zA-Z0-9]{30,}', '[REDACTED_GROQ_KEY]', text)
        text = re.sub(r'hf_[a-zA-Z0-9]{30,}', '[REDACTED_HF_KEY]', text)
        text = re.sub(r'ey[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{10,}', '[REDACTED_JWT_TOKEN]', text)
        return text
