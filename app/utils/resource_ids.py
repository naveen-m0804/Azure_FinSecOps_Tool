import re
from typing import Dict, Optional

AZURE_ID_REGEX = re.compile(
    r"^/subscriptions/(?P<subscription_id>[^/]+)"
    r"(?:/resourceGroups/(?P<resource_group>[^/]+))?"
    r"(?:/providers/(?P<provider>[^/]+/[^/]+(?:/[^/]+)*))?"
    r"(?:/(?P<resource_name>[^/]+))?$",
    re.IGNORECASE
)

def parse_azure_resource_id(resource_id: str) -> Dict[str, Optional[str]]:
    """
    Parses full Azure resource ID into subscription_id, resource_group, provider, and resource_name.
    """
    if not resource_id:
        return {
            "subscription_id": None,
            "resource_group": None,
            "provider": None,
            "resource_name": None,
            "resource_type": None,
        }
    
    parts = resource_id.strip("/").split("/")
    result = {
        "subscription_id": None,
        "resource_group": None,
        "provider": None,
        "resource_name": parts[-1] if parts else None,
        "resource_type": None,
    }
    
    for i in range(len(parts) - 1):
        key = parts[i].lower()
        if key == "subscriptions":
            result["subscription_id"] = parts[i + 1]
        elif key == "resourcegroups":
            result["resource_group"] = parts[i + 1]
        elif key == "providers" and i + 2 < len(parts):
            result["provider"] = f"{parts[i + 1]}/{parts[i + 2]}"
            result["resource_type"] = f"{parts[i + 1]}/{parts[i + 2]}"
            
    # Subscription-level resource scope handling
    if result["subscription_id"] and not result["resource_group"]:
        result["resource_group"] = "Subscription Scope"
        if len(parts) == 2 and parts[0].lower() == "subscriptions":
            result["resource_type"] = "Microsoft.Resources/subscriptions"

    return result

def normalize_resource_id(resource_id: str) -> str:
    """Returns normalized lowercase resource ID without trailing slash for case-insensitive matching."""
    return (resource_id or "").strip().rstrip("/").lower()
