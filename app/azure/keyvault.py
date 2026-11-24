from typing import Dict, Any, List, Optional
from app.azure.client_base import AzureClientBase
from app.utils.resource_ids import normalize_resource_id
import logging

logger = logging.getLogger("azure_finsecops.azure.keyvault")

class KeyVaultAdapter:
    @staticmethod
    async def get_key_vaults(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves Key Vaults in the subscription with multi-source discovery:
        1. Azure Resource Graph (ARG) for fast, full-subscription indexing with properties.
        2. Direct ARM Key Vault provider endpoint with pagination.
        3. Generic Resources endpoint fallback.
        Merges results and enriches with full resource details.
        """
        all_vaults_map: Dict[str, Dict[str, Any]] = {}

        # 1. Try Azure Resource Graph (ARG)
        try:
            arg_url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
            arg_payload = {
                "subscriptions": [subscription_id],
                "query": (
                    f"resources "
                    f"| where subscriptionId =~ '{subscription_id}' "
                    f"| where type =~ 'microsoft.keyvault/vaults' "
                    f"| project id, name, type, location, resourceGroup, properties, tags"
                ),
                "options": {"resultFormat": "objectArray"}
            }
            resp = await client.execute_request("POST", arg_url, json_data=arg_payload)
            if resp.status_code == 200:
                arg_data = resp.json().get("data", [])
                if isinstance(arg_data, list):
                    for v in arg_data:
                        v_id = v.get("id", "")
                        if v_id:
                            all_vaults_map[normalize_resource_id(v_id)] = v
        except Exception as ex:
            logger.debug("ARG Key Vault query failed: %s", ex)

        # 2. Query direct ARM Key Vault provider endpoint
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01"
        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    for v in data.get("value", []):
                        v_id = v.get("id", "")
                        if v_id:
                            norm_id = normalize_resource_id(v_id)
                            if norm_id in all_vaults_map:
                                # Merge properties
                                curr_props = all_vaults_map[norm_id].get("properties") or {}
                                new_props = v.get("properties") or {}
                                curr_props.update(new_props)
                                all_vaults_map[norm_id]["properties"] = curr_props
                            else:
                                all_vaults_map[norm_id] = v
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        # 3. Fallback to generic resources endpoint if still empty
        if not all_vaults_map:
            try:
                res_url = f"https://management.azure.com/subscriptions/{subscription_id}/resources?$filter=resourceType eq 'Microsoft.KeyVault/vaults'&api-version=2021-04-01"
                resp = await client.execute_request("GET", res_url)
                if resp.status_code == 200:
                    for v in resp.json().get("value", []):
                        v_id = v.get("id", "")
                        if v_id:
                            all_vaults_map[normalize_resource_id(v_id)] = v
            except Exception as ex:
                logger.debug("Generic resources Key Vault query failed: %s", ex)

        # 4. Enrich vaults with full properties if enableRbacAuthorization is missing
        enriched_vaults: List[Dict[str, Any]] = []
        for norm_id, v in all_vaults_map.items():
            props = v.get("properties", {}) or {}
            v_id = v.get("id", "")
            if not props or "enableRbacAuthorization" not in props:
                for api_ver in ("2023-07-01", "2021-10-01", "2022-07-01"):
                    try:
                        clean_id = v_id.lstrip("/")
                        detail_url = f"https://management.azure.com/{clean_id}?api-version={api_ver}"
                        detail_resp = await client.execute_request("GET", detail_url)
                        if detail_resp.status_code == 200:
                            detail_data = detail_resp.json()
                            v["properties"] = detail_data.get("properties", props)
                            break
                    except Exception as ex:
                        logger.debug("Failed to enrich key vault %s with api %s: %s", v.get("name"), api_ver, ex)
            enriched_vaults.append(v)

        return enriched_vaults
