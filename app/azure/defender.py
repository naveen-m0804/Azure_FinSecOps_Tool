from typing import Dict, Any, List, Optional
from app.azure.client_base import AzureClientBase

class DefenderAdapter:
    @staticmethod
    async def get_secure_score(client: AzureClientBase, subscription_id: str) -> Dict[str, Any]:
        """
        Calls Defender ascScore API.
        URI: /subscriptions/{sub}/providers/Microsoft.Security/secureScores/ascScore?api-version=2020-01-01
        """
        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Security/secureScores/ascScore?api-version=2020-01-01"
        try:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                data = resp.json()
                props = data.get("properties", {})
                score = props.get("score", {})
                current = float(score.get("current", 0.0))
                maximum = float(score.get("max", 0.0))
                api_pct = float(score.get("percentage", 0.0))
                weight = float(props.get("weight", 0.0))
                calculated_pct = (current / maximum * 100.0) if maximum > 0 else 0.0
                return {
                    "success": True,
                    "status_code": resp.status_code,
                    "current_score": current,
                    "max_score": maximum,
                    "percentage": round(calculated_pct, 2),
                    "api_percentage": round(api_pct * 100.0, 2),
                    "weight": weight,
                    "raw": data
                }
            else:
                return {
                    "success": False,
                    "status_code": resp.status_code,
                    "error": f"HTTP {resp.status_code}: {resp.text}"
                }
        except Exception as ex:
            return {"success": False, "status_code": 500, "error": str(ex)}

    @staticmethod
    async def get_secure_score_controls(client: AzureClientBase, subscription_id: str) -> Dict[str, Any]:
        """
        Retrieves Defender for Cloud Secure Score Controls with full pagination support.
        URI: /subscriptions/{sub}/providers/Microsoft.Security/secureScores/ascScore/secureScoreControls?api-version=2020-01-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Security/secureScores/ascScore/secureScoreControls?api-version=2020-01-01"
        all_items: List[Dict[str, Any]] = []
        last_status = 200

        while url:
            try:
                resp = await client.execute_request("GET", url)
                last_status = resp.status_code
                if resp.status_code == 200:
                    data = resp.json()
                    all_items.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    return {
                        "success": len(all_items) > 0,
                        "status_code": resp.status_code,
                        "value": all_items,
                        "error": f"HTTP {resp.status_code}: {resp.text}"
                    }
            except Exception as ex:
                return {"success": len(all_items) > 0, "status_code": 500, "value": all_items, "error": str(ex)}

        return {"success": True, "status_code": last_status, "value": all_items}

    @staticmethod
    async def get_security_assessments(client: AzureClientBase, subscription_id: str, max_items: int = 50) -> Dict[str, Any]:
        """
        Retrieves security recommendations / assessments from Defender for Cloud with controlled pagination.
        Uses $expand=metadata to retrieve official Azure remediation guidance and descriptions.
        URI: /subscriptions/{sub}/providers/Microsoft.Security/assessments?api-version=2021-06-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Security/assessments?api-version=2021-06-01&$expand=metadata"
        all_items: List[Dict[str, Any]] = []
        last_status = 200

        # Try with $expand=metadata first; fallback to standard endpoint if rejected with 400
        try:
            resp = await client.execute_request("GET", url)
            last_status = resp.status_code
            if resp.status_code == 200:
                data = resp.json()
                all_items.extend(data.get("value", []))
                if len(all_items) >= max_items:
                    url = None
                else:
                    url = data.get("nextLink")
            elif resp.status_code in (400, 404):
                url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Security/assessments?api-version=2021-06-01"
            else:
                return {
                    "success": False,
                    "status_code": resp.status_code,
                    "value": [],
                    "error": f"HTTP {resp.status_code}: {resp.text}"
                }
        except Exception as ex:
            return {"success": False, "status_code": 500, "value": [], "error": str(ex)}

        while url:
            try:
                resp = await client.execute_request("GET", url)
                last_status = resp.status_code
                if resp.status_code == 200:
                    data = resp.json()
                    all_items.extend(data.get("value", []))
                    if len(all_items) >= max_items:
                        break
                    url = data.get("nextLink")
                else:
                    return {
                        "success": len(all_items) > 0,
                        "status_code": resp.status_code,
                        "value": all_items,
                        "error": f"HTTP {resp.status_code}: {resp.text}"
                    }
            except Exception as ex:
                return {"success": len(all_items) > 0, "status_code": 500, "value": all_items, "error": str(ex)}

        return {"success": True, "status_code": last_status, "value": all_items}

    @staticmethod
    async def get_sub_assessments(client: AzureClientBase, subscription_id: str, assessment_name: str) -> Dict[str, Any]:
        """
        Retrieves sub-assessments (such as vulnerability assessments or container findings) with pagination.
        URI: /subscriptions/{sub}/providers/Microsoft.Security/assessments/{assessment_name}/subAssessments?api-version=2019-01-01-preview
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Security/assessments/{assessment_name}/subAssessments?api-version=2019-01-01-preview"
        all_items: List[Dict[str, Any]] = []
        last_status = 200

        while url:
            try:
                resp = await client.execute_request("GET", url)
                last_status = resp.status_code
                if resp.status_code == 200:
                    data = resp.json()
                    all_items.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    return {
                        "success": len(all_items) > 0,
                        "status_code": resp.status_code,
                        "value": all_items,
                        "error": f"HTTP {resp.status_code}: {resp.text}"
                    }
            except Exception as ex:
                return {"success": len(all_items) > 0, "status_code": 500, "value": all_items, "error": str(ex)}

        return {"success": True, "status_code": last_status, "value": all_items}

    @staticmethod
    async def get_security_alerts(client: AzureClientBase, subscription_id: str) -> Dict[str, Any]:
        """
        Retrieves security alerts from Defender for Cloud with full pagination.
        URI: /subscriptions/{sub}/providers/Microsoft.Security/alerts?api-version=2022-01-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Security/alerts?api-version=2022-01-01"
        all_items: List[Dict[str, Any]] = []
        last_status = 200

        while url:
            try:
                resp = await client.execute_request("GET", url)
                last_status = resp.status_code
                if resp.status_code == 200:
                    data = resp.json()
                    all_items.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    return {
                        "success": len(all_items) > 0,
                        "status_code": resp.status_code,
                        "value": all_items,
                        "error": f"HTTP {resp.status_code}: {resp.text}"
                    }
            except Exception as ex:
                return {"success": len(all_items) > 0, "status_code": 500, "value": all_items, "error": str(ex)}

        return {"success": True, "status_code": last_status, "value": all_items}

    @staticmethod
    async def get_all_sub_assessments(client: AzureClientBase, subscription_id: str) -> Dict[str, Any]:
        """
        Retrieves all sub-assessments across a subscription with full pagination.
        URI: /subscriptions/{sub}/providers/Microsoft.Security/subAssessments?api-version=2019-01-01-preview
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Security/subAssessments?api-version=2019-01-01-preview"
        all_items: List[Dict[str, Any]] = []
        last_status = 200

        while url:
            try:
                resp = await client.execute_request("GET", url)
                last_status = resp.status_code
                if resp.status_code == 200:
                    data = resp.json()
                    all_items.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    return {
                        "success": len(all_items) > 0,
                        "status_code": resp.status_code,
                        "value": all_items,
                        "error": f"HTTP {resp.status_code}: {resp.text}"
                    }
            except Exception as ex:
                return {"success": len(all_items) > 0, "status_code": 500, "value": all_items, "error": str(ex)}

        return {"success": True, "status_code": last_status, "value": all_items}

    @staticmethod
    async def get_attack_paths(client: AzureClientBase, subscription_id: str) -> Dict[str, Any]:
        """
        Retrieves attack paths from Defender for Cloud CSPM with full pagination and multi-version fallback.
        URI: /subscriptions/{sub}/providers/Microsoft.Security/attackPaths?api-version=2023-05-01
        """
        for api_version in ["2023-05-01", "2023-12-01-preview"]:
            url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Security/attackPaths?api-version={api_version}"
            all_items: List[Dict[str, Any]] = []
            last_status = 200
            fallback_needed = False

            while url:
                try:
                    resp = await client.execute_request("GET", url)
                    last_status = resp.status_code
                    if resp.status_code == 200:
                        data = resp.json()
                        all_items.extend(data.get("value", []))
                        url = data.get("nextLink")
                    elif resp.status_code in (400, 404):
                        fallback_needed = True
                        break
                    else:
                        return {
                            "success": len(all_items) > 0,
                            "status_code": resp.status_code,
                            "value": all_items,
                            "error": f"HTTP {resp.status_code}: {resp.text}"
                        }
                except Exception as ex:
                    return {"success": len(all_items) > 0, "status_code": 500, "value": all_items, "error": str(ex)}

            if not fallback_needed:
                return {"success": True, "status_code": last_status, "value": all_items}

        # 3. Fallback: Query Azure Resource Graph for Defender attack paths
        try:
            arg_url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
            arg_payload = {
                "subscriptions": [subscription_id],
                "query": (
                    f"securityresources "
                    f"| where subscriptionId =~ '{subscription_id}' "
                    f"| where type =~ 'microsoft.security/attackpaths' "
                    f"| project id, name, type, properties"
                )
            }
            arg_resp = await client.execute_request("POST", arg_url, json_data=arg_payload)
            if arg_resp.status_code == 200:
                arg_data = arg_resp.json().get("data", [])
                if arg_data:
                    return {"success": True, "status_code": 200, "value": arg_data}
        except Exception:
            pass

        return {"success": False, "status_code": 404, "value": [], "error": "Attack paths endpoint returned 404/400"}
