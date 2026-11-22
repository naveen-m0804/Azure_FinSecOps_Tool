from typing import Dict, Any, List, Optional
from app.azure.client_base import AzureClientBase

class MonitorAdapter:
    @staticmethod
    async def get_metrics(
        client: AzureClientBase,
        resource_id: str,
        metric_names: str,
        start_time: str,
        end_time: str,
        time_grain: str = "PT1H",
        aggregation: str = "Average",
        metric_namespace: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Queries Azure Monitor metrics.
        Mirrors Get-AzMetric from PowerShell scripts.
        """
        clean_res_id = resource_id.lstrip("/")
        url = f"https://management.azure.com/{clean_res_id}/providers/Microsoft.Insights/metrics?api-version=2018-01-01"
        params = {
            "metricnames": metric_names,
            "timespan": f"{start_time}/{end_time}",
            "interval": time_grain,
            "aggregation": aggregation,
        }
        if metric_namespace:
            params["metricnamespace"] = metric_namespace

        try:
            resp = await client.execute_request("GET", url, params=params)
            if resp.status_code == 200:
                data = resp.json()
                metrics_list = data.get("value", [])
                result: Dict[str, float] = {}
                for m in metrics_list:
                    m_name = m.get("name", {}).get("value")
                    timeseries = m.get("timeseries", [])
                    values = []
                    for ts in timeseries:
                        for pt in ts.get("data", []):
                            avg = pt.get("average")
                            if avg is not None:
                                values.append(avg)
                    if values:
                        result[m_name] = sum(values) / len(values)
                    else:
                        result[m_name] = 0.0
                return {"success": True, "metrics": result, "raw": data}
            return {"success": False, "error": f"HTTP {resp.status_code}"}
        except Exception as ex:
            return {"success": False, "error": str(ex)}

    @staticmethod
    async def get_diagnostic_settings(client: AzureClientBase, resource_id: str) -> List[Dict[str, Any]]:
        clean_res_id = resource_id.lstrip("/")
        url = f"https://management.azure.com/{clean_res_id}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
        try:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                return resp.json().get("value", [])
            return []
        except Exception:
            return []

    @staticmethod
    async def get_activity_logs(
        client: AzureClientBase,
        subscription_id: str,
        start_time: str,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Queries Azure Activity Log events across the subscription since start_time.
        Used to detect real administrative activity timestamps for resources.
        """
        filter_str = f"eventTimestamp ge '{start_time}'"
        if end_time:
            filter_str += f" and eventTimestamp le '{end_time}'"
        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$filter={filter_str}&$select=eventTimestamp,resourceId,eventName,operationName,caller"
        try:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                return resp.json().get("value", [])
            return []
        except Exception:
            return []
