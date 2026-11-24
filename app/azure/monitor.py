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
                            if avg is None:
                                avg = pt.get("total") if pt.get("total") is not None else pt.get("maximum")
                            if avg is not None:
                                values.append(float(avg))
                    val = sum(values) / len(values) if values else 0.0
                    if m_name:
                        result[m_name] = val
                        result[m_name.lower()] = val
                        result[m_name.replace(" ", "").lower()] = val
                return {"success": True, "metrics": result, "raw": data}

            # If multi-metric query failed with HTTP 400 (e.g. one metric is an invalid guest metric),
            # split and query individual metrics so all supported platform metrics are successfully returned.
            names_list = [m.strip() for m in metric_names.split(",") if m.strip()]
            if resp.status_code == 400 and len(names_list) > 1:
                combined_result: Dict[str, float] = {}
                for single_m in names_list:
                    sub_params = dict(params)
                    sub_params["metricnames"] = single_m
                    try:
                        sub_resp = await client.execute_request("GET", url, params=sub_params)
                        if sub_resp.status_code == 200:
                            sub_data = sub_resp.json()
                            for m in sub_data.get("value", []):
                                m_name = m.get("name", {}).get("value")
                                values = [
                                    float(pt.get("average") if pt.get("average") is not None else (pt.get("total") or pt.get("maximum") or 0.0))
                                    for ts in m.get("timeseries", [])
                                    for pt in ts.get("data", [])
                                    if pt.get("average") is not None or pt.get("total") is not None or pt.get("maximum") is not None
                                ]
                                val = sum(values) / len(values) if values else 0.0
                                if m_name:
                                    combined_result[m_name] = val
                                    combined_result[m_name.lower()] = val
                                    combined_result[m_name.replace(" ", "").lower()] = val
                    except Exception:
                        pass
                if combined_result:
                    return {"success": True, "metrics": combined_result}

            err_detail = ""
            try:
                err_detail = resp.json().get("error", {}).get("message", "")
            except Exception:
                err_detail = resp.text[:150]
            return {"success": False, "error": f"HTTP {resp.status_code}: {err_detail}" if err_detail else f"HTTP {resp.status_code}"}
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
