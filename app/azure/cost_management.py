import asyncio
import random
import time
import logging
import datetime
from typing import Dict, Any, List, Optional, Tuple
from app.azure.client_base import AzureClientBase
from app.utils.resource_ids import normalize_resource_id

logger = logging.getLogger("azure_finsecops.cost_management")

KNOWN_RESOURCE_TYPE_VARIANTS: Dict[str, List[str]] = {
    "microsoft.storage/storageaccounts": [
        "Microsoft.Storage/storageAccounts",
        "microsoft.storage/storageaccounts"
    ],
    "microsoft.compute/virtualmachines": [
        "Microsoft.Compute/virtualMachines",
        "microsoft.compute/virtualmachines"
    ],
    "microsoft.compute/disks": [
        "Microsoft.Compute/disks",
        "microsoft.compute/disks"
    ],
    "microsoft.compute/snapshots": [
        "Microsoft.Compute/snapshots",
        "microsoft.compute/snapshots"
    ],
    "microsoft.network/publicipaddresses": [
        "Microsoft.Network/publicIPAddresses",
        "microsoft.network/publicipaddresses"
    ],
    "microsoft.network/networksecuritygroups": [
        "Microsoft.Network/networkSecurityGroups",
        "microsoft.network/networksecuritygroups"
    ],
    "microsoft.network/routetables": [
        "Microsoft.Network/routeTables",
        "microsoft.network/routetables"
    ],
    "microsoft.network/loadbalancers": [
        "Microsoft.Network/loadBalancers",
        "microsoft.network/loadbalancers"
    ],
    "microsoft.network/natgateways": [
        "Microsoft.Network/natGateways",
        "microsoft.network/natgateways"
    ],
    "microsoft.network/applicationgateways": [
        "Microsoft.Network/applicationGateways",
        "microsoft.network/applicationgateways"
    ],
    "microsoft.web/serverfarms": [
        "Microsoft.Web/serverfarms",
        "microsoft.web/serverfarms"
    ],
    "microsoft.sql/servers/databases": [
        "Microsoft.Sql/servers/databases",
        "microsoft.sql/servers/databases"
    ],
}

def _get_resource_type_variants(resource_type_filter: str) -> List[str]:
    lowered = resource_type_filter.strip().lower()
    if lowered in KNOWN_RESOURCE_TYPE_VARIANTS:
        return KNOWN_RESOURCE_TYPE_VARIANTS[lowered]
    # General fallback: include the original filter and lowercase version
    variants = {resource_type_filter, lowered}
    return list(variants)

class CostManagementAdapter:
    # In-memory query cache: key -> (timestamp, data)
    _cost_cache: Dict[str, Tuple[float, Dict[str, Dict[str, Any]]]] = {}
    _cache_ttl_seconds: int = 1800  # 30-minute cache to eliminate duplicate/second-run 429 throttling
    _currency_cache: Dict[str, str] = {}

    # In-flight query deduplication to avoid thundering herd across parallel assessment modules
    _inflight_cost_queries: Dict[str, asyncio.Future] = {}
    _lock_per_loop: Dict[asyncio.AbstractEventLoop, asyncio.Lock] = {}
    _sem_per_loop: Dict[asyncio.AbstractEventLoop, asyncio.Semaphore] = {}

    @classmethod
    def _get_inflight_lock(cls) -> asyncio.Lock:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.Lock()
        if loop not in cls._lock_per_loop:
            cls._lock_per_loop[loop] = asyncio.Lock()
        return cls._lock_per_loop[loop]

    @classmethod
    def _get_cost_semaphore(cls) -> asyncio.Semaphore:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.Semaphore(2)
        if loop not in cls._sem_per_loop:
            cls._sem_per_loop[loop] = asyncio.Semaphore(2)
        return cls._sem_per_loop[loop]

    @classmethod
    async def get_subscription_currency(
        cls,
        client: AzureClientBase,
        subscription_id: str
    ) -> Optional[str]:
        """
        Detects the billing currency (e.g. 'INR', 'USD', 'EUR') for the subscription
        by executing a lightweight Cost Management ActualCost query for the past 30 days.
        Caches result per subscription to prevent redundant API queries.
        """
        if subscription_id in cls._currency_cache:
            return cls._currency_cache[subscription_id]

        today = datetime.date.today()
        start_date = (today - datetime.timedelta(days=30)).isoformat()
        end_date = today.isoformat()

        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.CostManagement/query?api-version=2023-03-01"
        body = {
            "type": "ActualCost",
            "timeframe": "Custom",
            "timePeriod": {
                "from": f"{start_date}T00:00:00Z",
                "to": f"{end_date}T23:59:59Z"
            },
            "dataset": {
                "granularity": "None",
                "aggregation": {
                    "totalCost": {
                        "name": "PreTaxCost",
                        "function": "Sum"
                    }
                }
            }
        }
        try:
            async with cls._get_cost_semaphore():
                resp = await client.execute_request("POST", url, json_data=body)
                await asyncio.sleep(0.2)

            if resp.status_code == 200:
                data = resp.json()
                props = data.get("properties", {})
                columns = props.get("columns", [])
                rows = props.get("rows", [])
                curr_idx = -1
                for idx, col in enumerate(columns):
                    if col.get("name") == "Currency":
                        curr_idx = idx
                        break
                if curr_idx >= 0 and rows:
                    for row in rows:
                        val = row[curr_idx]
                        if val and str(val).strip():
                            currency = str(val).strip().upper()
                            logger.info(f"Discovered tenant billing currency '{currency}' for subscription {subscription_id}")
                            cls._currency_cache[subscription_id] = currency
                            return currency
        except Exception as e:
            logger.warning(f"Could not probe currency from Cost Management for sub {subscription_id}: {e}")
        return None

    @classmethod
    async def query_resource_costs(
        cls,
        client: AzureClientBase,
        subscription_id: str,
        start_date: str,
        end_date: str,
        resource_type_filter: Optional[str] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Queries Azure Cost Management for ActualCost grouped by ResourceId with full pagination.
        Features request coalescing, in-memory caching (30m TTL), serialized concurrency,
        and exponential backoff retry on HTTP 429.
        """
        cache_key = f"{subscription_id}:{start_date}:{end_date}:{(resource_type_filter or 'ALL').lower()}"
        now_ts = time.time()

        # 1. Check in-memory cache
        if cache_key in cls._cost_cache:
            ts, cached_data = cls._cost_cache[cache_key]
            if (now_ts - ts) < cls._cache_ttl_seconds:
                logger.info(f"Returning cached Cost Management data ({len(cached_data)} items) for key '{cache_key}'")
                return dict(cached_data)

        loop = asyncio.get_running_loop()
        # 2. Coalesce in-flight requests for identical key
        async with cls._get_inflight_lock():
            fut = cls._inflight_cost_queries.get(cache_key)
            if fut and not fut.done() and getattr(fut, "_loop", None) == loop:
                pass
            else:
                fut = loop.create_future()
                cls._inflight_cost_queries[cache_key] = fut
                # Launch actual worker
                asyncio.create_task(
                    cls._execute_query_worker(
                        client=client,
                        subscription_id=subscription_id,
                        start_date=start_date,
                        end_date=end_date,
                        resource_type_filter=resource_type_filter,
                        cache_key=cache_key,
                        future=fut
                    )
                )

        try:
            res = await fut
            return dict(res)
        except Exception as ex:
            logger.error(f"In-flight cost query failed for {cache_key}: {ex}")
            return {}

    @classmethod
    async def _execute_query_worker(
        cls,
        client: AzureClientBase,
        subscription_id: str,
        start_date: str,
        end_date: str,
        resource_type_filter: Optional[str],
        cache_key: str,
        future: asyncio.Future
    ):
        try:
            result = await cls._do_query(
                client=client,
                subscription_id=subscription_id,
                start_date=start_date,
                end_date=end_date,
                resource_type_filter=resource_type_filter
            )
            # Store in cache
            cls._cost_cache[cache_key] = (time.time(), result)
            if not future.done():
                future.set_result(result)
        except Exception as e:
            logger.error(f"Cost query worker exception: {e}", exc_info=True)
            if not future.done():
                future.set_result({})
        finally:
            async with cls._get_inflight_lock():
                cls._inflight_cost_queries.pop(cache_key, None)

    @classmethod
    async def _do_query(
        cls,
        client: AzureClientBase,
        subscription_id: str,
        start_date: str,
        end_date: str,
        resource_type_filter: Optional[str] = None
    ) -> Dict[str, Dict[str, Any]]:
        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.CostManagement/query?api-version=2023-03-01"
        
        body: Dict[str, Any] = {
            "type": "ActualCost",
            "timeframe": "Custom",
            "timePeriod": {
                "from": f"{start_date}T00:00:00Z",
                "to": f"{end_date}T23:59:59Z"
            },
            "dataset": {
                "granularity": "None",
                "aggregation": {
                    "totalCost": {
                        "name": "PreTaxCost",
                        "function": "Sum"
                    }
                },
                "grouping": [
                    {
                        "type": "Dimension",
                        "name": "ResourceId"
                    }
                ]
            }
        }

        if resource_type_filter:
            filter_variants = _get_resource_type_variants(resource_type_filter)
            body["dataset"]["filter"] = {
                "dimensions": {
                    "name": "ResourceType",
                    "operator": "In",
                    "values": filter_variants
                }
            }

        cost_map: Dict[str, Dict[str, Any]] = {}
        curr_url: Optional[str] = url
        req_body: Optional[Dict[str, Any]] = body
        page_num = 1

        while curr_url:
            resp = None
            for attempt in range(1, 4):
                try:
                    async with cls._get_cost_semaphore():
                        resp = await client.execute_request("POST", curr_url, json_data=req_body)
                        await asyncio.sleep(0.3)

                    if resp.status_code == 429:
                        retry_after = resp.headers.get("Retry-After")
                        if retry_after and retry_after.isdigit():
                            wait_sec = min(int(retry_after), 10)
                        else:
                            wait_sec = (2 ** (attempt - 1)) * 2
                        wait_sec = min(wait_sec, 15)
                        logger.warning(
                            f"Cost Management query returned HTTP 429 for sub {subscription_id} (page {page_num}). "
                            f"Backing off for {wait_sec:.1f}s (attempt {attempt}/3)..."
                        )
                        await asyncio.sleep(wait_sec)
                        continue
                    else:
                        break
                except Exception as ex:
                    logger.warning(f"Cost query network error (attempt {attempt}/3): {ex}")
                    await asyncio.sleep(1.0)

            if not resp or resp.status_code != 200:
                err_text = resp.text if resp else "No response"
                logger.warning(
                    f"Cost Management query returned HTTP {resp.status_code if resp else 'ERR'} for sub {subscription_id} (page {page_num}): {err_text}"
                )
                break

            try:
                data = resp.json()
                props = data.get("properties", {})
                columns = props.get("columns", [])
                rows = props.get("rows", [])

                res_idx, cost_idx, curr_idx = -1, -1, -1
                for idx, col in enumerate(columns):
                    c_name = col.get("name")
                    if c_name == "ResourceId":
                        res_idx = idx
                    elif c_name == "PreTaxCost":
                        cost_idx = idx
                    elif c_name == "Currency":
                        curr_idx = idx

                if res_idx >= 0 and cost_idx >= 0:
                    for row in rows:
                        res_id = str(row[res_idx])
                        cost_val = float(row[cost_idx]) if row[cost_idx] is not None else 0.0
                        currency = str(row[curr_idx]) if curr_idx >= 0 and row[curr_idx] else "USD"
                        norm_id = normalize_resource_id(res_id)
                        cost_map[norm_id] = {
                            "resource_id": res_id,
                            "cost": cost_val,
                            "currency": currency,
                            "start_date": start_date,
                            "end_date": end_date
                        }

                # Azure Cost Management pagination: nextLink can be in props or root
                next_link = props.get("nextLink") or data.get("nextLink")
                if next_link:
                    curr_url = next_link
                    req_body = None  # subsequent calls to nextLink do not send the original filter body
                    page_num += 1
                else:
                    curr_url = None

            except Exception as e:
                logger.error(f"Error parsing Cost Management response for subscription {subscription_id} (page {page_num}): {e}", exc_info=True)
                break

        return cost_map
