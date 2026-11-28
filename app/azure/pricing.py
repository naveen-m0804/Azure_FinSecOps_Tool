import asyncio
import logging
import time
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
import httpx

logger = logging.getLogger("azure_finsecops.pricing")

RETAIL_PRICES_URL = "https://prices.azure.com/api/retail/prices"
RETAIL_API_VERSION = "2023-01-01-preview"
HOURS_PER_MONTH = 730.0


def normalize_arm_region(region: Optional[str]) -> str:
    """Normalizes Azure region display names (e.g. 'East US') to ARM region names ('eastus')."""
    if not region:
        return ""
    return str(region).strip().lower().replace(" ", "")


class PricingEngine:
    """
    Dynamic Azure Retail Prices API client (https://prices.azure.com/api/retail/prices).
    All prices are fetched dynamically from Azure for the exact SKU, region, and billing currency.
    Zero hardcoded or predefined price tables are used.
    """

    _cache: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}
    _cache_ttl_seconds: int = 3600
    _inflight: Dict[str, asyncio.Future] = {}
    _lock_per_loop: Dict[asyncio.AbstractEventLoop, asyncio.Lock] = {}
    _sem_per_loop: Dict[asyncio.AbstractEventLoop, asyncio.Semaphore] = {}

    @classmethod
    def _get_lock(cls) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if loop not in cls._lock_per_loop:
            cls._lock_per_loop[loop] = asyncio.Lock()
        return cls._lock_per_loop[loop]

    @classmethod
    def _get_sem(cls) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        if loop not in cls._sem_per_loop:
            cls._sem_per_loop[loop] = asyncio.Semaphore(5)
        return cls._sem_per_loop[loop]

    @classmethod
    async def query_retail_prices(
        cls,
        filter_expr: str,
        currency: str = "USD",
        max_pages: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Queries the public Azure Retail Prices API with caching and in-flight coalescing.
        Returns a list of matching price items, or [] if unavailable.
        """
        curr = (currency or "USD").strip().upper()
        cache_key = f"{curr}:{filter_expr}"
        now_ts = time.time()

        if cache_key in cls._cache:
            ts, items = cls._cache[cache_key]
            if (now_ts - ts) < cls._cache_ttl_seconds:
                return list(items)

        loop = asyncio.get_running_loop()
        async with cls._get_lock():
            fut = cls._inflight.get(cache_key)
            if fut and not fut.done() and getattr(fut, "_loop", None) == loop:
                pass
            else:
                fut = loop.create_future()
                cls._inflight[cache_key] = fut
                asyncio.create_task(cls._execute_retail_query(filter_expr, curr, max_pages, cache_key, fut))

        try:
            res = await fut
            return list(res)
        except Exception as ex:
            logger.debug("Retail prices query failed for '%s': %s", filter_expr, ex)
            return []

    @classmethod
    async def _execute_retail_query(
        cls,
        filter_expr: str,
        currency: str,
        max_pages: int,
        cache_key: str,
        future: asyncio.Future,
    ):
        items: List[Dict[str, Any]] = []
        try:
            encoded_filter = urllib.parse.quote(filter_expr, safe="='() ")
            url: Optional[str] = (
                f"{RETAIL_PRICES_URL}?api-version={RETAIL_API_VERSION}"
                f"&currencyCode={currency}&$filter={encoded_filter}"
            )
            page = 0
            async with cls._get_sem():
                async with httpx.AsyncClient(timeout=15.0) as client:
                    while url and page < max_pages:
                        resp = await client.get(url)
                        if resp.status_code != 200:
                            logger.debug("Retail Prices API HTTP %s for %s", resp.status_code, filter_expr)
                            break
                        data = resp.json()
                        items.extend(data.get("Items", []))
                        url = data.get("NextPageLink")
                        page += 1
            cls._cache[cache_key] = (time.time(), items)
            if not future.done():
                future.set_result(items)
        except Exception as ex:
            logger.debug("Retail Prices API exception for '%s': %s", filter_expr, ex)
            if not future.done():
                future.set_result([])
        finally:
            async with cls._get_lock():
                cls._inflight.pop(cache_key, None)

    @classmethod
    async def get_vm_rates(
        cls,
        vm_size: str,
        region: str,
        os_type: str = "Linux",
        currency: str = "USD",
    ) -> Optional[Dict[str, float]]:
        """
        Fetches dynamic VM hourly/monthly compute and OS license rates from Azure Retail Prices API.
        Returns dict with 'hourly', 'monthly', 'linux_monthly', 'windows_monthly', 'ahb_monthly_saving',
        or None if pricing is unavailable.
        """
        arm_region = normalize_arm_region(region)
        if not vm_size or not arm_region or arm_region == "global":
            return None

        filter_expr = (
            f"serviceName eq 'Virtual Machines' and armRegionName eq '{arm_region}' "
            f"and armSkuName eq '{vm_size}' and priceType eq 'Consumption'"
        )
        items = await cls.query_retail_prices(filter_expr, currency=currency, max_pages=2)
        if not items:
            return None

        linux_hourly: Optional[float] = None
        windows_hourly: Optional[float] = None

        for it in items:
            sku_name = (it.get("skuName") or "").lower()
            prod_name = (it.get("productName") or "").lower()
            meter_name = (it.get("meterName") or "").lower()
            unit_price = it.get("unitPrice")
            if unit_price is None or float(unit_price) <= 0:
                continue
            if "spot" in sku_name or "low priority" in sku_name or "spot" in meter_name or "low priority" in meter_name:
                continue
            if "cloud services" in prod_name or "dedicated host" in prod_name:
                continue

            price = float(unit_price)
            if "windows" in prod_name:
                if windows_hourly is None or price < windows_hourly:
                    windows_hourly = price
            elif "red hat" not in prod_name and "suse" not in prod_name and "rhel" not in prod_name and "sles" not in prod_name and "ubuntu" not in prod_name and "sql" not in prod_name:
                if linux_hourly is None or price < linux_hourly:
                    linux_hourly = price

        is_win = (os_type or "").strip().lower() == "windows"
        selected_hourly = windows_hourly if (is_win and windows_hourly is not None) else linux_hourly
        if selected_hourly is None:
            selected_hourly = windows_hourly

        if selected_hourly is None:
            return None

        linux_mo = round(linux_hourly * HOURS_PER_MONTH, 2) if linux_hourly is not None else None
        win_mo = round(windows_hourly * HOURS_PER_MONTH, 2) if windows_hourly is not None else None
        ahb_saving = round(max(0.0, win_mo - linux_mo), 2) if (win_mo is not None and linux_mo is not None) else None

        res: Dict[str, float] = {
            "hourly": round(selected_hourly, 4),
            "monthly": round(selected_hourly * HOURS_PER_MONTH, 2),
        }
        if linux_mo is not None:
            res["linux_monthly"] = linux_mo
        if win_mo is not None:
            res["windows_monthly"] = win_mo
        if ahb_saving is not None:
            res["ahb_monthly_saving"] = ahb_saving
        return res

    @classmethod
    async def get_vm_license_rate_diff(
        cls,
        vm_size: str,
        region: str,
        license_family: str,
        currency: str = "USD",
    ) -> Optional[Dict[str, float]]:
        """
        Computes exact PAYG license surcharge vs BYOS/AHB base compute rate from Azure Retail Prices API.
        license_family: 'windows', 'rhel', 'sles', 'sql'
        """
        arm_region = normalize_arm_region(region)
        if not vm_size or not arm_region or arm_region == "global":
            return None

        filter_expr = (
            f"serviceName eq 'Virtual Machines' and armRegionName eq '{arm_region}' "
            f"and armSkuName eq '{vm_size}' and priceType eq 'Consumption'"
        )
        items = await cls.query_retail_prices(filter_expr, currency=currency, max_pages=3)
        if not items:
            return None

        base_linux: Optional[float] = None
        target_hourly: Optional[float] = None
        fam = (license_family or "").lower()

        for it in items:
            sku_name = (it.get("skuName") or "").lower()
            prod_name = (it.get("productName") or "").lower()
            meter_name = (it.get("meterName") or "").lower()
            unit_price = it.get("unitPrice")
            if unit_price is None or float(unit_price) <= 0:
                continue
            if "spot" in sku_name or "low priority" in sku_name or "spot" in meter_name or "low priority" in meter_name:
                continue

            price = float(unit_price)
            if not any(x in prod_name for x in ("windows", "red hat", "rhel", "suse", "sles", "sql", "ubuntu pro")):
                if base_linux is None or price < base_linux:
                    base_linux = price

            if fam == "windows" and "windows" in prod_name and "sql" not in prod_name:
                if target_hourly is None or price < target_hourly:
                    target_hourly = price
            elif fam == "rhel" and ("red hat" in prod_name or "rhel" in prod_name) and "sql" not in prod_name:
                if target_hourly is None or price < target_hourly:
                    target_hourly = price
            elif fam == "sles" and ("suse" in prod_name or "sles" in prod_name) and "sql" not in prod_name:
                if target_hourly is None or price < target_hourly:
                    target_hourly = price
            elif fam == "sql" and "sql" in prod_name:
                if target_hourly is None or price < target_hourly:
                    target_hourly = price

        if base_linux is None or target_hourly is None:
            return None

        payg_mo = round(target_hourly * HOURS_PER_MONTH, 2)
        base_mo = round(base_linux * HOURS_PER_MONTH, 2)
        license_charge = round(max(0.0, payg_mo - base_mo), 2)
        return {
            "payg_monthly": payg_mo,
            "ahb_or_byos_monthly": base_mo,
            "license_charge_monthly": license_charge,
        }

    @classmethod
    def _disk_tier_code(cls, sku_tier: str, disk_size_gb: int) -> Tuple[str, str]:
        """Maps disk SKU and size to Azure Retail Prices skuName code (e.g. 'P10', 'Premium SSD')."""
        tier = (sku_tier or "Standard_LRS").lower()
        if "premium" in tier:
            prefix, prod_hint = "P", "Premium SSD"
        elif "standardssd" in tier:
            prefix, prod_hint = "E", "Standard SSD"
        else:
            prefix, prod_hint = "S", "Standard HDD"

        if disk_size_gb <= 32:
            num = "4"
        elif disk_size_gb <= 64:
            num = "6"
        elif disk_size_gb <= 128:
            num = "10"
        elif disk_size_gb <= 256:
            num = "15"
        elif disk_size_gb <= 512:
            num = "20"
        elif disk_size_gb <= 1024:
            num = "30"
        elif disk_size_gb <= 2048:
            num = "40"
        elif disk_size_gb <= 4096:
            num = "50"
        elif disk_size_gb <= 8192:
            num = "60"
        elif disk_size_gb <= 16384:
            num = "70"
        else:
            num = "80"

        return f"{prefix}{num}", prod_hint

    @classmethod
    async def get_disk_monthly_price(
        cls,
        sku_tier: str,
        disk_size_gb: int,
        region: str,
        currency: str = "USD",
    ) -> Optional[float]:
        """Fetches dynamic Managed Disk monthly price from Azure Retail Prices API."""
        arm_region = normalize_arm_region(region)
        if not arm_region or arm_region == "global":
            return None

        tier_code, prod_hint = cls._disk_tier_code(sku_tier, disk_size_gb)
        redundancy = "ZRS" if "zrs" in (sku_tier or "").lower() else "LRS"
        sku_filter = f"{tier_code} {redundancy}"

        filter_expr = (
            f"serviceName eq 'Storage' and armRegionName eq '{arm_region}' "
            f"and skuName eq '{sku_filter}' and priceType eq 'Consumption'"
        )
        items = await cls.query_retail_prices(filter_expr, currency=currency, max_pages=1)
        for it in items:
            meter = (it.get("meterName") or "").lower()
            prod = (it.get("productName") or "").lower()
            if (
                "disk" in meter
                and "snapshot" not in meter
                and "transaction" not in meter
                and "burst" not in meter
                and "mount" not in meter
                and "operation" not in meter
                and "reservation" not in meter
                and "enable" not in meter
            ):
                if prod_hint.lower() in prod:
                    price = float(it.get("unitPrice") or 0.0)
                    if price > 0:
                        return round(price, 2)
        return None

    @classmethod
    async def get_disk_downgrade_pricing(
        cls,
        current_sku: str,
        disk_size_gb: int,
        region: str,
        currency: str = "USD",
    ) -> Tuple[Optional[float], str, Optional[float]]:
        """
        Returns (current_price, proposed_sku, proposed_price) using Azure Retail Prices API.
        """
        if "premium" in (current_sku or "").lower():
            proposed_sku = "StandardSSD_LRS"
        else:
            proposed_sku = "Standard_LRS"

        curr_price, proposed_price = await asyncio.gather(
            cls.get_disk_monthly_price(current_sku, disk_size_gb, region, currency),
            cls.get_disk_monthly_price(proposed_sku, disk_size_gb, region, currency),
        )
        return curr_price, proposed_sku, proposed_price

    @classmethod
    async def get_public_ip_monthly_price(
        cls,
        sku_name: str,
        region: str,
        currency: str = "USD",
    ) -> Optional[float]:
        """Fetches dynamic Public IP monthly price from Azure Retail Prices API."""
        arm_region = normalize_arm_region(region)
        if not arm_region or arm_region == "global":
            return None

        filter_expr = (
            f"serviceName eq 'Virtual Network' and armRegionName eq '{arm_region}' "
            f"and productName eq 'IP Addresses' and priceType eq 'Consumption'"
        )
        items = await cls.query_retail_prices(filter_expr, currency=currency, max_pages=1)
        target_sku = (sku_name or "Standard").lower()
        for it in items:
            meter = (it.get("meterName") or "").lower()
            s_name = (it.get("skuName") or "").lower()
            if "static" in meter and (target_sku in s_name or target_sku in meter):
                price = float(it.get("unitPrice") or 0.0)
                if price > 0:
                    return round(price * HOURS_PER_MONTH, 2)
        return None

    @classmethod
    async def get_snapshot_gb_monthly_price(
        cls,
        region: str,
        currency: str = "USD",
    ) -> Optional[float]:
        """Fetches dynamic Managed Disk Snapshot per-GB monthly rate from Azure Retail Prices API."""
        arm_region = normalize_arm_region(region)
        if not arm_region or arm_region == "global":
            return None

        filter_expr = (
            f"serviceName eq 'Storage' and armRegionName eq '{arm_region}' "
            f"and contains(productName, 'Managed Disks') and contains(meterName, 'Snapshot') and priceType eq 'Consumption'"
        )
        items = await cls.query_retail_prices(filter_expr, currency=currency, max_pages=1)
        for it in items:
            meter = (it.get("meterName") or "").lower()
            if "lrs" in meter or "standard" in meter:
                price = float(it.get("unitPrice") or 0.0)
                if price > 0:
                    return price
        if items:
            price = float(items[0].get("unitPrice") or 0.0)
            return price if price > 0 else None
        return None

    @classmethod
    async def get_app_service_plan_monthly_price(
        cls,
        sku_name: str,
        sku_tier: str,
        capacity: int,
        region: str,
        currency: str = "USD",
    ) -> Optional[float]:
        """Fetches dynamic App Service Plan monthly price from Azure Retail Prices API."""
        tier_upper = (sku_tier or "").upper()
        name_upper = (sku_name or "").upper()
        if "FREE" in tier_upper or "F1" in name_upper:
            return 0.0

        arm_region = normalize_arm_region(region)
        if not arm_region or arm_region == "global":
            return None

        cap = max(capacity or 1, 1)
        filter_expr = (
            f"serviceName eq 'Azure App Service' and armRegionName eq '{arm_region}' "
            f"and skuName eq '{sku_name}' and priceType eq 'Consumption'"
        )
        items = await cls.query_retail_prices(filter_expr, currency=currency, max_pages=1)
        for it in items:
            prod = (it.get("productName") or "").lower()
            if "windows" not in prod and "linux" in prod or "app service" in prod:
                price = float(it.get("unitPrice") or 0.0)
                if price > 0:
                    return round(price * HOURS_PER_MONTH * cap, 2)
        return None

    @classmethod
    async def get_sql_database_monthly_price(
        cls,
        sku_name: str,
        tier_name: str,
        region: str,
        currency: str = "USD",
    ) -> Optional[float]:
        """Fetches dynamic Azure SQL Database monthly price from Azure Retail Prices API."""
        arm_region = normalize_arm_region(region)
        if not arm_region or arm_region == "global":
            return None

        target_sku = (sku_name or "").strip().lower()
        # Normalize e.g. 'Standard S4' -> 's4', 'Basic' -> 'basic'
        if " " in target_sku:
            parts = target_sku.split()
            if parts[-1] in ("basic", "s0", "s1", "s2", "s3", "s4", "s6", "s7", "s9", "s12", "p1", "p2", "p4", "p6", "p11", "p15"):
                target_sku = parts[-1]

        filter_expr = (
            f"serviceName eq 'SQL Database' and armRegionName eq '{arm_region}' "
            f"and priceType eq 'Consumption'"
        )
        items = await cls.query_retail_prices(filter_expr, currency=currency, max_pages=4)

        for it in items:
            s_name = (it.get("skuName") or "").strip().lower()
            p_name = (it.get("productName") or "").lower()
            m_name = (it.get("meterName") or "").lower()
            uom = (it.get("unitOfMeasure") or "").lower()
            price = float(it.get("unitPrice") or 0.0)
            if price <= 0:
                continue
            if "secondary" in s_name or "secondary" in m_name or "elastic" in p_name or "serverless" in p_name:
                continue
            if "sql database" not in p_name and "single database" not in p_name:
                continue
            if target_sku and (target_sku == s_name or (target_sku == "basic" and s_name in ("b", "basic"))):
                if "day" in uom:
                    return round(price * 30.4167, 2)
                elif "hour" in uom:
                    return round(price * HOURS_PER_MONTH, 2)
        return None

    @classmethod
    async def get_database_storage_gb_price(
        cls,
        db_service: str,
        region: str,
        currency: str = "USD",
    ) -> Optional[float]:
        """Fetches dynamic per-GB/month storage price for SQL / PostgreSQL / MySQL from Azure Retail Prices API."""
        arm_region = normalize_arm_region(region)
        if not arm_region or arm_region == "global":
            return None

        svc_map = {
            "sql": "SQL Database",
            "postgresql": "Azure Database for PostgreSQL",
            "mysql": "Azure Database for MySQL",
        }
        service_name = svc_map.get(db_service.lower(), "SQL Database")
        filter_expr = (
            f"serviceName eq '{service_name}' and armRegionName eq '{arm_region}' "
            f"and contains(meterName, 'Storage') and priceType eq 'Consumption'"
        )
        items = await cls.query_retail_prices(filter_expr, currency=currency, max_pages=2)
        for it in items:
            meter = (it.get("meterName") or "").lower()
            uom = (it.get("unitOfMeasure") or "").lower()
            price = float(it.get("unitPrice") or 0.0)
            if price > 0 and "gb" in uom and "backup" not in meter:
                return price
        return None

    @classmethod
    async def get_storage_redundancy_unit_prices(
        cls,
        current_redundancy: str,
        region: str,
        currency: str = "USD",
    ) -> Optional[Dict[str, float]]:
        """
        Fetches per-GB Hot/Standard storage unit prices for current redundancy vs LRS
        from Azure Retail Prices API so redundancy downgrade savings are exact.
        """
        arm_region = normalize_arm_region(region)
        if not arm_region or arm_region == "global":
            return None

        red_clean = (current_redundancy or "GRS").upper().replace("-", "")
        filter_expr = (
            f"serviceName eq 'Storage' and armRegionName eq '{arm_region}' "
            f"and contains(productName, 'Blob Storage') and priceType eq 'Consumption'"
        )
        items = await cls.query_retail_prices(filter_expr, currency=currency, max_pages=2)
        lrs_price: Optional[float] = None
        curr_price: Optional[float] = None

        for it in items:
            meter = (it.get("meterName") or "").lower()
            sku = (it.get("skuName") or "").lower()
            price = float(it.get("unitPrice") or 0.0)
            if price <= 0 or "data stored" not in meter or "hot" not in meter:
                continue
            if "lrs" in sku and "gzrs" not in sku and lrs_price is None:
                lrs_price = price
            if red_clean.lower() in sku.replace("-", "") and curr_price is None:
                curr_price = price

        if lrs_price and curr_price and curr_price > 0:
            return {"lrs_unit_price": lrs_price, "current_unit_price": curr_price}
        return None

    @classmethod
    async def get_storage_tier_unit_prices(
        cls,
        region: str,
        redundancy: str = "LRS",
        currency: str = "USD",
    ) -> Optional[Dict[str, float]]:
        """Fetches Hot vs Cool vs Archive per-GB storage prices from Azure Retail Prices API."""
        arm_region = normalize_arm_region(region)
        if not arm_region or arm_region == "global":
            return None

        red_clean = (redundancy or "LRS").upper().replace("-", "")
        filter_expr = (
            f"serviceName eq 'Storage' and armRegionName eq '{arm_region}' "
            f"and contains(productName, 'Blob Storage') and priceType eq 'Consumption'"
        )
        items = await cls.query_retail_prices(filter_expr, currency=currency, max_pages=2)
        prices: Dict[str, float] = {}
        for it in items:
            meter = (it.get("meterName") or "").lower()
            sku = (it.get("skuName") or "").lower().replace("-", "")
            price = float(it.get("unitPrice") or 0.0)
            if price <= 0 or "data stored" not in meter:
                continue
            if red_clean.lower() not in sku:
                continue
            if "hot" in meter and "hot" not in prices:
                prices["hot"] = price
            elif "cool" in meter and "cool" not in prices:
                prices["cool"] = price
            elif "archive" in meter and "archive" not in prices:
                prices["archive"] = price

        return prices if prices else None

    @classmethod
    async def get_backup_storage_gb_price(
        cls,
        region: str,
        currency: str = "USD",
    ) -> Optional[float]:
        """Fetches Azure Backup LRS/GRS storage per-GB monthly rate from Azure Retail Prices API."""
        arm_region = normalize_arm_region(region)
        if not arm_region or arm_region == "global":
            return None

        filter_expr = (
            f"serviceName eq 'Backup' and armRegionName eq '{arm_region}' "
            f"and contains(meterName, 'Data Stored') and priceType eq 'Consumption'"
        )
        items = await cls.query_retail_prices(filter_expr, currency=currency, max_pages=1)
        for it in items:
            price = float(it.get("unitPrice") or 0.0)
            if price > 0:
                return price
        return None

    @classmethod
    async def get_function_consumption_rates(
        cls,
        region: str,
        currency: str = "USD",
    ) -> Optional[Dict[str, float]]:
        """Fetches Azure Functions Consumption plan Execution Time & Total Executions rates."""
        arm_region = normalize_arm_region(region)
        if not arm_region or arm_region == "global":
            return None

        filter_expr = (
            f"serviceName eq 'Functions' and armRegionName eq '{arm_region}' "
            f"and priceType eq 'Consumption'"
        )
        items = await cls.query_retail_prices(filter_expr, currency=currency, max_pages=1)
        rates: Dict[str, float] = {}
        for it in items:
            meter = (it.get("meterName") or "").lower()
            price = float(it.get("unitPrice") or 0.0)
            if price <= 0:
                continue
            if "execution time" in meter and "execution_time_gbs" not in rates:
                rates["execution_time_gbs"] = price
            elif "total executions" in meter and "executions_per_million" not in rates:
                rates["executions_per_million"] = price
        return rates if rates else None

    @classmethod
    async def get_recommended_smaller_vm_sku(
        cls,
        current_vm_size: str,
        region: str,
        currency: str = "USD",
        os_type: str = "Linux",
    ) -> Optional[Dict[str, Any]]:
        """
        Determines a suitable smaller VM SKU in the same region and fetches its dynamic price
        from Azure Retail Prices API.
        """
        if not current_vm_size:
            return None

        import re
        # e.g. Standard_D4s_v5 -> Standard_D2s_v5, Standard_D2s_v5 -> Standard_B2s / Standard_B1s
        candidates: List[str] = []
        m = re.match(r"^(Standard_[A-Za-z]+)(\d+)([A-Za-z_0-9]*)$", current_vm_size, re.IGNORECASE)
        if m:
            prefix, num_str, suffix = m.group(1), m.group(2), m.group(3)
            vcpus = int(num_str)
            if vcpus >= 4:
                candidates.append(f"{prefix}{vcpus // 2}{suffix}")
            if vcpus >= 8:
                candidates.append(f"{prefix}{vcpus // 4}{suffix}")
            # Also consider burstable B-series for severely underutilized (<1% CPU) VMs
            if "b" not in prefix.lower():
                candidates.append("Standard_B2s" if vcpus >= 4 else "Standard_B1s")
                candidates.append("Standard_B1ms")
            elif vcpus >= 2:
                candidates.append(f"{prefix}{max(1, vcpus // 2)}{suffix}")

        curr_rates = await cls.get_vm_rates(current_vm_size, region, os_type=os_type, currency=currency)
        curr_monthly = curr_rates["monthly"] if curr_rates else None

        best_candidate: Optional[Dict[str, Any]] = None
        for cand in candidates:
            if cand.lower() == current_vm_size.lower():
                continue
            cand_rates = await cls.get_vm_rates(cand, region, os_type=os_type, currency=currency)
            if cand_rates and cand_rates.get("monthly") is not None:
                if curr_monthly is None or cand_rates["monthly"] < curr_monthly:
                    best_candidate = {
                        "recommended_sku": cand,
                        "recommended_monthly_cost": cand_rates["monthly"],
                        "current_monthly_cost": curr_monthly,
                    }
                    break
        return best_candidate
