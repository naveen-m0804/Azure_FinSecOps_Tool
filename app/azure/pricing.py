from typing import Dict, Any, Optional, Tuple

class PricingEngine:
    # Managed Disk monthly baseline estimates (USD, East US / Central US standard)
    DISK_PRICING_TABLE = {
        # Premium SSD
        "premium_p4": 5.28,
        "premium_p6": 10.21,
        "premium_p10": 19.71,
        "premium_p15": 38.02,
        "premium_p20": 73.22,
        "premium_p30": 135.17,
        "premium_p40": 260.10,
        "premium_p50": 480.00,
        # Standard SSD
        "standardssd_e4": 2.40,
        "standardssd_e6": 4.80,
        "standardssd_e10": 9.60,
        "standardssd_e15": 19.20,
        "standardssd_e20": 38.00,
        "standardssd_e30": 76.00,
        "standardssd_e40": 150.00,
        "standardssd_e50": 280.00,
        # Standard HDD
        "standard_s4": 1.54,
        "standard_s6": 3.01,
        "standard_s10": 5.89,
        "standard_s15": 11.20,
        "standard_s20": 21.76,
        "standard_s30": 40.96,
        "standard_s40": 79.87,
        "standard_s50": 147.46,
    }

    # VM compute hourly and monthly rates
    VM_RATES = {
        "standard_b2s": {"hourly": 0.0416, "monthly": 30.37, "ahb_hourly_saving": 0.018},
        "standard_d2s_v3": {"hourly": 0.096, "monthly": 70.08, "ahb_hourly_saving": 0.046},
        "standard_d4s_v3": {"hourly": 0.192, "monthly": 140.16, "ahb_hourly_saving": 0.092},
        "standard_d8s_v3": {"hourly": 0.384, "monthly": 280.32, "ahb_hourly_saving": 0.184},
        "standard_d2s_v5": {"hourly": 0.096, "monthly": 70.08, "ahb_hourly_saving": 0.046},
        "standard_d4s_v5": {"hourly": 0.192, "monthly": 140.16, "ahb_hourly_saving": 0.092},
        "standard_d8s_v5": {"hourly": 0.384, "monthly": 280.32, "ahb_hourly_saving": 0.184},
        "standard_e4s_v5": {"hourly": 0.252, "monthly": 183.96, "ahb_hourly_saving": 0.092},
        "standard_e8s_v5": {"hourly": 0.504, "monthly": 367.92, "ahb_hourly_saving": 0.184},
    }

    PUBLIC_IP_MONTHLY = 3.65 # Standard IPv4 public IP per month
    SNAPSHOT_GB_MONTHLY = 0.05 # Standard snapshot storage per GB-month
    APP_SERVICE_PLAN_BASIC = 54.75 # B1 plan monthly
    APP_SERVICE_PLAN_STANDARD = 73.00 # S1 plan monthly
    APP_SERVICE_PLAN_PREMIUM = 146.00 # P1v3 plan monthly

    @classmethod
    def get_app_service_plan_monthly_price(cls, sku_name: str = "", sku_tier: str = "", capacity: int = 1) -> float:
        name = (sku_name or "").upper()
        tier = (sku_tier or "").upper()
        cap = max(capacity or 1, 1)

        # Free & Shared Tiers
        if "F1" in name or "FREE" in tier:
            return 0.0
        if "D1" in name or "SHARED" in tier:
            return round(9.49 * cap, 2)

        # Basic Tiers
        if "B1" in name:
            return round(54.75 * cap, 2)
        if "B2" in name:
            return round(109.50 * cap, 2)
        if "B3" in name:
            return round(219.00 * cap, 2)
        if "BASIC" in tier:
            return round(cls.APP_SERVICE_PLAN_BASIC * cap, 2)

        # Standard Tiers
        if "S1" in name:
            return round(73.00 * cap, 2)
        if "S2" in name:
            return round(146.00 * cap, 2)
        if "S3" in name:
            return round(292.00 * cap, 2)
        if "STANDARD" in tier:
            return round(cls.APP_SERVICE_PLAN_STANDARD * cap, 2)

        # Premium Tiers (P1V2, P2V2, P3V2, P1V3, P2V3, P3V3)
        if "P1" in name:
            return round(146.00 * cap, 2)
        if "P2" in name:
            return round(292.00 * cap, 2)
        if "P3" in name:
            return round(584.00 * cap, 2)
        if "PREMIUM" in tier:
            return round(cls.APP_SERVICE_PLAN_PREMIUM * cap, 2)

        # Isolated Tiers
        if "I1" in name or "ISOLATED" in tier:
            return round(292.00 * cap, 2)
        if "I2" in name:
            return round(584.00 * cap, 2)
        if "I3" in name:
            return round(1168.00 * cap, 2)

        return round(cls.APP_SERVICE_PLAN_STANDARD * cap, 2)

    @classmethod
    def get_disk_monthly_price(cls, sku_tier: str, disk_size_gb: int) -> float:
        tier = (sku_tier or "Standard_LRS").lower()
        if "premium" in tier:
            prefix = "premium_p"
        elif "standardssd" in tier:
            prefix = "standardssd_e"
        else:
            prefix = "standard_s"

        if disk_size_gb <= 32:
            key = f"{prefix}4"
        elif disk_size_gb <= 64:
            key = f"{prefix}6"
        elif disk_size_gb <= 128:
            key = f"{prefix}10"
        elif disk_size_gb <= 256:
            key = f"{prefix}15"
        elif disk_size_gb <= 512:
            key = f"{prefix}20"
        elif disk_size_gb <= 1024:
            key = f"{prefix}30"
        elif disk_size_gb <= 2048:
            key = f"{prefix}40"
        else:
            key = f"{prefix}50"

        return cls.DISK_PRICING_TABLE.get(key, 19.71)

    @classmethod
    def get_disk_downgrade_savings(cls, current_sku: str, disk_size_gb: int) -> Tuple[float, str, float]:
        """
        Returns (current_price, proposed_sku, proposed_price).
        If currently Premium SSD, proposed is Standard SSD.
        """
        curr_price = cls.get_disk_monthly_price(current_sku, disk_size_gb)
        if "premium" in (current_sku or "").lower():
            proposed_sku = "StandardSSD_LRS"
            proposed_price = cls.get_disk_monthly_price("StandardSSD_LRS", disk_size_gb)
        else:
            proposed_sku = "Standard_LRS"
            proposed_price = cls.get_disk_monthly_price("Standard_LRS", disk_size_gb)
        return curr_price, proposed_sku, proposed_price

    @classmethod
    def get_vm_rates(cls, vm_size: str) -> Dict[str, float]:
        normalized = (vm_size or "").lower().replace(" ", "_")
        return cls.VM_RATES.get(normalized, {"hourly": 0.12, "monthly": 87.60, "ahb_hourly_saving": 0.05})
