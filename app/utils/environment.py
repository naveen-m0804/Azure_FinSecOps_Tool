"""
Azure Environment Resolution Utility
Implements comprehensive case-insensitive tag, resource name, and resource group
matching for Production and Test environments.
Handles all casing variations (UPPERCASE, lowercase, TitleCase, mixed-case) and combinations.
"""

import re
from typing import Dict, Any, Optional, List

# Regex matching production in all possible ways, casings, delimiters, and combinations
# e.g.: prod, PROD, Production, PRODUCTION, prd, PRD, live, LIVE,
#       prod-01, vm-prod-backend, Production-RG, rg-prd-eastus, _prod_, etc.
PROD_REGEX = re.compile(r"(?i)(^|[-_./\s])(prod|production|live|prd)([-_./\s\d]|$)", re.IGNORECASE)

# Regex matching test-related environments in all possible ways and combinations
# e.g.: test, TEST, testing, TESTING, qa, QA, uat, UAT, staging, STAGING, stage,
#       quality assurance, user acceptance testing, etc.
TEST_REGEX = re.compile(
    r"(?i)(^|[-_./\s])(test|testing|qa|uat|staging|stage|sandbox|poc|quality[_\s-]?assurance|user[_\s-]?acceptance[_\s-]?testing)([-_./\s\d]|$)",
    re.IGNORECASE
)

# Regex matching non-production (includes test + dev)
NON_PROD_REGEX = re.compile(
    r"(?i)(^|[-_./\s])(dev|development|test|testing|qa|uat|staging|stage|sandbox|poc|nonprod|non-production)([-_./\s\d]|$)",
    re.IGNORECASE
)

ENV_TAG_KEYS = [
    "environment",
    "env",
    "environmentname",
    "environmenttype",
    "envtype",
    "stage",
    "deploymentenvironment",
    "workloadtype",
    "targetenvironment",
]

def is_production_resource(
    tags: Optional[Dict[str, Any]] = None,
    resource_name: str = "",
    resource_group: str = "",
    prod_tags: Optional[List[str]] = None
) -> bool:
    """
    Checks if a resource is Production in ALL possible ways, casings, and combinations:
    - User-configured custom production tags (prod_tags)
    - Capitalized: PRODUCTION, PROD, PRD, LIVE
    - Lowercase: production, prod, prd, live
    - Mixed case: Production, Prod, Prd, Live, ProD
    - Prefixed/Suffixed: prod-01, vm_production, rg-prd-hub
    - Any tag key or tag value indicating production
    - Resource name or resource group name containing production indicators
    """
    # 1. Inspect tags
    if tags:
        for k, v in tags.items():
            if v is None:
                continue
            k_clean = str(k).strip()
            v_clean = str(v).strip()
            
            # Check user-configured prod_tags if provided
            if prod_tags:
                for pt in prod_tags:
                    pt_clean = pt.strip().lower()
                    if pt_clean and (pt_clean == v_clean.lower() or pt_clean == k_clean.lower() or re.search(rf"(^|[-_./\s]){re.escape(pt_clean)}([-_./\s\d]|$)", v_clean, re.I)):
                        return True

            # If tag key is an environment tag or value matches production
            if k_clean.lower() in ENV_TAG_KEYS or "env" in k_clean.lower():
                if PROD_REGEX.search(v_clean):
                    return True
            # Even if key is generic, check if value explicitly says production
            if v_clean.lower() in ["production", "prod", "prd", "live"]:
                return True

    # 2. Inspect Resource Name
    if resource_name and PROD_REGEX.search(resource_name):
        return True

    # 3. Inspect Resource Group
    if resource_group and PROD_REGEX.search(resource_group):
        return True

    return False

def is_test_environment(
    tags: Optional[Dict[str, Any]] = None,
    resource_name: str = "",
    resource_group: str = "",
    test_tags: Optional[List[str]] = None,
    prod_tags: Optional[List[str]] = None,
    target_tags: Optional[List[str]] = None
) -> bool:
    """
    Strictly verifies whether a resource belongs to a non-production/test-related environment
    (Test, Testing, QA, UAT, Staging, Dev, Sandbox, NonProd, or user-configured test_tags/target_tags).
    
    CRITICAL RULE:
    If the resource is identified as Production in ANY way/casing/combination,
    this function IMMEDIATELY returns False (!production).
    """
    # 1. Strict Exclusion: If it's production in any way -> NOT TEST
    if is_production_resource(tags, resource_name, resource_group, prod_tags=prod_tags):
        return False

    # 2. Inspect tags
    if tags:
        # Check user-configured target_tags with strict exact casing
        if target_tags:
            for tt in target_tags:
                tt_exact = str(tt).strip()
                if not tt_exact:
                    continue
                for k, v in tags.items():
                    if v is None:
                        continue
                    if tt_exact == str(k).strip() or tt_exact == str(v).strip():
                        return True

        tag_map = {str(k).strip().lower(): str(v).strip() for k, v in tags.items() if v is not None}
        
        # Check user-configured test_tags if provided
        if test_tags:
            for tt in test_tags:
                tt_clean = tt.strip().lower()
                if not tt_clean:
                    continue
                for k, v in tag_map.items():
                    if tt_clean == v.lower() or tt_clean == k:
                        return True

        for key in ENV_TAG_KEYS:
            if key in tag_map:
                val = tag_map[key]
                if TEST_REGEX.search(val):
                    return True

        # Check all tag values
        for v in tag_map.values():
            if v.lower() in ["test", "testing", "qa", "uat", "staging", "stage", "sandbox", "poc"]:
                return True

    # 3. Inspect resource name or resource group if tagged as test
    if resource_name and TEST_REGEX.search(resource_name):
        return True

    if resource_group and TEST_REGEX.search(resource_group):
        return True

    # 4. Check if resource name or resource group matches user-entered target_tags
    if target_tags:
        for tt in target_tags:
            tt_clean = tt.strip().lower()
            if tt_clean and (tt_clean in resource_name.lower() or tt_clean in resource_group.lower()):
                return True

    return False

def is_non_production_resource(
    tags: Optional[Dict[str, Any]] = None,
    resource_name: str = "",
    resource_group: str = "",
    test_tags: Optional[List[str]] = None,
    prod_tags: Optional[List[str]] = None,
    target_tags: Optional[List[str]] = None
) -> bool:
    """
    Verifies whether a resource belongs to any Non-Production environment
    (Dev, Test, QA, UAT, Staging, Sandbox, or user-configured test_tags/target_tags).
    
    CRITICAL RULE:
    If the resource is identified as Production in ANY way/casing/combination,
    this function IMMEDIATELY returns False (!production).
    """
    # 1. Strict Exclusion: If it's production in any way -> NOT NON-PROD
    if is_production_resource(tags, resource_name, resource_group, prod_tags=prod_tags):
        return False

    # 2. Inspect tags
    if tags:
        # Check user-configured target_tags with strict exact casing
        if target_tags:
            for tt in target_tags:
                tt_exact = str(tt).strip()
                if not tt_exact:
                    continue
                for k, v in tags.items():
                    if v is None:
                        continue
                    if tt_exact == str(k).strip() or tt_exact == str(v).strip():
                        return True

        tag_map = {str(k).strip().lower(): str(v).strip() for k, v in tags.items() if v is not None}
        
        if test_tags:
            for tt in test_tags:
                tt_clean = tt.strip().lower()
                if not tt_clean:
                    continue
                for k, v in tag_map.items():
                    if tt_clean == v.lower() or tt_clean == k:
                        return True

        for key in ENV_TAG_KEYS:
            if key in tag_map:
                val = tag_map[key]
                if NON_PROD_REGEX.search(val):
                    return True

        for v in tag_map.values():
            if v.lower() in ["dev", "development", "test", "testing", "qa", "uat", "staging", "sandbox", "nonprod"]:
                return True

    # 3. Inspect resource name / RG
    if resource_name and NON_PROD_REGEX.search(resource_name):
        return True

    if resource_group and NON_PROD_REGEX.search(resource_group):
        return True

    return False

def resolve_environment(
    tags: Optional[Dict[str, Any]] = None,
    resource_name: str = "",
    resource_group: str = "",
    prod_tags: Optional[List[str]] = None,
    test_tags: Optional[List[str]] = None,
    target_tags: Optional[List[str]] = None
) -> str:
    """
    Extracts and normalizes the environment name.
    If production is matched in any combination -> returns 'Production'.
    Otherwise resolves to QA, Test, UAT, Development, Staging, or Unassigned.
    """
    if is_production_resource(tags, resource_name, resource_group, prod_tags=prod_tags):
        return "Production"

    if tags:
        # Check target_tags with strict exact casing
        if target_tags:
            for tt in target_tags:
                tt_exact = str(tt).strip()
                for k, v in tags.items():
                    if v is not None and (tt_exact == str(k).strip() or tt_exact == str(v).strip()):
                        return tt_exact

        tag_map = {str(k).strip().lower(): str(v).strip() for k, v in tags.items() if v is not None}
        if test_tags:
            for tt in test_tags:
                tt_clean = tt.strip().lower()
                for k, v in tag_map.items():
                    if tt_clean == v.lower() or tt_clean == k:
                        return tt.capitalize()

        for key in ENV_TAG_KEYS:
            if key in tag_map and tag_map[key]:
                val = tag_map[key]
                val_lower = val.lower()
                if val_lower in ["test", "testing"]:
                    return "Test"
                if val_lower in ["qa", "quality assurance"]:
                    return "QA"
                if val_lower in ["uat", "user acceptance testing"]:
                    return "UAT"
                if val_lower in ["dev", "development"]:
                    return "Development"
                if val_lower in ["staging", "stage"]:
                    return "Staging"
                if val_lower in ["sandbox", "poc"]:
                    return "Sandbox"
                return val

    # Check name / RG tokens
    name_to_check = f"{resource_name} {resource_group}".lower()
    if any(tok in name_to_check for tok in ["-qa", "_qa", " qa ", "-uat", "_uat"]):
        return "QA"
    if any(tok in name_to_check for tok in ["-test", "_test", " test "]):
        return "Test"
    if any(tok in name_to_check for tok in ["-dev", "_dev", " dev ", "development"]):
        return "Development"
    if "staging" in name_to_check or "stage" in name_to_check:
        return "Staging"

    return "Unassigned"


def matches_target_tags(
    tags: Optional[Dict[str, Any]] = None,
    target_tags: Optional[List[str]] = None,
) -> bool:
    """
    If user entered target_tags, returns True ONLY if the resource's tags match
    at least one entered tag (key, value, or key=value / key:value, case-insensitive).
    If no target_tags were entered, returns True for all resources (tagged or untagged).
    """
    clean_targets = [str(t).strip().lower() for t in (target_tags or []) if str(t).strip()]
    if not clean_targets:
        return True
    if not tags or not isinstance(tags, dict):
        return False
    for tt in clean_targets:
        for k, v in tags.items():
            k_str = str(k).strip().lower()
            v_str = str(v).strip().lower() if v is not None else ""
            if tt == k_str or tt == v_str or tt == f"{k_str}={v_str}" or tt == f"{k_str}:{v_str}":
                return True
    return False
