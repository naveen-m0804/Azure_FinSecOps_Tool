import re

GUID_REGEX = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

def is_valid_guid(val: str) -> bool:
    if not val or not isinstance(val, str):
        return False
    return bool(GUID_REGEX.match(val.strip()))
