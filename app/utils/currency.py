from typing import Optional, Dict

CURRENCY_SYMBOLS: Dict[str, str] = {
    "USD": "$",
    "EUR": "€",
    "GBP": "£",
    "INR": "₹",
    "JPY": "¥",
    "AUD": "A$",
    "CAD": "C$",
    "CHF": "CHF ",
    "CNY": "¥",
    "BRL": "R$",
}

def format_currency(amount: Optional[float], currency: Optional[str] = "USD", decimals: int = 2) -> str:
    if amount is None:
        return "N/A"
    curr = (currency or "USD").upper()
    symbol = CURRENCY_SYMBOLS.get(curr, f"{curr} ")
    formatted_number = f"{amount:,.{decimals}f}"
    return f"{symbol}{formatted_number}"

def validate_same_currency(c1: Optional[str], c2: Optional[str]) -> bool:
    if not c1 or not c2:
        return True
    return c1.upper() == c2.upper()
