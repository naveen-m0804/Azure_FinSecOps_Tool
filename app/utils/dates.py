import datetime
from typing import Tuple

def get_previous_calendar_month(reference_date: datetime.date = None) -> Tuple[str, str]:
    """
    Returns (start_date, end_date) as YYYY-MM-DD for the previous complete calendar month.
    """
    today = reference_date or datetime.date.today()
    first_of_this_month = today.replace(day=1)
    last_day_prev_month = first_of_this_month - datetime.timedelta(days=1)
    first_day_prev_month = last_day_prev_month.replace(day=1)
    return (
        first_day_prev_month.strftime("%Y-%m-%d"),
        last_day_prev_month.strftime("%Y-%m-%d")
    )

def get_current_month_to_date(reference_date: datetime.date = None) -> Tuple[str, str]:
    """
    Returns (start_date, end_date) as YYYY-MM-DD for current month to date.
    """
    today = reference_date or datetime.date.today()
    first_day = today.replace(day=1)
    return (
        first_day.strftime("%Y-%m-%d"),
        today.strftime("%Y-%m-%d")
    )

def get_cutoff_date(days: int = 365, reference_date: datetime.datetime = None) -> datetime.datetime:
    """
    Returns cutoff datetime N days prior to reference datetime.
    """
    now = reference_date or datetime.datetime.now(datetime.timezone.utc)
    return now - datetime.timedelta(days=days)

def get_observation_window(days: int = 30) -> Tuple[str, str]:
    """
    Returns ISO 8601 strings (start_time, end_time) for metric queries.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(days=days)
    return (start.isoformat(), now.isoformat())
