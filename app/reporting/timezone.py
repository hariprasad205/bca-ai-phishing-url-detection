"""Timezone conversion helpers for user-requested report exports."""
from datetime import datetime, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def get_device_timezone(timezone_name: str | None) -> tzinfo:
    """Return the requested IANA timezone, defaulting to UTC when none is supplied."""
    if not timezone_name:
        return timezone.utc
    try:
        return ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as error:
        raise ValueError(f"Unknown timezone: {timezone_name}") from error


def format_local_timestamp(value: datetime | None, local_timezone: tzinfo) -> str:
    """Format a database timestamp in the selected timezone, treating naive values as UTC."""
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(local_timezone).strftime("%Y-%m-%d %H:%M:%S %Z")
