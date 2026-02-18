"""Timezone-aware UTC timestamp utilities.

All backend code should use these helpers instead of datetime.utcnow()
or datetime.now(). This ensures every serialized timestamp includes a
+00:00 offset so JavaScript (and any other consumer) can correctly
convert to local time.
"""

from datetime import datetime, timezone


def now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def isonow() -> str:
    """Return the current UTC time as an ISO 8601 string with +00:00 offset."""
    return now().isoformat()


def parse_timestamp(iso_str: str) -> datetime:
    """Parse an ISO timestamp, assuming UTC if no timezone info.

    Handles legacy naive timestamps stored before the timezone fix.
    """
    dt = datetime.fromisoformat(iso_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
