from datetime import datetime
from datetime import timezone


def utcnow() -> datetime:
    """
    Returns the current time in UTC.

    :return: now in UTC
    """
    return datetime.now(timezone.utc)
