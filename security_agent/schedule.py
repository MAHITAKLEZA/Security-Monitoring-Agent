"""Daily scan time helpers (local time of the machine running the agent)."""

from datetime import datetime, timedelta


def parse_daily_at(value):
    """'09:00' -> (9, 0); raises ValueError for anything that isn't a valid HH:MM time."""
    try:
        hour, minute = (int(part) for part in str(value).strip().split(":"))
    except ValueError:
        raise ValueError(f"schedule.daily_at must look like HH:MM (e.g. 09:00), got {value!r}") from None
    if not (0 <= hour < 24 and 0 <= minute < 60):
        raise ValueError(f"schedule.daily_at is not a valid time: {value!r}")
    return hour, minute


def next_daily_run(at, now=None):
    """Next local datetime at `at` ("HH:MM") strictly after `now`."""
    now = now or datetime.now()
    hour, minute = parse_daily_at(at)
    run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return run if run > now else run + timedelta(days=1)
