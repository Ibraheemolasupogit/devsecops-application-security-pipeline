"""Clock abstractions for deterministic tests."""

from collections.abc import Callable
from datetime import datetime

from genomic_research_access_api.domain.models import utc_now

Clock = Callable[[], datetime]


def system_clock() -> datetime:
    return utc_now()
