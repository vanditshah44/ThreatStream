from __future__ import annotations

from app.collectors.base import FeedCollector
from app.collectors.cisa_kev import CisaKevCollector
from app.collectors.openphish import OpenPhishCollector
from app.collectors.ransomware_live import RansomwareLiveCollector
from app.collectors.urlhaus import URLHausCollector
from app.models.enums import FeedSource


class CollectorRegistry:
    def __init__(self) -> None:
        self._collectors: dict[FeedSource, FeedCollector] = {
            FeedSource.CISA_KEV: CisaKevCollector(),
            FeedSource.URLHAUS: URLHausCollector(),
            FeedSource.OPENPHISH: OpenPhishCollector(),
            FeedSource.RANSOMWARE_LIVE: RansomwareLiveCollector(),
        }

    def get(self, source: FeedSource) -> FeedCollector:
        return self._collectors[source]

    def available_sources(self) -> list[FeedSource]:
        return list(self._collectors.keys())

