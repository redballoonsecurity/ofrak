import asyncio
import logging
from typing import Dict

import math
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass

from ofrak.component.analyzer import Analyzer
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource, ResourceFactory
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface

LOGGER = logging.getLogger(__name__)

try:
    from ofrak.core.entropy.entropy_c import entropy_c as entropy_func
except:
    from ofrak.core.entropy.entropy_py import entropy_py as entropy_func


@dataclass
class DataSummary(ResourceAttributes):
    """
    High-level summary of binary data.

    :ivar entropy_samples: Shannon entropy of the data. A description of Shannon entropy and how it
    can be used is [here](../../../../user-guide/key-concepts/gui/minimap.md#entropy-view).
    :ivar magnitude_samples: Sample of the binary data to put an upper limit on the displayed byte
    magnitudes; if the input data is smaller than this upper limit, all bytes are sampled.
    """

    entropy_samples: bytes
    magnitude_samples: bytes


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class DataSummaryCache(ResourceAttributes):
    cache_key: str


class DataSummaryAnalyzer(Analyzer[None, DataSummaryCache]):
    """
    Analyze binary data and return summaries of its structure via the entropy and magnitude of
    its bytes.
    """

    targets = ()  # Target any resource with data
    outputs = (DataSummaryCache,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self._cache_service = DataSummaryService()

    async def analyze(self, resource: Resource, config=None) -> DataSummaryCache:
        cache_info = await self._cache_service.compute(resource)
        return cache_info

    def get_data_summary(self, cache_info: DataSummaryCache) -> DataSummary:
        return self._cache_service.get_cache(cache_info)


def sample_entropy(
    data: bytes, resource_id: bytes, window_size=256, max_samples=2**20
) -> bytes:  # pragma: no cover
    """
    Return a list of entropy values where each value represents the Shannon entropy of the byte
    value distribution over a fixed-size, sliding window. If the entropy data is larger than a
    maximum size, summarize it by periodically sampling it.

    Shannon entropy represents how uniform a probability distribution is. Since more uniform
    implies less predictable (because the probability of any outcome is equally likely in a
    uniform distribution), a sample with higher entropy is "more random" than one with lower
    entropy. More here: <https://en.wikipedia.org/wiki/Entropy_(information_theory)>.
    """

    if len(data) < 256:
        return b""

    def log_percent(percent):  # pragma: no cover
        LOGGER.info(f"Entropy calculation {percent}% complete for {resource_id.hex()}")

    result = entropy_func(data, window_size, log_percent)

    if len(result) <= max_samples:
        return result

    # Sample the calculated array if it is too large
    skip = len(result) / max_samples
    return bytes(result[math.floor(i * skip)] for i in range(max_samples))


def sample_magnitude(data: bytes, max_samples=2**20) -> bytes:  # pragma: no cover
    if len(data) < max_samples:
        # TODO: Should this be a shallow copy instead?
        return data
    else:
        skip = len(data) / max_samples
        return bytes(data[math.floor(i * skip)] for i in range(max_samples))


class DataSummaryService:
    def __init__(self):
        self._cache: Dict[str, DataSummary] = {}
        self.pool = ProcessPoolExecutor()
        self.max_analysis_retries = 10

    async def compute(self, resource: Resource, depth=0) -> DataSummaryCache:
        if depth > self.max_analysis_retries:
            raise RuntimeError(
                f"Analysis process killed more than {self.max_analysis_retries} times. Aborting."
            )

        cache_key = resource.get_id().hex()
        data = await resource.get_data()

        try:
            entropy = await asyncio.get_running_loop().run_in_executor(
                self.pool, sample_entropy, data, resource.get_id()
            )
            magnitude = await asyncio.get_running_loop().run_in_executor(
                self.pool, sample_magnitude, data
            )
            self._cache[cache_key] = DataSummary(entropy, magnitude)
            return DataSummaryCache(cache_key)
        except BrokenProcessPool:
            # If the previous one was aborted, try again with a new pool
            self.pool = ProcessPoolExecutor()
            return await self.compute(resource, depth=depth + 1)

    def get_cache(self, cache_info: DataSummaryCache) -> DataSummary:
        return self._cache[cache_info.cache_key]
