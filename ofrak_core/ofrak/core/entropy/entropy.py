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
    from ofrak.core.entropy.entropy_c import get_entropy_c

    entropy_func = get_entropy_c()
except:
    from ofrak.core.entropy.entropy_py import entropy_py as entropy_func


@dataclass
class DataSummary:
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
        self.pool = ProcessPoolExecutor()
        self.max_analysis_retries = 10
        self._cache: Dict[str, DataSummary] = {}

    async def analyze(self, resource: Resource, config=None) -> DataSummaryCache:
        data_summary = await self._compute_data_summary(resource)
        cache_key = resource.get_id().hex()
        self._cache[cache_key] = data_summary
        return DataSummaryCache(cache_key)

    async def get_data_summary(self, resource: Resource) -> DataSummary:
        await resource.run(DataSummaryAnalyzer)
        cache_info = resource.get_attributes(DataSummaryCache)
        return self._cache[cache_info.cache_key]

    async def _compute_data_summary(self, resource: Resource, depth=0) -> DataSummary:
        if depth > self.max_analysis_retries:
            raise RuntimeError(
                f"Analysis process killed more than {self.max_analysis_retries} times. Aborting."
            )
        try:
            data = await resource.get_data()
            entropy = await asyncio.get_running_loop().run_in_executor(
                self.pool, sample_entropy, data, resource.get_id()
            )
            magnitude = await asyncio.get_running_loop().run_in_executor(
                self.pool, sample_magnitude, data
            )
            data_summary = DataSummary(entropy, magnitude)
            return data_summary
        except BrokenProcessPool:
            # If the previous one was aborted, try again with a new pool
            self.pool = ProcessPoolExecutor()
            return await self._compute_data_summary(resource, depth=depth + 1)


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
