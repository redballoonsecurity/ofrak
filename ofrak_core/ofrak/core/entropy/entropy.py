import asyncio
import ctypes
import logging
import math
import os
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass

from ofrak.component.abstract import ComponentMissingDependencyError
from ofrak.component.analyzer import Analyzer
from ofrak.model.component_model import ComponentExternalTool
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource, ResourceFactory
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface

LOGGER = logging.getLogger(__name__)


C_LOG_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_uint8)

try:
    _lib_entropy = ctypes.cdll.LoadLibrary(
        os.path.abspath(os.path.join(os.path.dirname(__file__), "entropy.so.1"))
    )
    ENTROPY_FUNCTION = _lib_entropy.entropy

    ENTROPY_FUNCTION.argtypes = (
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        C_LOG_TYPE,
    )
    ENTROPY_FUNCTION.restype = ctypes.c_int
except OSError:
    ENTROPY_FUNCTION = None  # type: ignore


class _EntropyCTypesTool(ComponentExternalTool):
    def __init__(self):
        # TODO: Add docs page on building entropy.so.1
        super().__init__("entropy.so.1", None, None, None)

    def is_tool_installed(self) -> bool:
        return ENTROPY_FUNCTION is not None


_ENTROPY_SO_DEPENDENCY = _EntropyCTypesTool()


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class DataSummary(ResourceAttributes):
    entropy_samples: bytes
    magnitude_samples: bytes


class DataSummaryAnalyzer(Analyzer[None, DataSummary]):
    """
    Analyze binary data and return summaries of its structure via the entropy and magnitude of
    its bytes.
    """

    targets = ()  # Target any resource with data
    outputs = (DataSummary,)
    external_dependencies = (_ENTROPY_SO_DEPENDENCY,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self.pool = ProcessPoolExecutor()
        self.max_analysis_retries = 10

    async def analyze(self, resource: Resource, config=None, depth=0) -> DataSummary:
        if depth > self.max_analysis_retries:
            raise RuntimeError(
                f"Analysis process killed more than {self.max_analysis_retries} times. Aborting."
            )

        if not _ENTROPY_SO_DEPENDENCY.is_tool_installed():
            raise ComponentMissingDependencyError(self, _ENTROPY_SO_DEPENDENCY)

        data = await resource.get_data()
        # Run blocking computations in separate processes
        try:
            entropy = await asyncio.get_running_loop().run_in_executor(
                self.pool, sample_entropy, data, resource.get_id()
            )
            magnitude = await asyncio.get_running_loop().run_in_executor(
                self.pool, sample_magnitude, data
            )
            return DataSummary(entropy, magnitude)
        except BrokenProcessPool:
            # If the previous one was aborted, try again with a new pool
            self.pool = ProcessPoolExecutor()
            return await self.analyze(resource, config=config, depth=depth + 1)


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

    # Make the entropy buffer mutable to the external C function
    entropy = ctypes.create_string_buffer(len(data) - window_size)
    errval = ENTROPY_FUNCTION(data, len(data), entropy, window_size, C_LOG_TYPE(log_percent))
    if errval != 0:
        raise ValueError("Bad input to entropy function.")
    result = bytes(entropy.raw)

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
