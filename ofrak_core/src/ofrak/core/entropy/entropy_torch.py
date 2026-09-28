import asyncio
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ofrak.component.analyzer import Analyzer
from ofrak.model.resource_model import ResourceAttributes
from ofrak.model.tag_model import ResourceTag
from ofrak.resource import Resource, ResourceFactory
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface

from .entropy import DataSummary, sample_magnitude

WINDOW_SIZE = 256
MAX_SAMPLES = 2**20
FIXED_SCALE = 2**32
MAX_ENTROPY_BITS = WINDOW_SIZE * 8


class TorchEntropyResource(metaclass=ResourceTag):
    """Opt-in marker for resources analyzed by ``TorchDataSummaryAnalyzer``."""


def _positions(length: int, window_size: int, max_samples: int):
    import torch

    output_length = max(0, length - window_size)
    if output_length <= max_samples:
        return torch.arange(output_length, dtype=torch.int64)
    skip = output_length / max_samples
    return torch.floor(torch.arange(max_samples, dtype=torch.float64) * skip).to(torch.int64)


def _lookup_table() -> List[int]:
    return [
        round(count * math.log2(count) * FIXED_SCALE) if count else 0
        for count in range(WINDOW_SIZE + 1)
    ]


def sample_entropy_torch(
    data: bytes,
    window_size: int = WINDOW_SIZE,
    max_samples: int = MAX_SAMPLES,
    batch_size: int = 4096,
    device: Optional[str] = None,
) -> bytes:
    if window_size != WINDOW_SIZE:
        raise ValueError("Torch entropy currently requires a 256-byte window")
    if len(data) <= window_size:
        return b""
    try:
        import torch
    except ImportError as error:
        raise ModuleNotFoundError(
            "The PyTorch entropy backend requires the optional 'ofrak[entropy-torch]' dependency"
        ) from error

    if device is None:
        device = (
            "cuda"
            if torch.cuda.is_available()
            else "mps" if torch.backends.mps.is_available() else "cpu"
        )

    positions = _positions(len(data), window_size, max_samples)
    source = torch.frombuffer(bytearray(data), dtype=torch.uint8).to(device)
    columns = torch.arange(window_size, dtype=torch.int64, device=device)
    table = torch.tensor(_lookup_table(), dtype=torch.int64, device=device)
    denominator = MAX_ENTROPY_BITS * FIXED_SCALE
    output = bytearray()
    for start in range(0, len(positions), batch_size):
        batch_positions = positions[start : start + batch_size].to(device)
        windows = source[batch_positions[:, None] + columns[None, :]]
        ordered = windows.sort(dim=1).values
        boundaries = torch.cat(
            (
                torch.ones((len(ordered), 1), dtype=torch.int32, device=device),
                (ordered[:, 1:] != ordered[:, :-1]).to(torch.int32),
            ),
            dim=1,
        )
        run_ids = boundaries.cumsum(dim=1) - 1
        counts = torch.zeros((len(ordered), window_size), dtype=torch.int32, device=device)
        counts.scatter_add_(1, run_ids.to(torch.int64), torch.ones_like(run_ids, dtype=torch.int32))
        weighted = table[counts.to(torch.int64)].sum(dim=1)
        quantized = torch.div(255 * (denominator - weighted), denominator, rounding_mode="floor")
        output.extend(quantized.to(torch.uint8).cpu().numpy().tobytes())
    return bytes(output)


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class TorchDataSummaryCache(ResourceAttributes):
    cache_key: str


class TorchDataSummaryAnalyzer(Analyzer[None, TorchDataSummaryCache]):
    """Compute data-summary entropy with an optional PyTorch tensor backend (CUDA/MPS/CPU).

    This is a separate component from ``DataSummaryAnalyzer`` so both result caches can coexist on
    one resource.
    """

    targets = (TorchEntropyResource,)
    outputs = (TorchDataSummaryCache,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self._cache: Dict[str, DataSummary] = {}

    async def analyze(self, resource: Resource, config=None) -> TorchDataSummaryCache:
        data = await resource.get_data()
        entropy, magnitude = await asyncio.gather(
            asyncio.to_thread(sample_entropy_torch, data),
            asyncio.to_thread(sample_magnitude, data),
        )
        cache_key = resource.get_id().hex()
        self._cache[cache_key] = DataSummary(entropy, magnitude)
        return TorchDataSummaryCache(cache_key)

    async def get_data_summary(self, resource: Resource) -> DataSummary:
        added_tag = False
        if not resource.has_tag(TorchEntropyResource):
            resource.add_tag(TorchEntropyResource)
            await resource.save()
            added_tag = True
        try:
            await resource.run(TorchDataSummaryAnalyzer)
        except Exception:
            if added_tag:
                resource.remove_tag(TorchEntropyResource)
                await resource.save()
            raise
        cache_info = resource.get_attributes(TorchDataSummaryCache)
        return self._cache[cache_info.cache_key]
