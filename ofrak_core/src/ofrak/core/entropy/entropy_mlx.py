import asyncio
import math
import threading
from array import array
from dataclasses import dataclass
from typing import Any, Dict, cast

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
_MLX_KERNEL: Any = None
_MLX_LOOKUP: Any = None
_MLX_LOCK = threading.Lock()


class MlxEntropyResource(metaclass=ResourceTag):
    """Opt-in marker for resources analyzed by ``MlxDataSummaryAnalyzer``."""


def _sample_positions(length: int, window_size: int, max_samples: int) -> array:
    output_length = max(0, length - window_size)
    if output_length <= max_samples:
        return array("q", range(output_length))
    return array("q", (index * output_length // max_samples for index in range(max_samples)))


def _lookup_table() -> array:
    return array(
        "q",
        (
            round(count * math.log2(count) * FIXED_SCALE) if count else 0
            for count in range(WINDOW_SIZE + 1)
        ),
    )


def sample_entropy_mlx(
    data: bytes,
    window_size: int = WINDOW_SIZE,
    max_samples: int = MAX_SAMPLES,
) -> bytes:
    if window_size != WINDOW_SIZE:
        raise ValueError("MLX entropy currently requires a 256-byte window")
    if len(data) <= window_size:
        return b""
    try:
        import mlx.core as mx
    except ImportError as error:
        raise ModuleNotFoundError(
            "The MLX entropy backend requires Apple Silicon and the optional "
            "'ofrak[entropy-mlx]' dependency"
        ) from error
    with _MLX_LOCK:
        return _sample_entropy_mlx_impl(mx, data, window_size, max_samples)


def _sample_entropy_mlx_impl(
    mx: Any, data: bytes, window_size: int, max_samples: int
) -> bytes:  # pragma: no cover - requires Apple Silicon and optional MLX dependency
    global _MLX_KERNEL, _MLX_LOOKUP

    positions = _sample_positions(len(data), window_size, max_samples)
    source = mx.array(cast(Any, memoryview(data)), dtype=mx.uint8)
    sample_positions = mx.array(cast(Any, memoryview(positions)), dtype=mx.int64)
    if _MLX_LOOKUP is None:
        lookup_values = _lookup_table()
        _MLX_LOOKUP = mx.array(cast(Any, memoryview(lookup_values)), dtype=mx.int64)
    if _MLX_KERNEL is None:
        _MLX_KERNEL = mx.fast.metal_kernel(
            name="ofrak_entropy_u8_w256",
            input_names=["data", "positions", "lookup"],
            output_names=["entropy"],
            source="""
                uint sample = threadgroup_position_in_grid.x;
                uint lane = thread_position_in_threadgroup.x;
                threadgroup atomic_uint histogram[256];
                threadgroup long contributions[256];

                atomic_store_explicit(&histogram[lane], 0u, memory_order_relaxed);
                threadgroup_barrier(mem_flags::mem_threadgroup);
                long position = positions[sample];
                uchar value = data[position + lane];
                atomic_fetch_add_explicit(&histogram[value], 1u, memory_order_relaxed);
                threadgroup_barrier(mem_flags::mem_threadgroup);

                uint count = atomic_load_explicit(&histogram[lane], memory_order_relaxed);
                contributions[lane] = lookup[count];
                threadgroup_barrier(mem_flags::mem_threadgroup);

                for (uint stride = 128u; stride > 0u; stride >>= 1u) {
                    if (lane < stride) {
                        contributions[lane] += contributions[lane + stride];
                    }
                    threadgroup_barrier(mem_flags::mem_threadgroup);
                }
                if (lane == 0u) {
                    const long denominator = 8796093022208L;
                    entropy[sample] = uchar(
                        (255L * (denominator - contributions[0])) / denominator
                    );
                }
            """,
        )
    result = _MLX_KERNEL(
        inputs=[source, sample_positions, _MLX_LOOKUP],
        template=[],
        grid=(len(positions) * window_size, 1, 1),
        threadgroup=(window_size, 1, 1),
        output_shapes=[(len(positions),)],
        output_dtypes=[mx.uint8],
    )[0]
    mx.eval(result)
    return bytes(memoryview(result))


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class MlxDataSummaryCache(ResourceAttributes):
    cache_key: str


class MlxDataSummaryAnalyzer(Analyzer[None, MlxDataSummaryCache]):
    """Compute data-summary entropy with an optional Apple Silicon MLX/Metal backend.

    This is a separate component from ``DataSummaryAnalyzer`` so both result caches can coexist on
    one resource. MLX is most useful for large resources or repeated analyses because its first run
    includes Metal JIT compilation.
    """

    targets = (MlxEntropyResource,)
    outputs = (MlxDataSummaryCache,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self._cache: Dict[str, DataSummary] = {}

    async def analyze(self, resource: Resource, config=None) -> MlxDataSummaryCache:
        data = await resource.get_data()
        entropy, magnitude = await asyncio.gather(
            asyncio.to_thread(sample_entropy_mlx, data),
            asyncio.to_thread(sample_magnitude, data),
        )
        cache_key = resource.get_id().hex()
        self._cache[cache_key] = DataSummary(entropy, magnitude)
        return MlxDataSummaryCache(cache_key)

    async def get_data_summary(self, resource: Resource) -> DataSummary:
        added_tag = False
        if not resource.has_tag(MlxEntropyResource):
            resource.add_tag(MlxEntropyResource)
            await resource.save()
            added_tag = True
        try:
            await resource.run(MlxDataSummaryAnalyzer)
        except Exception:
            if added_tag:
                resource.remove_tag(MlxEntropyResource)
                await resource.save()
            raise
        cache_info = resource.get_attributes(MlxDataSummaryCache)
        return self._cache[cache_info.cache_key]
