from typing import Callable, Optional

from ofrak_gpu.entropy import entropy


def entropy_gpu(
    data: bytes, window_size: int, log_percent: Optional[Callable[[int], None]] = None
) -> bytes:
    """
    Return a list of entropy values where each value represents the Shannon entropy of the byte
    value distribution over a fixed-size, sliding window.

    Unlike the python and C implementations, entropy_gpu slides the window window_size bytes at
    a time, not 1 byte at a time, for easier parallelization. This runs much faster and returns
    far fewer results.

    log_percent is currently unsupported
    """
    # TODO determine fastest device
    # TODO determine potential errors from this
    e = entropy(device_pref="AMD")
    results = e.chunked_entropy(window_size, data)

    return bytes(results)
