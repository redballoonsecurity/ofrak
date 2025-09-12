import logging
import math
from typing import Callable, List, Optional


def entropy_py(
    data: bytes, window_size: int, log_percent: Optional[Callable[[int], None]] = None
) -> bytes:
    """
    Return a list of entropy values where each value represents the Shannon entropy of the byte
    value distribution over a fixed-size, sliding window.
    """
    if log_percent is None:
        log_percent = lambda x: None
    else:
        # Sort of hacky way to know we are being called from the tests and don't need to log this
        logging.warning(
            f"Using the Python implementation of the Shannon entropy calculation! This is potentially "
            f"very slow, and is only used when the C extension cannot be built/found."
        )

    # Create a histogram, and populate it with initial values
    histogram = [0] * 256
    for b in data[:window_size]:
        histogram[b] += 1

    # Calculate the entropy using a sliding window
    entropy = [0] * (len(data) - window_size)
    last_percent_logged = 0
    for i in range(len(entropy)):
        entropy[i] = math.floor(255 * _shannon_entropy(histogram, window_size))
        histogram[data[i]] -= 1
        histogram[data[i + window_size]] += 1
        percent = int((i * 100) / len(data))
        if percent > last_percent_logged and percent % 10 == 0:
            log_percent(percent)
            last_percent_logged = percent
    return bytes(entropy)


def _shannon_entropy(distribution: List[int], window_size: int) -> float:
    """
    Return the Shannon entropy of the input probability distribution (represented as a histogram
    counting byte occurrences over a window of known size).

    Shannon entropy represents how uniform a probability distribution is. Since more uniform
    implies less predictable (because the probability of any outcome is equally likely in a
    uniform distribution), a sample with higher entropy is "more random" than one with lower
    entropy. More here: <https://en.wikipedia.org/wiki/Entropy_(information_theory)>.
    """

    result = 0.0
    for num_occurrences in distribution:
        probability = num_occurrences / window_size
        # Note that the zero check is required because the domain of log2 is the positive reals
        result += probability * math.log2(probability) if probability != 0.0 else 0.0
    return -result / math.log2(window_size)
