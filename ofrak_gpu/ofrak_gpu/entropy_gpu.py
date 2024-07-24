import pyopencl as cl  # type: ignore
import logging
from ofrak_gpu.entropy import entropy
from numpy import ndarray
from typing import Callable, Optional, Tuple


def pick_pyopencl_device(log_platforms: bool = False) -> Tuple[str, str]:
    """
    Picks the best PyOpencl device to run the calculation on.
    Currently picks the device with the highest max_compute_units.

    :raises RuntimeError: if no platform or device can be found
    :return: A tuple: (chosen platform name, chosen device name)
    :rtype: Tuple[str, str]
    """
    try:
        cl_platforms = cl.get_platforms()

        if len(cl_platforms) == 0:
            raise RuntimeError("pyopencl.get_platforms found no platforms!")
    except cl.LogicError:
        raise RuntimeError(
            "No PyOpenCL platforms found. \
                Cannot proceed with GPU-bound entropy calcuation!"
        )

    chosen_platform: str
    chosen_device: str
    most_compute_units = 0

    for platform in cl_platforms:
        try:
            devices = platform.get_devices()
        except:
            logging.warning(
                f"Exception encountered in get_devices() for pyopencl platform '{platform.name.strip()}'"
            )
            continue  # Skip this platform

        for device in devices:
            logging.debug(
                f"Found device {device.name.strip()} on platform {platform.name.strip()}, with max compute units = {device.max_compute_units}"
            )
            # Choose this device, if it's the best we've seen so far
            if device.max_compute_units > most_compute_units:
                try:
                    chosen_platform = platform.name.strip()
                    chosen_device = device.name.strip()
                    most_compute_units = device.max_compute_units
                except:
                    logging.warning(f"Device {device} missing fields")
                    continue  # This device is missing info

    if chosen_device is None:
        raise RuntimeError(
            "PyOpenCL plaftorm(s) found, but no PyOpenCL devices found. "
            "Cannot proceed with GPU-bound entropy calcuation!"
        )

    return chosen_platform, chosen_device


def entropy_gpu(
    data: ndarray, window_size: int, log_percent: Optional[Callable[[int], None]] = None
) -> bytes:
    """
    Return a list of entropy values where each value represents the Shannon entropy of the byte
    value distribution over a fixed-size, sliding window.

    Unlike the python and C implementations, entropy_gpu slides the window window_size bytes at
    a time, not 1 byte at a time, for easier parallelization. This runs much faster but returns
    far fewer results.

    :param data: The raw data to compute the entropy of, in a numpy.ndarray
    :type data: numpy.ndarray
    :param window_size: The size of the sliding window in which entropy is computed
    :type window_size: int
    :param log_percent: Currently unsupported
    :type log_percent: Callable[[int], None], optional
    :raises RuntimeError: if pick_pyopencl_device() or chunked_entropy calculation fails
    :raises AttributeError: if the Futhark-generated ofrak_gpu.entropy library has changed
    :return: Data's entropy values. Each returned byte is the entropy over window_size bytes.
    :rtype: bytes
    """
    chosen_platform, chosen_device = pick_pyopencl_device()
    try:
        Entropy = entropy(
            platform_pref=chosen_platform, device_pref=chosen_device, interactive=False
        )
    except Exception as e:
        raise RuntimeError(
            "Failed to instantiate futhark-generated pyopencl entropy class. "
            "Cannot proceed with GPU-bound entropy calcuation!"
            f"Encountered {type(e).__name__}: {e}"
        )
    try:
        raw_results: cl.array.Array = Entropy.chunked_entropy(window_size, data)
    except AttributeError:
        raise AttributeError(
            "Futhark-generated pyopencl library no longer has a chunked_entropy method! "
            "Is the chunked_entropy function marked as an entry point? "
            "Was entropy.py compiled with `futhark pyopencl --library`?"
        )
    except Exception as e:
        raise RuntimeError(
            "Futhark-generated chunked_entropy() failed. "
            "Cannot proceed with GPU-bound entropy calcuation!"
            f"Encountered {type(e).__name__}: {e}"
        )

    try:
        # This can raise TypeError, ValueError
        results_array: ndarray = raw_results.get()
    except (TypeError, ValueError):
        raise RuntimeError(
            "pyopencl.array.Array to ndarray conversion failed. "
            "Cannot proceed with GPU-bound entropy calcuation!"
        )

    return results_array.tobytes()
