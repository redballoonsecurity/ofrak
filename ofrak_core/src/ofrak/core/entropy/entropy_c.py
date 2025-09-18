import ctypes
import os
from typing import Callable, Optional
import sysconfig


def get_entropy_c() -> Callable[[bytes, int, Optional[Callable[[int], None]]], bytes]:
    """
    This function ensures the dependency injector does not "discover" this module and error while
    trying to load the entropy_c library.
    """
    C_LOG_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_uint8)

    ext_suffix = sysconfig.get_config_var("EXT_SUFFIX")
    if not isinstance(ext_suffix, str):
        raise RuntimeError("Could not find compiled C library, no EXT_SUFFIX sysconfig var")

    _lib_entropy = ctypes.cdll.LoadLibrary(
        os.path.abspath(os.path.join(os.path.dirname(__file__), "entropy_c" + ext_suffix + ".1"))
    )
    C_ENTROPY_FUNC = _lib_entropy.entropy

    C_ENTROPY_FUNC.argtypes = (
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        C_LOG_TYPE,
    )
    C_ENTROPY_FUNC.restype = ctypes.c_int

    def entropy_c(
        data: bytes, window_size: int, log_percent: Optional[Callable[[int], None]] = None
    ) -> bytes:
        if log_percent is None:
            log_percent = lambda x: None

        if len(data) <= window_size:
            return b""
        entropy = ctypes.create_string_buffer(len(data) - window_size)
        errval = C_ENTROPY_FUNC(data, len(data), entropy, window_size, C_LOG_TYPE(log_percent))
        if errval != 0:
            raise ValueError("Bad input to entropy function.")
        return bytes(entropy.raw)

    return entropy_c
