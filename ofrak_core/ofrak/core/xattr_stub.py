import inspect
import logging


LOGGER = logging.getLogger(__name__)


class xattr:
    """
    Stub library to support OFRAK on Windows and other platforms where xattr is not available.
    """

    def __init__(self, obj, options=0):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def __repr__(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return ""

    def get(self, name, options=0):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return b""

    def set(self, name, value, options=0):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return None

    def remove(self, name, options=0):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return None

    def list(self, options=0):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return []

    def __len__(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return 0

    def __delitem__(self, item):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return None

    def __setitem__(self, item, value):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return None

    def __getitem__(self, item):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return b""

    def iterkeys(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return iter(list())

    def has_key(self, item):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return False

    def clear(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return None

    def update(self, seq):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return None

    def copy(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return dict()

    def setdefault(self, k, d=""):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return b""

    def keys(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return []

    def itervalues(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        yield b""

    def values(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return []

    def iteritems(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        yield tuple()

    def items(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)
        return []


def listxattr(f, symlink=False):
    frame = inspect.currentframe()
    _warn_user_no_xattr(inspect.getframeinfo(frame).function)
    return tuple()


def getxattr(f, attr, symlink=False):
    frame = inspect.currentframe()
    _warn_user_no_xattr(inspect.getframeinfo(frame).function)
    return b""


def setxattr(f, attr, value, options=0, symlink=False):
    frame = inspect.currentframe()
    _warn_user_no_xattr(inspect.getframeinfo(frame).function)
    return None


def removexattr(f, attr, symlink=False):
    frame = inspect.currentframe()
    _warn_user_no_xattr(inspect.getframeinfo(frame).function)
    return None


def _warn_user_no_xattr(function_name: str) -> None:
    LOGGER.warning(
        f"Function {function_name} not found. Library xattr is not available on Windows platforms. \
        Extended attributes will not be properly handled while using OFRAK on this platform. \
        If you require extended attributes, please use a platform that supports xattr."
    )
