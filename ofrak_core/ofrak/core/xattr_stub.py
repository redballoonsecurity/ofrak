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

    def _call(self, name_func, fd_func, *args):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def get(self, name, options=0):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def set(self, name, value, options=0):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def remove(self, name, options=0):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def list(self, options=0):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def __len__(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def __delitem__(self, item):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def __setitem__(self, item, value):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def __getitem__(self, item):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def iterkeys(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def has_key(self, item):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def clear(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def update(self, seq):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def copy(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def setdefault(self, k, d=""):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def keys(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def itervalues(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def values(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def iteritems(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)

    def items(self):
        frame = inspect.currentframe()
        _warn_user_no_xattr(inspect.getframeinfo(frame).function)


def listxattr(f, symlink=False):
    frame = inspect.currentframe()
    _warn_user_no_xattr(inspect.getframeinfo(frame).function)
    return tuple()


def getxattr(f, attr, symlink=False):
    frame = inspect.currentframe()
    _warn_user_no_xattr(inspect.getframeinfo(frame).function)
    return ""


def setxattr(f, attr, value, options=0, symlink=False):
    frame = inspect.currentframe()
    _warn_user_no_xattr(inspect.getframeinfo(frame).function)


def removexattr(f, attr, symlink=False):
    frame = inspect.currentframe()
    _warn_user_no_xattr(inspect.getframeinfo(frame).function)


def _warn_user_no_xattr(function_name: str) -> None:
    logging.warning(
        f"Function {function_name} not found. Library xattr is not available on Windows platforms. \
        Extended attributes will not be properly handled while using OFRAK on this platform. \
        If you require extended attributes, please use a platform that supports xattr."
    )
