import os
import xattr

import pytest

import ofrak.core.xattr_stub as xattr_stub

EXAMPLE_DIRECTORY = os.path.join(os.path.dirname(__file__), "assets/")
EXAMPLE_FILE = os.path.join(EXAMPLE_DIRECTORY, "README.md")


@pytest.fixture
def xattr_class_stub():
    stub = xattr_stub.xattr(EXAMPLE_FILE)
    stub.set("user.foo", b"bar")
    yield stub
    stub.clear()


@pytest.fixture
def xattr_class_real():
    real = xattr.xattr(EXAMPLE_FILE)
    real.set("user.foo", b"bar")
    yield real
    real.clear()


@pytest.fixture
def xattr_func_stub():
    stub = xattr_stub.setxattr(EXAMPLE_FILE, "user.foo", b"bar")
    yield
    xattr_stub.removexattr(EXAMPLE_FILE, "user.foo")


@pytest.fixture
def xattr_func_real():
    real = xattr.setxattr(EXAMPLE_FILE, "user.foo", b"bar")
    yield
    xattr.removexattr(EXAMPLE_FILE, "user.foo")


def test_init(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.__init__(EXAMPLE_FILE)
    assert "Function __init__" in caplog.text
    assert type(value) == type(xattr_class_real.__init__(EXAMPLE_FILE))


def test_repr(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.__repr__()
    assert "Function __repr__" in caplog.text
    assert type(value) == type(xattr_class_real.__repr__())


def test_call(xattr_class_stub, caplog):
    value = xattr_class_stub._call(None, None)
    assert "Function _call" in caplog.text
    # Not testing return type of _call because it is dependent on the function being called. Could
    # be either str or None. _call should only be called indirectly through methods like get()
    # or set(), which are being type tested.


def test_get(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.get("user.foo")
    assert "Function get" in caplog.text
    assert type(value) == type(xattr_class_real.get("user.foo"))


def test_set(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.set("user.baz", b"qux")
    assert "Function set" in caplog.text
    assert type(value) == type(xattr_class_real.set("user.baz", b"qux"))


def test_remove(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.remove("user.foo")
    assert "Function remove" in caplog.text
    assert type(value) == type(xattr_class_real.remove("user.foo"))


def test_list(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.list()
    assert "Function list" in caplog.text
    assert type(value) == type(xattr_class_real.list())


def test_len(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.__len__()
    assert "Function __len__" in caplog.text
    assert type(value) == type(xattr_class_real.__len__())


def test_delitem(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.__delitem__("user.foo")
    assert "Function __delitem__" in caplog.text
    assert type(value) == type(xattr_class_real.__delitem__("user.foo"))


def test_setitem(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.__setitem__("user.baz", b"qux")
    assert "Function __setitem__" in caplog.text
    assert type(value) == type(xattr_class_real.__setitem__("user.baz", b"qux"))


def test_getitem(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.__getitem__("user.foo")
    assert "Function __getitem__" in caplog.text
    assert type(value) == type(xattr_class_real.__getitem__("user.foo"))


def test_iterkeys(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.iterkeys()
    assert "Function iterkeys" in caplog.text
    assert type(value) == type(xattr_class_real.iterkeys())


def test_has_key(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.has_key("user.foo")
    assert "Function has_key" in caplog.text
    assert type(value) == type(xattr_class_real.has_key("user.foo"))


def test_clear(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.clear()
    assert "Function clear" in caplog.text
    assert type(value) == type(xattr_class_real.clear())


def test_update(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.update({"user.foo": b"baz"})
    assert "Function update" in caplog.text
    assert type(value) == type(xattr_class_real.update({"user.foo": b"baz"}))


def test_copy(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.copy()
    assert "Function copy" in caplog.text
    assert type(value) == type(xattr_class_real.copy())


def test_setdefault(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.setdefault("user.foo")
    assert "Function setdefault" in caplog.text
    assert type(value) == type(xattr_class_real.setdefault("user.foo"))


def test_keys(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.keys()
    assert "Function keys" in caplog.text
    assert type(value) == type(xattr_class_real.keys())


def test_itervalues(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.itervalues()
    assert type(value) == type(xattr_class_real.itervalues())
    next(value)
    assert "Function itervalues" in caplog.text


def test_values(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.values()
    assert "Function values" in caplog.text
    assert type(value) == type(xattr_class_real.values())


def test_iteritems(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.iteritems()
    assert type(value) == type(xattr_class_real.iteritems())
    next(value)
    assert "Function iteritems" in caplog.text


def test_items(xattr_class_stub, xattr_class_real, caplog):
    value = xattr_class_stub.items()
    assert "Function items" in caplog.text
    assert type(value) == type(xattr_class_real.items())


def test_listxattr(xattr_func_stub, xattr_func_real, caplog):
    value = xattr_stub.listxattr(EXAMPLE_FILE)
    assert "Function listxattr" in caplog.text
    assert type(value) == type(xattr.listxattr(EXAMPLE_FILE))


def test_getxattr(xattr_func_stub, xattr_func_real, caplog):
    value = xattr_stub.getxattr(EXAMPLE_FILE, "user.foo")
    assert "Function getxattr" in caplog.text
    assert type(value) == type(xattr.getxattr(EXAMPLE_FILE, "user.foo"))


def test_setxattr(xattr_func_stub, xattr_func_real, caplog):
    value = xattr_stub.setxattr(EXAMPLE_FILE, "user.baz", b"qux")
    assert "Function setxattr" in caplog.text
    assert type(value) == type(xattr.setxattr(EXAMPLE_FILE, "user.baz", b"qux"))

    xattr_stub.removexattr(EXAMPLE_FILE, "user.baz")
    xattr.removexattr(EXAMPLE_FILE, "user.baz")


def test_removexattr(xattr_func_stub, xattr_func_real, caplog):
    value = xattr_stub.removexattr(EXAMPLE_FILE, "user.foo")
    assert "Function removexattr" in caplog.text
    assert type(value) == type(xattr.removexattr(EXAMPLE_FILE, "user.foo"))

    # Reset xattrs so that teardown cleans them up
    xattr_stub.setxattr(EXAMPLE_FILE, "user.foo", b"bar")
    xattr.setxattr(EXAMPLE_FILE, "user.foo", b"bar")
