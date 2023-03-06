import os

import pytest

import ofrak.core.xattr_stub as xattr_stub

EXAMPLE_DIRECTORY = os.path.join(os.path.dirname(__file__), "assets/")
EXAMPLE_FILE = os.path.join(EXAMPLE_DIRECTORY, "README.md")


@pytest.fixture
def xattr_class_stub():
    stub = xattr_stub.xattr(EXAMPLE_FILE)
    return stub


def test_repr(xattr_class_stub, caplog):
    value = xattr_class_stub.__repr__()
    assert "Function __repr__" in caplog.text
    assert isinstance(value, str)


def test_get(xattr_class_stub, caplog):
    value = xattr_class_stub.get("user.foo")
    assert "Function get" in caplog.text
    assert value == b""


def test_set(xattr_class_stub, caplog):
    value = xattr_class_stub.set("user.baz", b"qux")
    assert "Function set" in caplog.text
    assert value is None


def test_remove(xattr_class_stub, caplog):
    value = xattr_class_stub.remove("user.foo")
    assert "Function remove" in caplog.text
    assert value is None


def test_list(xattr_class_stub, caplog):
    value = xattr_class_stub.list()
    assert "Function list" in caplog.text
    assert len(value) == 0


def test_len(xattr_class_stub, caplog):
    value = xattr_class_stub.__len__()
    assert "Function __len__" in caplog.text
    assert value == 0


def test_delitem(xattr_class_stub, caplog):
    value = xattr_class_stub.__delitem__("user.foo")
    assert "Function __delitem__" in caplog.text
    assert value is None


def test_setitem(xattr_class_stub, caplog):
    value = xattr_class_stub.__setitem__("user.baz", b"qux")
    assert "Function __setitem__" in caplog.text
    assert value is None


def test_getitem(xattr_class_stub, caplog):
    value = xattr_class_stub.__getitem__("user.foo")
    assert "Function __getitem__" in caplog.text
    assert value == b""


def test_iterkeys(xattr_class_stub, caplog):
    value = xattr_class_stub.iterkeys()
    assert "Function iterkeys" in caplog.text
    with pytest.raises(StopIteration):
        next(value)


def test_has_key(xattr_class_stub, caplog):
    value = xattr_class_stub.has_key("user.foo")
    assert "Function has_key" in caplog.text
    assert value is False


def test_clear(xattr_class_stub, caplog):
    value = xattr_class_stub.clear()
    assert "Function clear" in caplog.text
    assert value is None


def test_update(xattr_class_stub, caplog):
    value = xattr_class_stub.update({"user.foo": b"baz"})
    assert "Function update" in caplog.text
    assert value is None


def test_copy(xattr_class_stub, caplog):
    value = xattr_class_stub.copy()
    assert "Function copy" in caplog.text
    assert len(value) == 0


def test_setdefault(xattr_class_stub, caplog):
    value = xattr_class_stub.setdefault("user.foo")
    assert "Function setdefault" in caplog.text
    assert value == b""


def test_keys(xattr_class_stub, caplog):
    value = xattr_class_stub.keys()
    assert "Function keys" in caplog.text
    assert len(value) == 0


def test_itervalues(xattr_class_stub, caplog):
    value = xattr_class_stub.itervalues()
    assert next(value) == b""
    assert "Function itervalues" in caplog.text


def test_values(xattr_class_stub, caplog):
    value = xattr_class_stub.values()
    assert "Function values" in caplog.text
    assert len(value) == 0


def test_iteritems(xattr_class_stub, caplog):
    value = xattr_class_stub.iteritems()
    assert next(value) == ()
    assert "Function iteritems" in caplog.text


def test_items(xattr_class_stub, caplog):
    value = xattr_class_stub.items()
    assert "Function items" in caplog.text
    assert len(value) == 0


def test_listxattr(caplog):
    value = xattr_stub.listxattr(EXAMPLE_FILE)
    assert "Function listxattr" in caplog.text
    assert value == ()


def test_getxattr(caplog):
    value = xattr_stub.getxattr(EXAMPLE_FILE, "user.foo")
    assert "Function getxattr" in caplog.text
    assert value == b""


def test_setxattr(caplog):
    value = xattr_stub.setxattr(EXAMPLE_FILE, "user.baz", b"qux")
    assert "Function setxattr" in caplog.text
    assert value is None


def test_removexattr(caplog):
    value = xattr_stub.removexattr(EXAMPLE_FILE, "user.foo")
    assert "Function removexattr" in caplog.text
    assert value is None
