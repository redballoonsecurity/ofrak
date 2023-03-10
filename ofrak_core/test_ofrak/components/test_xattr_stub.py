import os
import xattr

import pytest

import ofrak.core.xattr_stub as xattr_stub

EXAMPLE_DIRECTORY = os.path.join(os.path.dirname(__file__), "assets/")


@pytest.fixture(scope="session")
def move_to_test_directory():
    current_directory = os.getcwd()
    os.chdir(EXAMPLE_DIRECTORY)
    yield
    os.chdir(current_directory)


@pytest.fixture
async def xattr_stub_fixture():
    return xattr_stub.xattr(None)


@pytest.fixture
async def xattr_real_fixture():
    return xattr.xattr(os.path.join(EXAMPLE_DIRECTORY, "README.md"))


async def test_init(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.__init__(None)
    assert "Function __init__" in caplog.text
    assert type(value) == type(xattr_real_fixture.__init__(None))


async def test_repr(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.__repr__()
    assert "Function __repr__" in caplog.text
    assert type(value) == type(xattr_real_fixture.__repr__())


async def test_call(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture._call(None, None)
    assert "Function _call" in caplog.text
    # Not testing return type of _call because it is dependent on the function being called. Could
    # be either str or None. _call should only be called indirectly through methods like get()
    # or set(), which are being type tested.


async def test_get(xattr_stub_fixture, xattr_real_fixture, caplog):
    xattr_real_fixture.set("user.foo", b"bar")
    value = xattr_stub_fixture.get(None)
    assert "Function get" in caplog.text
    assert type(value) == type(xattr_real_fixture.get("user.foo"))


async def test_set(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.set(None, None)
    assert "Function set" in caplog.text
    assert type(value) == type(xattr_real_fixture.set("user.foo", b"bar"))


async def test_remove(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.remove(None)
    xattr_real_fixture.set("user.foo", b"bar")
    assert "Function remove" in caplog.text
    assert type(value) == type(xattr_real_fixture.remove("user.foo"))


async def test_list(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.list()
    assert "Function list" in caplog.text
    assert type(value) == type(xattr_real_fixture.list())


async def test_len(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.__len__()
    assert "Function __len__" in caplog.text
    assert type(value) == type(xattr_real_fixture.__len__())


async def test_delitem(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.__delitem__(None)
    xattr_real_fixture.set("user.foo", b"bar")
    assert "Function __delitem__" in caplog.text
    assert type(value) == type(xattr_real_fixture.__delitem__("user.foo"))


async def test_setitem(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.__setitem__(None, None)
    assert "Function __setitem__" in caplog.text
    assert type(value) == type(xattr_real_fixture.__setitem__("user.foo", b"bar"))


async def test_getitem(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.__getitem__(None)
    xattr_real_fixture.set("user.foo", b"bar")
    assert "Function __getitem__" in caplog.text
    assert type(value) == type(xattr_real_fixture.__getitem__("user.foo"))


async def test_iterkeys(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.iterkeys()
    assert "Function iterkeys" in caplog.text
    assert type(value) == type(xattr_real_fixture.iterkeys())


async def test_has_key(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.has_key(None)
    assert "Function has_key" in caplog.text
    assert type(value) == type(xattr_real_fixture.has_key("user.foo"))


async def test_clear(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.clear()
    assert "Function clear" in caplog.text
    assert type(value) == type(xattr_real_fixture.clear())


async def test_update(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.update(None)
    assert "Function update" in caplog.text
    assert type(value) == type(xattr_real_fixture.update({"user.foo": b"bar"}))


async def test_copy(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.copy()
    assert "Function copy" in caplog.text
    assert type(value) == type(xattr_real_fixture.copy())


async def test_setdefault(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.setdefault(None)
    assert "Function setdefault" in caplog.text
    assert type(value) == type(xattr_real_fixture.setdefault("user.foo"))


async def test_keys(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.keys()
    assert "Function keys" in caplog.text
    assert type(value) == type(xattr_real_fixture.keys())


async def test_itervalues(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.itervalues()
    assert type(value) == type(xattr_real_fixture.itervalues())
    next(value)
    assert "Function itervalues" in caplog.text


async def test_values(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.values()
    assert "Function values" in caplog.text
    assert type(value) == type(xattr_real_fixture.values())


async def test_iteritems(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.iteritems()
    assert type(value) == type(xattr_real_fixture.iteritems())
    next(value)
    assert "Function iteritems" in caplog.text


async def test_items(xattr_stub_fixture, xattr_real_fixture, caplog):
    value = xattr_stub_fixture.items()
    assert "Function items" in caplog.text
    assert type(value) == type(xattr_real_fixture.items())


async def test_listxattr(caplog):
    value = xattr_stub.listxattr(None)
    assert "Function listxattr" in caplog.text
    assert type(value) == type(xattr.listxattr(os.path.join(EXAMPLE_DIRECTORY, "README.md")))


async def test_getxattr(caplog):
    value = xattr_stub.getxattr(None, None)
    assert "Function getxattr" in caplog.text
    assert type(value) == type(
        xattr.getxattr(os.path.join(EXAMPLE_DIRECTORY, "README.md"), "user.foo")
    )


async def test_setxattr(caplog):
    value = xattr_stub.setxattr(None, None, None)
    assert "Function setxattr" in caplog.text
    assert type(value) == type(
        xattr.setxattr(os.path.join(EXAMPLE_DIRECTORY, "README.md"), "user.foo", b"bar")
    )


async def test_removexattr(caplog):
    value = xattr_stub.removexattr(None, None)
    assert "Function removexattr" in caplog.text
    assert type(value) == type(
        xattr.removexattr(os.path.join(EXAMPLE_DIRECTORY, "README.md"), "user.foo")
    )
