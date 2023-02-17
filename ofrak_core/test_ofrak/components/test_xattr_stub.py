import pytest

import ofrak.core.xattr_stub as xattr_stub


@pytest.fixture
async def xattr():
    return xattr_stub.xattr(None)


async def test_init(xattr, caplog):
    xattr.__init__(None)
    assert "Function __init__" in caplog.text


async def test_repr(xattr, caplog):
    xattr.__repr__()
    assert "Function __repr__" in caplog.text


async def test_call(xattr, caplog):
    xattr._call(None, None)
    assert "Function _call" in caplog.text


async def test_get(xattr, caplog):
    xattr.get(None)
    assert "Function get" in caplog.text


async def test_set(xattr, caplog):
    xattr.set(None, None)
    assert "Function set" in caplog.text


async def test_remove(xattr, caplog):
    xattr.remove(None)
    assert "Function remove" in caplog.text


async def test_list(xattr, caplog):
    xattr.list()
    assert "Function list" in caplog.text


async def test_len(xattr, caplog):
    xattr.__len__()
    assert "Function __len__" in caplog.text


async def test_delitem(xattr, caplog):
    xattr.__delitem__(None)
    assert "Function __delitem__" in caplog.text


async def test_setitem(xattr, caplog):
    xattr.__setitem__(None, None)
    assert "Function __setitem__" in caplog.text


async def test_getitem(xattr, caplog):
    xattr.__getitem__(None)
    assert "Function __getitem__" in caplog.text


async def test_iterkeys(xattr, caplog):
    xattr.iterkeys()
    assert "Function iterkeys" in caplog.text


async def test_has_key(xattr, caplog):
    xattr.has_key(None)
    assert "Function has_key" in caplog.text


async def test_clear(xattr, caplog):
    xattr.clear()
    assert "Function clear" in caplog.text


async def test_update(xattr, caplog):
    xattr.update(None)
    assert "Function update" in caplog.text


async def test_copy(xattr, caplog):
    xattr.copy()
    assert "Function copy" in caplog.text


async def test_setdefault(xattr, caplog):
    xattr.setdefault(None)
    assert "Function setdefault" in caplog.text


async def test_keys(xattr, caplog):
    xattr.keys()
    assert "Function keys" in caplog.text


async def test_itervalues(xattr, caplog):
    xattr.itervalues()
    assert "Function itervalues" in caplog.text


async def test_values(xattr, caplog):
    xattr.values()
    assert "Function values" in caplog.text


async def test_iteritems(xattr, caplog):
    xattr.iteritems()
    assert "Function iteritems" in caplog.text


async def test_items(xattr, caplog):
    xattr.items()
    assert "Function items" in caplog.text


async def test_listxattr(caplog):
    xattr_stub.listxattr(None)
    assert "Function listxattr" in caplog.text


async def test_getxattr(caplog):
    xattr_stub.getxattr(None, None)
    assert "Function getxattr" in caplog.text


async def test_setxattr(caplog):
    xattr_stub.setxattr(None, None, None)
    assert "Function setxattr" in caplog.text


async def test_removexattr(caplog):
    xattr_stub.removexattr(None, None)
    assert "Function removexattr" in caplog.text
