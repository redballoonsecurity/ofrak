"""
This module tests the unpack and pack functionality of OFRAK resources.

Requirements Mapping:
- REQ1.6: As an OFRAK user, I want to automatically unpack a binary, so I don't have to manually pick analyzers and unpackers.
  - test_unpack_pack_unpack: Tests that a resource can be automatically unpacked and packed
- REQ4.2: As an OFRAK user, I want to be able to repack an unpacked binary so that I can get a binary file that contains modifications.
  - test_unpack_pack_unpack: Tests that a resource can be repacked after being unpacked
"""

from gzip import GzipFile as _GzipFile

import pytest
from io import BytesIO


@pytest.fixture
def test_file(tmpdir):
    d = tmpdir.mkdir("gzip")
    fh = d.join("hello.gz")
    result = BytesIO()
    with _GzipFile(fileobj=result, mode="w") as gzip_file:
        gzip_file.write(b"hello world")
    fh.write_binary(result.getvalue())

    return fh.realpath()


async def test_unpack_pack_unpack(ofrak_context, test_file):
    """
    Tests that a resource can be automatically unpacked and packed (REQ1.6).

    This test verifies that:
    - A resource can be automatically unpacked without manual analyzer/unpacker selection
    - The resource can be packed after unpacking
    - The resource can be unpacked again after repacking
    """
    root_resource = await ofrak_context.create_root_resource_from_file(test_file)

    await root_resource.unpack()
    children1 = await root_resource.get_children()
    assert 1 == len(list(children1))

    # Children should be deleted after packing
    await root_resource.pack()
    children2 = await root_resource.get_children()
    assert 0 == len(list(children2))

    # Resource should now be ready to be unpacked again
    await root_resource.unpack()
    children3 = await root_resource.get_children()
    assert 1 == len(list(children3))
