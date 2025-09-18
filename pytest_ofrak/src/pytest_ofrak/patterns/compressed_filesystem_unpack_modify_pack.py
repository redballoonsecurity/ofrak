from abc import ABC
from typing import Optional

import pytest

from ofrak import OFRAKContext
from ofrak.model.tag_model import ResourceTag
from ofrak.resource import Resource
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern


class CompressedFileUnpackModifyPackPattern(UnpackModifyPackPattern, ABC):
    """
    Generic test pattern for unpackers/packers targeting compressed file types. The test expects
    to create an initial compressed file with some known data, unpack it, modify the unpacked
    child by changing the string data, repack it, then verify the repacked file by independently
    decompressing it and asserting the data is equal to the expected repacked string.

    Subclasses should implement:

    :async def verify(self, repacked_root_resource: Resource):

    :def create_test_file(self):
    """

    INITIAL_DATA: bytes = b"hello world\n"
    EXPECTED_REPACKED_DATA: bytes = b"hello ofrak\n"

    @property
    def expected_tag(self) -> Optional[ResourceTag]:
        """
        Optionally check that the root_resource has a specific flag after the `unpack` method is
        run. In other words, if ``expected_tag`` is set then this will also test that the root
        resource is automatically identified.
        Set ``expected_tag`` like this:

        class TestExampleFilesystem(CompressedFileUnpackModifyPackPattern):
            expected_tag = ExampleTag

            ...

        Or omit it to skip this check.
        """
        return None

    @pytest.fixture(autouse=True)
    def create_test_file(self):
        """
        Override this method with a fixture which creates the initial compressed file to unpack.
        The file should be compressed with the relevant compression scheme and its uncompressed
        data should be CompressedFileUnpackModifyPackPattern.INITIAL_DATA
        :return:
        """
        self._test_file = None

    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        assert self._test_file
        return await ofrak_context.create_root_resource_from_file(self._test_file)

    async def unpack(self, root_resource: Resource):
        await root_resource.unpack()
        if self.expected_tag:
            assert root_resource.has_tag(self.expected_tag)

    async def repack(self, modified_root_resource: Resource):
        await modified_root_resource.pack()

        children = await modified_root_resource.get_children()
        assert 0 == len(list(children))

    async def modify(self, unpacked_root_resource: Resource):
        resource_to_modify = await unpacked_root_resource.get_only_child()
        new_string_config = StringPatchingConfig(6, "ofrak")
        await resource_to_modify.run(StringPatchingModifier, new_string_config)
