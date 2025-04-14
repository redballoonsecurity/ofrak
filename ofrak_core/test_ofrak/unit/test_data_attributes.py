from ofrak import OFRAKContext, ResourceSort
from ofrak.core import BinaryPatchModifier, BinaryPatchConfig
from ofrak.model.resource_model import Data
from ofrak_type import Range


async def test_data_attributes(ofrak_context: OFRAKContext, elf_object_file):
    root = await ofrak_context.create_root_resource_from_file(elf_object_file)
    await root.unpack()

    unordered_children = list(await root.get_children())
    ordered_children = list(await root.get_children(r_sort=ResourceSort(Data.Offset)))

    print(ordered_children)

    assert unordered_children != ordered_children


async def test_data_attributes_update(ofrak_context: OFRAKContext, elf_object_file):
    root = await ofrak_context.create_root_resource_from_file(elf_object_file)
    await root.unpack()

    # Get two arbitrary children, which both have some data
    unordered_children = list(await root.get_children())
    arbitrary_child1 = unordered_children[18]
    arbitrary_child2 = unordered_children[16]

    l1 = await arbitrary_child1.get_data_length()
    l2 = await arbitrary_child2.get_data_length()
    assert l1 > 0
    assert l2 > 0

    # patch away of the arbitrary children's data
    original_data_attrs = arbitrary_child1.get_attributes(Data)
    assert original_data_attrs._length == l1

    arbitrary_child1.queue_patch(Range(0, l1), b"")
    await arbitrary_child1.save()

    # manually check the data attributes are updated
    data_attrs = arbitrary_child1.get_attributes(Data)
    assert data_attrs._length == 0
    assert data_attrs._offset == original_data_attrs._offset

    # check that sorting by length works
    # the child whose data was patched should definitely be before the one which wasn't patched
    arbitrary_child1_found = False
    for child in await root.get_children(r_sort=ResourceSort(Data.Length)):
        if child == arbitrary_child1:
            arbitrary_child1_found = True
        elif child == arbitrary_child2:
            assert arbitrary_child1_found
            break


class TestGrandchildrenDataAttributes:
    async def test_grandchildren_data_attributes_update(self, ofrak_context: OFRAKContext):
        """
        Test that grandchildren data attributes update correctly.
        """
        b_child = await self._create_resource_get_child(ofrak_context)
        await b_child.run(BinaryPatchModifier, BinaryPatchConfig(0, b"C"))
        await self.assert_child_and_sorted_grandchildren_are_equivalent(b_child)

    @staticmethod
    async def _create_resource_get_child(ofrak_context):
        """
        Create a resource with contents b"AAAABBBB".
        Unpack the BBBB as one child, and create byte-size grandchildren for each byte
        of that child.

        Returns b_child.
        """
        resource = await ofrak_context.create_root_resource(name="test-resource", data=b"AAAABBBB")
        b_child = await resource.create_child(data_range=Range(4, 8))
        for i in range(await b_child.get_data_length()):
            await b_child.create_child(data_range=Range(i, i + 1))
        return b_child

    @staticmethod
    async def assert_child_and_sorted_grandchildren_are_equivalent(b_child):
        """
        Assert that child bytes equals the values of sorted grandchildren.

        When this test was created, it failed with:
        b'CBBB' != b'BBBC'

        Expected :b'BBBC'
        Actual   :b'CBBB'

        See https://github.com/redballoonsecurity/ofrak/pull/559 for the bugfix corresponding
        to this test.
        """
        sorted_children = await b_child.get_children(r_sort=ResourceSort(Data.Offset))
        assert await b_child.get_data() == b"".join(
            [await child.get_data() for child in sorted_children]
        )
