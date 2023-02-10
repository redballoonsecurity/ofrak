from ofrak import OFRAKContext, ResourceSort
from ofrak.model.resource_model import DataBytes
from ofrak_type import Range


async def test_data_attributes(ofrak_context: OFRAKContext, elf_object_file):
    root = await ofrak_context.create_root_resource_from_file(elf_object_file)
    await root.unpack()

    unordered_children = list(await root.get_children())
    ordered_children = list(await root.get_children(r_sort=ResourceSort(RootOffset)))

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
    original_data_attrs = arbitrary_child1.get_attributes(DataBytes)
    assert original_data_attrs._length == l1

    arbitrary_child1.queue_patch(Range(0, l1), b"")
    await arbitrary_child1.save()

    # manually check the data attributes are updated
    data_attrs = arbitrary_child1.get_attributes(DataBytes)
    assert data_attrs._length == 0
    assert data_attrs._offset == original_data_attrs._offset

    # check that sorting by length works
    # the child whose data was patched should definitely be before the one which wasn't patched
    arbitrary_child1_found = False
    for child in await root.get_children(r_sort=ResourceSort(DataBytes.Length)):
        if child == arbitrary_child1:
            arbitrary_child1_found = True
        elif child == arbitrary_child2:
            assert arbitrary_child1_found
            break
