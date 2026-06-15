from typing import Tuple, Optional, List

from ofrak import OFRAKContext
from ofrak.core.memory_region import MemoryRegion
from ofrak.resource import Resource
from ofrak.core.free_space import Allocatable, RuntimeFreeSpace

FreeSpaceTreeType = Tuple[MemoryRegion, Optional[List["FreeSpaceTreeType"]]]


async def inflate_tree(tree: FreeSpaceTreeType, ofrak_context: OFRAKContext) -> Resource:
    raw_root_region, children = tree
    root_r = await ofrak_context.create_root_resource(
        "test_r",
        b"\x00" * raw_root_region.size,
    )
    root_r.add_view(raw_root_region)
    root_r.add_tag(Allocatable)
    await root_r.save()

    if children:
        root_region = await root_r.view_as(MemoryRegion)
        for child in children:
            await _inflate_node(root_region, child)

    return root_r


async def _inflate_node(parent: MemoryRegion, node: FreeSpaceTreeType):
    raw_node_region, children = node
    if isinstance(raw_node_region, RuntimeFreeSpace):
        node_r = await parent.resource.create_child_from_view(raw_node_region, data_range=None)
    else:
        node_r = await parent.create_child_region(raw_node_region)
    node_r.add_view(raw_node_region)
    await node_r.save()
    if children:
        node_region = await node_r.view_as(MemoryRegion)
        for child in children:
            await _inflate_node(node_region, child)
