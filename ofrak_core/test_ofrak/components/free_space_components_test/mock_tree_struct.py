from typing import Tuple, Optional, List

from ofrak import OFRAKContext
from ofrak.core.memory_region import MemoryRegion
from ofrak.resource import Resource
from ofrak.core.free_space import Allocatable

FreeSpaceTreeType = Tuple[MemoryRegion, Optional[List["FreeSpaceTreeType"]]]


def inflate_tree(tree: FreeSpaceTreeType, ofrak_context: OFRAKContext) -> Resource:
    raw_root_region, children = tree
    root_r = ofrak_context.create_root_resource(
        "test_r",
        b"\x00" * raw_root_region.size,
    )
    root_r.add_view(raw_root_region)
    root_r.add_tag(Allocatable)
    root_r.save()

    if children:
        root_region = root_r.view_as(MemoryRegion)
        for child in children:
            _inflate_node(root_region, child)

    return root_r


def _inflate_node(parent: MemoryRegion, node: FreeSpaceTreeType):
    raw_node_region, children = node
    node_r = parent.create_child_region(raw_node_region)
    node_r.add_view(raw_node_region)
    node_r.save()
    if children:
        node_region = node_r.view_as(MemoryRegion)
        for child in children:
            _inflate_node(node_region, child)
