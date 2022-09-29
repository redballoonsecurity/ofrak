""" Test DataNode and DataService with finite state machines. """
from typing import Any, Callable, Dict, List

import hypothesis.strategies as st
import pytest
import sys
from beartype import beartype
from functools import reduce
from hypothesis import assume
from hypothesis.stateful import (
    RuleBasedStateMachine,
    initialize,
    invariant,
    precondition,
    rule,
)
from hypothesis_trio.stateful import TrioAsyncioRuleBasedStateMachine

from ofrak.model.data_model import DataModel
from ofrak.service.data_service import (
    DataNode,
    DataService,
)
from ofrak.service.error import OverlapError, AmbiguousOrderError
from ofrak_type.error import AlreadyExistError
from ofrak_type.range import Range

# pylint: disable=protected-access

MIN_RANGE_VALUE = 0
MAX_RANGE_VALUE = sys.maxsize
MIN_RANGE_SIZE = 1
MAX_DATA_ID_SIZE = int(10e3)
MAX_BINARY_SIZE = sys.maxsize
DATA_IDS = st.binary(max_size=MAX_DATA_ID_SIZE)
BINARIES = st.binary(min_size=MIN_RANGE_SIZE, max_size=MAX_BINARY_SIZE)
ALIGNMENTS = st.integers(min_value=1)


@st.composite
@beartype
def ranges(
    draw: Callable[[st.SearchStrategy], Any],
    min_start: int = MIN_RANGE_VALUE,
    max_end: int = MAX_RANGE_VALUE,
) -> Range:
    """A strategy for ranges."""
    max_start = max_end - MIN_RANGE_SIZE
    starts = st.integers(min_value=max(min_start, MIN_RANGE_VALUE), max_value=max_start)
    start = draw(starts)
    ends = st.integers(min_value=start + MIN_RANGE_SIZE, max_value=max_end)
    end = draw(ends)
    return Range(start, end)


async def draw_populated_data_service(data: st.DataObject, num_nodes: int) -> DataService:
    """Generate populated data services given a data object."""
    service = DataService()

    # Create a strategy for sequences of data ids and draw from it.
    id_pools = st.lists(DATA_IDS, min_size=num_nodes, max_size=num_nodes, unique=True)
    ids: List[bytes] = data.draw(id_pools, label="id_pool")

    # Get lists of root IDs and node IDs without duplicates.
    num_roots = data.draw(st.integers(min_value=1, max_value=num_nodes), label="num_roots")
    root_ids = ids[:num_roots]
    node_ids = ids[num_roots:]

    # Draw the corresponding binaries.
    binaries = data.draw(
        st.lists(BINARIES, min_size=num_roots, max_size=num_roots), label="binaries"
    )

    # Create root nodes.
    for root_id, binary in zip(root_ids, binaries):
        await service.create(root_id, binary)

    num_mapped_nodes = 0
    num_ambigs = 0
    num_overlaps = 0
    for data_id in node_ids:

        # TODO: Remove duplicated code.
        # Validate the ``data_id`` and get a parent ID.
        parent_id = data.draw(st.sampled_from(root_ids), label="root_id")

        # Generate a new range.
        length = await service.get_data_length(parent_id)

        allow_overlap = data.draw(st.booleans(), "overlap")

        buckets: List[Range] = list(
            await service.get_unmapped_ranges(
                parent_id,
                False,
                Range(0, (await service.get_by_id(parent_id)).range.length()),
            )
        )
        if not allow_overlap and len(buckets) == 0:
            continue

        if allow_overlap:
            new_range = data.draw(ranges(max_end=length), label="overlapping range?")
        else:
            bucket = data.draw(st.sampled_from(buckets), label="bucket")
            subranges = ranges(min_start=bucket.start, max_end=bucket.end)
            new_range = data.draw(subranges, label="new_range")

        # Check if the range overlaps with a child.
        overlaps = False
        ambig = False
        parent: DataNode = service._data_node_store[parent_id]
        for kid in parent.get_children_in_range(Range(0, length)):
            kid_length = kid.model.range.length()

            if kid.model.range.overlaps(new_range):
                overlaps = True

            start = new_range.start
            if kid.model.range.start == start and kid_length == new_range.length() == 0:
                ambig = True

        # Check that error is raised if overlapping or ambiguous, else add region.
        if ambig:
            with pytest.raises(AmbiguousOrderError):
                await service.create_mapped(data_id, parent_id, new_range)
            num_ambigs += 1
            continue
        if overlaps:
            with pytest.raises(OverlapError):
                await service.create_mapped(data_id, parent_id, new_range)
            num_overlaps += 1
            continue

        await service.create_mapped(data_id, parent_id, new_range)
        num_mapped_nodes += 1

    assert len(service._data_node_store) == num_roots + num_mapped_nodes
    store = service._data_node_store
    return service


class DataNodeStateMachine(RuleBasedStateMachine):
    """Finite state machine test for ``DataNode``."""

    def __init__(self) -> None:
        super().__init__()
        self.root: DataNode
        self.nodes: Dict[bytes, DataNode] = {}

    @initialize(
        data_id=DATA_IDS,
        nrange=ranges(),
        alignment=st.integers(min_value=1),
        overlap=st.booleans(),
    )
    @beartype
    def init_root(self, data_id: bytes, nrange: Range, alignment: int, overlap: bool) -> None:
        """Initialize the root node."""
        model = DataModel(data_id, nrange, alignment, None)
        self.root = DataNode(model, None, overlap)
        self.nodes[data_id] = self.root

    @invariant()
    def internal_children_is_sorted(self) -> None:
        for node in self.nodes.values():
            assert sorted(node._children) == node._children

    @invariant()
    def internal_children_start_indices_are_correct(self) -> None:
        for node in self.nodes.values():
            for start, child in node._children:
                assert start == child.model.range.start

    @rule(
        data=st.data(),
        data_id=DATA_IDS,
        alignment=st.integers(min_value=1),
        overlap=st.booleans(),
    )
    @beartype
    def insert_node(
        self, data: st.DataObject, data_id: bytes, alignment: int, overlap: bool
    ) -> None:
        """Insert a node."""
        assume(data_id not in self.nodes)
        data_ids = list(self.nodes.keys())
        parent_id = data.draw(st.sampled_from(data_ids), label="root_id")
        parent = self.nodes[parent_id]

        # Generate a new range.
        length = parent.model.range.length()
        new_range = data.draw(ranges(max_end=length), label="new_range")

        model = DataModel(data_id, new_range, alignment, parent_id)
        node = DataNode(model, parent, overlap)

        # TODO: Add optional arguments.
        parent_overlap: bool = parent.is_overlaps_enabled()
        if not parent_overlap and list(parent.get_children_in_range(new_range)):
            with pytest.raises(OverlapError):
                parent.insert_node(node)
            return

        # Handle ambiguous ordering when overlaps are enabled.
        if parent_overlap:
            for child in parent.get_children_in_range(new_range):
                if child.model.range.start == new_range.start:

                    # TODO: See AMP-24.
                    with pytest.raises(AmbiguousOrderError):
                        parent.insert_node(node)
                    return

        parent.insert_node(node)
        self.nodes[data_id] = node


class DataServiceStateMachine(TrioAsyncioRuleBasedStateMachine):
    """Finite state machine test for ``DataService``."""

    def __init__(self) -> None:
        super().__init__()
        self.service = DataService()
        self.model = b""
        self.data_ids: List[bytes] = []

    @rule(data_id=DATA_IDS, data=BINARIES)
    @beartype
    async def create(self, data_id: bytes, data: bytes):
        """Create a root node and add data."""
        assume(data_id not in self.data_ids)
        self.data_ids.append(data_id)
        await self.service.create(data_id, data)

    @invariant()
    async def matches_data_ids(self):
        """Data ID model matches internal node store."""
        data_ids = list(self.service._data_node_store.keys())
        assert self.data_ids == data_ids, f"self.data_ids: {self.data_ids}"

    @invariant()
    async def children_structures_agree(self):
        """Data structures tracking children must agree."""
        for node in self.service._data_node_store.values():
            entirety = Range(0, node.model.range.length())
            _children = {pair[1] for pair in node._children}
            children = set(node.get_children_in_range(entirety))
            assert _children == children, f"{_children} != {children}"

    @precondition(lambda self: self.data_ids)
    @rule(data=st.data(), data_id=DATA_IDS)
    @beartype
    async def create_mapped(self, data: st.DataObject, data_id: bytes):
        """Add a mapped region and a corresponding new node."""
        # Validate the ``data_id`` and get a parent ID.
        assume(data_id not in self.data_ids)
        parent_id = data.draw(st.sampled_from(self.data_ids), label="root_id")

        # Generate a new range.
        length = await self.service.get_data_length(parent_id)
        new_range = data.draw(ranges(max_end=length), label="new_range")

        # Check if the range overlaps with a child.
        overlaps = False
        ambig = False
        parent: DataNode = self.service._data_node_store[parent_id]
        for kid in parent.get_children_in_range(Range(0, length)):
            kid_length = kid.model.range.length()

            if kid.model.range.overlaps(new_range):
                overlaps = True

            start = new_range.start
            if kid.model.range.start == start and kid_length == new_range.length() == 0:
                ambig = True

        # Check that error is raised if overlapping or ambiguous, else add region.
        if ambig:
            with pytest.raises(AmbiguousOrderError):
                await self.service.create_mapped(data_id, parent_id, new_range)
            return
        if overlaps:
            with pytest.raises(OverlapError):
                await self.service.create_mapped(data_id, parent_id, new_range)
            return

        await self.service.create_mapped(data_id, parent_id, new_range)
        self.data_ids.append(data_id)

    @precondition(lambda self: len(self.data_ids) >= 2)
    @rule(data=st.data(), data_id=DATA_IDS)
    @beartype
    async def create_mapped_duplicate_id(self, data: st.DataObject, data_id: bytes):
        """Test that adding children with duplicate data_ids raises an error."""
        # Generate a parent ID and a duplicate node ID.
        sample_ids: st.SearchStrategy = st.sampled_from(self.data_ids)
        id_pairs: st.SearchStrategy = st.lists(sample_ids, min_size=2, max_size=2)
        data_id, parent_id = data.draw(id_pairs, label="(data_id, root_id)")

        length = await self.service.get_data_length(parent_id)
        start = data.draw(st.integers(min_value=0, max_value=length), label="start")
        end = data.draw(st.integers(min_value=start, max_value=length), label="end")
        new_range = Range(start, end)
        with pytest.raises(AlreadyExistError):
            await self.service.create_mapped(data_id, parent_id, new_range)

    @precondition(lambda self: self.data_ids)
    @rule(data=st.data(), sort=st.booleans())
    @beartype
    async def get_unmapped_ranges(self, data: st.DataObject, sort: bool):
        """Test the ``get_unmapped_ranges()`` function."""
        data_id: bytes = data.draw(st.sampled_from(self.data_ids), label="data_id")
        parent: DataNode = self.service._data_node_store[data_id]
        bounds = Range(0, parent.model.range.length())

        # Unmapped ranges.
        uranges = list(await self.service.get_unmapped_ranges(data_id, sort, bounds))

        # Check that ranges are actually unmapped.
        total_mapped_size = 0
        for kid in parent.get_children_in_range(bounds):
            kid_range = kid.model.range
            total_mapped_size += kid_range.length()
            for urange in uranges:
                assert not kid_range.overlaps(urange), f"{urange} is mapped"

        # Check that ranges are sorted by size.
        if sort:
            sorted_ranges = sorted(uranges, key=lambda x: x.length())
            assert uranges == sorted_ranges

        # Otherwise, they should be sorted by start (assumes nonoverlapping, nonempty).
        else:
            sorted_ranges = sorted(uranges, key=lambda x: x.start)
            assert uranges == sorted_ranges

        # Assuming mapped ranges cannot overlap, make sure this gets us everything.
        unmapped_lengths: List[int] = [urange.length() for urange in uranges]
        total_unmapped_size = reduce(lambda x, y: x + y, unmapped_lengths, 0)
        assert total_mapped_size + total_unmapped_size == bounds.length()

    @precondition(lambda self: self.data_ids)
    @rule(data=st.data(), sort=st.booleans())
    @beartype
    async def get_unmapped_ranges_is_bounded(
        self,
        data: st.DataObject,
        sort: bool,
    ):
        """Test the ``get_unmapped_ranges()`` function listens to bounds."""
        data_id: bytes = data.draw(st.sampled_from(self.data_ids), label="data_id")

        # Gollum-speak to adhere to the convention that strategies are plural.
        parent: DataNode = self.service._data_node_store[data_id]
        boundses = ranges(min_start=0, max_end=parent.model.range.length())
        bounds = data.draw(boundses, label="bounds")

        # Unmapped ranges.
        uranges = list(await self.service.get_unmapped_ranges(data_id, sort, bounds))

        # Make sure ranges are within bounds.
        for urange in uranges:
            assert urange == urange.intersect(bounds)


TestDataNode = DataNodeStateMachine.TestCase
TestDataService = DataServiceStateMachine.TestCase
