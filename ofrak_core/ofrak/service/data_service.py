import bisect
import copy
import dataclasses
import datetime
import functools
import logging
import random
from collections import defaultdict, deque
from typing import Dict, Optional, List, Tuple, Iterable, Deque, cast

from intervaltree import IntervalTree

from ofrak.model.data_model import (
    DataModel,
    DataPatch,
    DataPatchesResult,
    DataPatchResult,
    DataMove,
    DataRangePosition,
)
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.error import (
    OutOfBoundError,
    OverlapError,
    PatchOverlapError,
    AmbiguousOrderError,
    NonContiguousError,
)
from ofrak_type.error import NotFoundError, AlreadyExistError
from ofrak_type.range import Range

LOGGER = logging.getLogger("ofrak.service.data_service")


class DataNode:
    model: DataModel
    parent: Optional["DataNode"]
    # Used to keep the children sorted when their start addresses are the same. It is kept
    # sorted by the child's start position.
    _children: List[Tuple[int, "DataNode"]]
    # Used to quickly look up a child's index within the sorted list
    _children_index_by_id: Dict[bytes, int]
    # Used to look up children using a range/position when overlapping is allowed
    _children_tree: Optional[IntervalTree]
    _unmapped_ranges: List[Tuple[int, Range]]
    _unmapped_sizes: List[Tuple[int, int, Range]]

    def __init__(
        self, model: DataModel, parent: Optional["DataNode"] = None, overlap_allowed: bool = False
    ):
        self.model = model
        self.parent = parent
        self._children = []
        self._children_index_by_id = {}
        self._children_tree = IntervalTree() if overlap_allowed else None
        # Used to keep track of the unmapped ranges within the child
        length = model.range.length()
        self._unmapped_ranges = [(0, Range(0, length))]
        self._unmapped_sizes = [(length, hash(Range(0, length)), Range(0, length))]

    def set_parent(self, parent: Optional["DataNode"]):
        self.parent = parent
        if parent is None:
            self.model.parent_id = None
        else:
            self.model.parent_id = parent.model.id

    def is_root(self) -> bool:
        return self.parent is None

    def is_overlaps_enabled(self) -> bool:
        return self._children_tree is not None

    def set_overlaps_enabled(self, enable_overlaps: bool):
        if enable_overlaps is False and self._children_tree is not None:
            raise ValueError(
                f"Cannot disable overlaps on data node {self.model.id.hex()} once they are "
                f"enabled"
            )
        if enable_overlaps == self.is_overlaps_enabled():
            return
        children_tree_data = []
        for _, child_node in self._children:
            child_range = child_node.model.range
            if child_range.length() > 0:
                children_tree_data.append((child_range.start, child_range.end, child_node))
        self._children_tree = IntervalTree.from_tuples(children_tree_data)

    def get_num_children(self) -> int:
        return len(self._children)

    def get_child(self, index: int) -> "DataNode":
        return self._children[index][1]

    def get_child_index(self, data_node: "DataNode") -> int:
        return self._children_index_by_id[data_node.model.id]

    def get_unmapped_ranges(
        self, sort_by_size: bool = False, bounds: Optional[Range] = None
    ) -> Iterable[Range]:
        """Get an iterator over unmapped ranges in zero passes."""
        # Get hash, and get size-sorted-range from hash :: [(size, hash)] -> [Range].
        size_sorted_ranges: Iterable[Range] = map(lambda x: x[2], self._unmapped_sizes)

        # Get range, discard index :: [(idx, Range)] -> [Range].
        unmapped_ranges: Iterable[Range] = map(lambda x: x[1], self._unmapped_ranges)

        # Choose between size-sorted and start-index-sorted.
        unmapped_iterable = size_sorted_ranges if sort_by_size else unmapped_ranges

        def selector(urange: Range, bounds: Optional[Range]) -> Tuple[int, Range]:
            """Intersects ``urange`` with bounds, returning (length, Range)."""
            bounds = bounds if bounds is not None else urange
            start = max(urange.start, bounds.start)
            end = min(urange.end, bounds.end)
            end = max(start, end)
            intersection = Range(start, end)
            return end - start, intersection

        # Fill in ``bounds`` kwarg.
        bounded_selector = functools.partial(selector, bounds=bounds)

        # Get lengths and range intersections.
        lengths_and_ranges = map(bounded_selector, unmapped_iterable)

        # Filter 0-length ranges.
        nontrivial_lengths_and_ranges = filter(lambda x: x[0] > 0, lengths_and_ranges)

        # Take ranges, discard lengths.
        bounded_ranges = map(lambda x: x[1], nontrivial_lengths_and_ranges)
        return bounded_ranges

    def _pop_size(self, candidate: Range) -> None:
        """
        Delete the representations of ``candidate`` from
        ``self._unmapped_sizes``.
        """
        candidate_tuple = (candidate.length(), hash(candidate), candidate)
        idx = bisect.bisect_left(self._unmapped_sizes, candidate_tuple)
        del self._unmapped_sizes[idx]

    def _push_size(self, candidate: Range) -> None:
        """
        Add the representations of ``candidate`` to ``self._unmapped_sizes``.
        """
        candidate_tuple = (candidate.length(), hash(candidate), candidate)
        bisect.insort_left(self._unmapped_sizes, candidate_tuple)

    def get_children_in_range(self, target_range: Range) -> Iterable["DataNode"]:
        """
        Get all the children that overlap the provided range. If the provided range is empty and
        there are empty ranges at that location, they are included in the results. The children
        are not ordered.
        :param target_range:
        :return:
        """
        if len(self._children) == 0:
            return tuple()
        child_index = bisect.bisect_left(self._children, (target_range.start,))
        if not self.is_overlaps_enabled():
            # Since overlaps are not allowed, this is just binary search
            if child_index != 0:
                # The child_index corresponds to the first child that starts at or after the
                # provided range. The child to the left must also be checked if it exists.
                _, left_child = self._children[child_index - 1]
                if target_range.overlaps(left_child.model.range):
                    yield left_child

            for i in range(child_index, len(self._children)):
                # Iterate the children that starts at or after the provided range until the first
                # child to the left of the range is found.
                _, child = self._children[i]
                if target_range.end < child.model.range.start:
                    break
                if target_range.overlaps(child.model.range) or target_range == child.model.range:
                    # The ranges overlaps or they are equal (which is only possible if they are 0
                    # sized ranges, which is considered an overlap)
                    yield child
        else:
            self._children_tree = cast(IntervalTree, self._children_tree)
            if target_range.length() > 0:
                intervals = self._children_tree.overlap(target_range.start, target_range.end)
            else:
                intervals = self._children_tree.at(target_range.start)
            for interval in sorted(intervals):
                if interval.data.model.range.overlaps(target_range):
                    yield interval.data
            for i in range(child_index, len(self._children)):
                # Handle the 0-sized children
                _, child = self._children[i]
                if child.model.range.start > target_range.end:
                    break
                if child.model.range.length() == 0 and (
                    child.model.range.overlaps(target_range) or target_range == child.model.range
                ):
                    yield child

    def get_unmapped_range(
        self, position: int, relative_position: Optional[DataRangePosition] = None
    ) -> Range:
        if position < 0 or position > self.model.range.length():
            raise OutOfBoundError(
                f"The provided position {position} is outside the bounds of the parent {self}"
            )
        unmapped_range_index = cast(int, bisect.bisect_left(self._unmapped_ranges, (position,)))
        if unmapped_range_index > 0:
            unmapped_range_left: Optional[Range]
            _, unmapped_range_left = self._unmapped_ranges[unmapped_range_index - 1]
            if position < unmapped_range_left.end:
                return unmapped_range_left
            elif unmapped_range_left.end != position:
                unmapped_range_left = None
        else:
            unmapped_range_left = None

        if unmapped_range_index < len(self._unmapped_ranges):
            unmapped_range_right: Optional[Range]
            _, unmapped_range_right = self._unmapped_ranges[unmapped_range_index]
            if unmapped_range_right.start != position:
                unmapped_range_right = None
        else:
            unmapped_range_right = None

        if unmapped_range_left is not None and unmapped_range_right is not None:
            if relative_position is None:
                raise AmbiguousOrderError(
                    f"The requested unmapped range within {self} could be before or "
                    f"after {hex(position)} but the order was not specified"
                )
            if relative_position is DataRangePosition.BEFORE:
                return unmapped_range_left
            elif relative_position is DataRangePosition.AFTER:
                return unmapped_range_right
            else:
                raise ValueError(
                    "The get_unmapped_range() method only accept the relative position value "
                    f"BEFORE or AFTER, not {relative_position.name}"
                )
        elif unmapped_range_right is not None:
            return unmapped_range_right
        elif unmapped_range_left is not None:
            return unmapped_range_left
        else:
            return Range.from_size(position, 0)

    def _validate_range_index(
        self,
        child_range: Range,
        index: int,
        relative_position: DataRangePosition,
        within_data_id: Optional[bytes] = None,
        after_data_id: Optional[bytes] = None,
        before_data_id: Optional[bytes] = None,
    ) -> Tuple[int, DataRangePosition]:
        if relative_position is DataRangePosition.WITHIN:
            _, child_node = self._children[index]
            if within_data_id is not None and within_data_id != child_node.model.id:
                raise AmbiguousOrderError(
                    f"The {child_range} is within {child_node} but it was hinted to "
                    f"be within the child {within_data_id.hex()}"
                )
            if after_data_id is not None:
                raise AmbiguousOrderError(
                    f"The {child_range} is within {child_node} but it was hinted to "
                    f"be after the child {after_data_id.hex()}"
                )
            if before_data_id is not None:
                raise AmbiguousOrderError(
                    f"The {child_range} is within {child_node} but it was hinted to "
                    f"be before the child {before_data_id.hex()}"
                )
            return index, relative_position
        elif relative_position is DataRangePosition.OVERLAP:
            _, child_node = self._children[index]
            if within_data_id is not None:
                raise AmbiguousOrderError(
                    f"The {child_range} is overlapping {child_node} but it was "
                    f"hinted to be within the child {within_data_id.hex()}"
                )
            if after_data_id is not None:
                raise AmbiguousOrderError(
                    f"The {child_range} is overlapping {child_node} but it was "
                    f"hinted to be after the child {after_data_id.hex()}"
                )
            if before_data_id is not None:
                raise AmbiguousOrderError(
                    f"The {child_range} is overlapping {child_node} but it was "
                    f"hinted to be before the child {before_data_id.hex()}"
                )
            return index, relative_position
        elif relative_position is DataRangePosition.UNMAPPED:
            if within_data_id is not None:
                raise AmbiguousOrderError(
                    f"The {child_range} is in unmapped space but it was "
                    f"hinted to be within the child {within_data_id.hex()}"
                )
            if after_data_id is not None:
                if index == 0:
                    raise AmbiguousOrderError(
                        f"The {child_range} was hinted to be after the child "
                        f"{after_data_id.hex()} but there is no child to the left"
                    )
                _, left_child_node = self._children[index - 1]
                if left_child_node.model.id != after_data_id:
                    hinted_after_index = self._children_index_by_id[after_data_id]
                    _, hinted_after_node = self._children[hinted_after_index]
                    raise AmbiguousOrderError(
                        f"The {child_range} is after {left_child_node} but it was "
                        f"hinted to be after the child {hinted_after_node}"
                    )
                return index - 1, DataRangePosition.AFTER
            if before_data_id is not None:
                if index >= len(self._children):
                    raise AmbiguousOrderError(
                        f"The {child_range} was hinted to be after the child "
                        f"{before_data_id.hex()} but there is no child to the right"
                    )
                _, right_child_node = self._children[index]
                if right_child_node.model.id != before_data_id:
                    raise AmbiguousOrderError(
                        f"The {child_range} is before {right_child_node} but it was "
                        f"hinted to be before the child {before_data_id.hex()}"
                    )
                return index, DataRangePosition.BEFORE
            return index, relative_position
        else:
            _, child_node = self._children[index]
            raise ValueError(
                f"Received unexpected relative_position value {relative_position}"
                f" for range {child_range}, child {child_node}, and node ID"
                f" {self.model.id.hex()}"
            )

    def get_range_index(
        self,
        child_range: Range,
        within_data_id: Optional[bytes] = None,
        after_data_id: Optional[bytes] = None,
        before_data_id: Optional[bytes] = None,
    ) -> Tuple[int, DataRangePosition]:
        """
        Return the index of an existing node and the enum value describing the
        relation between ``child_range`` and that node.
        """
        if child_range.start < 0 or child_range.end > self.model.range.length():
            raise OutOfBoundError(
                f"The provided {child_range} is outside the bounds of the parent {self}"
            )
        if len(self._children) == 0:
            return 0, DataRangePosition.UNDEFINED

        min_child_index = cast(int, bisect.bisect_left(self._children, (child_range.start,)))
        max_child_index = cast(int, bisect.bisect_left(self._children, (child_range.start + 1,)))
        if min_child_index == max_child_index:
            # There is no existing child that match the start address of the new child
            if min_child_index > 0:
                # Check the left child for overlaps
                _, left_child_node = self._children[min_child_index - 1]
                left_child_range = left_child_node.model.range
                if left_child_range.end > child_range.end or (
                    left_child_range.end == child_range.end and child_range.length() > 0
                ):
                    return self._validate_range_index(
                        child_range,
                        min_child_index - 1,
                        DataRangePosition.WITHIN,
                        within_data_id,
                        after_data_id,
                        before_data_id,
                    )
                if left_child_node.model.range.end > child_range.start:
                    return self._validate_range_index(
                        child_range,
                        min_child_index - 1,
                        DataRangePosition.OVERLAP,
                        within_data_id,
                        after_data_id,
                        before_data_id,
                    )

            if min_child_index < len(self._children):
                # Check the right child for overlaps
                _, right_child_node = self._children[min_child_index]
                if right_child_node.model.range.start < child_range.end:
                    return self._validate_range_index(
                        child_range,
                        min_child_index,
                        DataRangePosition.OVERLAP,
                        within_data_id,
                        after_data_id,
                        before_data_id,
                    )

            return self._validate_range_index(
                child_range,
                min_child_index,
                DataRangePosition.UNMAPPED,
                within_data_id,
                after_data_id,
                before_data_id,
            )

        # At this point, there are one or more existing children that have the same start address
        # as the new child.
        if child_range.length() != 0:
            # If all existing children are zero-sized and the new child is not, it should go at
            # the end.
            all_zero_sized = True
            for i in range(min_child_index, max_child_index):
                _, _child = self._children[i]
                if _child.model.range.length() > 0:
                    if not self.is_overlaps_enabled():
                        if _child.model.range.end >= child_range.end:
                            return self._validate_range_index(
                                child_range,
                                i,
                                DataRangePosition.WITHIN,
                                within_data_id,
                                after_data_id,
                                before_data_id,
                            )
                        else:
                            return self._validate_range_index(
                                child_range,
                                i,
                                DataRangePosition.OVERLAP,
                                within_data_id,
                                after_data_id,
                                before_data_id,
                            )
                    else:
                        all_zero_sized = False
            if all_zero_sized:
                # If overlaps are forbidden, this branch will always be taken (otherwise it would
                # have returned in the loop above). If overlaps are allowed, there is only one
                # possibility for the new child's index
                return self._validate_range_index(
                    child_range,
                    max_child_index,
                    DataRangePosition.UNMAPPED,
                    within_data_id,
                    after_data_id,
                    before_data_id,
                )

        if (
            max_child_index - min_child_index == 1
            and child_range.length() == 0
            and within_data_id is None
        ):
            # If there is just one existing non-zero-sized child, the new child should go before it.
            _, _child = self._children[min_child_index]
            if _child.model.range.length() != 0:
                return self._validate_range_index(
                    child_range,
                    min_child_index,
                    DataRangePosition.UNMAPPED,
                    within_data_id,
                    after_data_id,
                    before_data_id,
                )

        # At this point, there is at least one existing child and the new child have the same
        # start position. If overlaps are not allowed, the new child is 0-sized and at least
        # one other child sharing the same start address is 0-sized. It requires a hint
        # to know where the new child will be inserted relative to the other 0-sized child(ren)

        _, min_child_node = self._children[min_child_index]
        if after_data_id is None and before_data_id is None and within_data_id is None:
            raise AmbiguousOrderError(
                f"The {child_range} could got before or after child {min_child_node} but the "
                f"order was not specified"
            )
        elif (
            len(
                list(
                    filter(lambda v: v is not None, (within_data_id, after_data_id, before_data_id))
                )
            )
            != 1
        ):
            raise AmbiguousOrderError(
                f"The range {child_range} could go within, before or after multiple "
                f"children. Exactly one within, after or before data id parameter must be included."
            )
        if after_data_id is not None:
            min_previous_child_index = max(min_child_index - 1, 0)
            for previous_child_index in range(min_previous_child_index, max_child_index):
                _, previous_child = self._children[previous_child_index]
                if previous_child.model.id == after_data_id:
                    return previous_child_index, DataRangePosition.AFTER
            raise AmbiguousOrderError(
                f"The {child_range} could be go in multiple locations but the order was "
                f"specified with an after data ID that does not exist or is not located "
                f"immediately before one of the child's valid insertion indexes."
            )
        elif before_data_id is not None:
            max_next_child_index = min(max_child_index, len(self._children) - 1)
            for next_child_index in range(min_child_index, max_next_child_index + 1):
                _, next_child = self._children[next_child_index]
                if next_child.model.id == before_data_id:
                    return next_child_index, DataRangePosition.BEFORE
            raise AmbiguousOrderError(
                f"The {child_range} could be inserted before or after child {min_child_node} but"
                f" the order was specified with an after data ID that does not exist or is "
                f"located after the provided range."
            )
        elif within_data_id is not None:
            min_previous_child_index = max(min_child_index - 1, 0)
            max_next_child_index = min(max_child_index, len(self._children) - 1)
            for child_index in range(min_previous_child_index, max_next_child_index + 1):
                _, _child = self._children[child_index]
                if _child.model.id == within_data_id and child_range.within(_child.model.range):
                    return child_index, DataRangePosition.WITHIN
            raise AmbiguousOrderError(
                f"The {child_range} could be inserted before or after child {min_child_node} but"
                f" the order was specified with an after data ID that does not exist or is "
                f"located after the provided range."
            )
        # Unreachable code
        raise NotImplementedError()

    def insert_node(
        self,
        child_node: "DataNode",
        after_data_id: Optional[bytes] = None,
        before_data_id: Optional[bytes] = None,
    ) -> "DataNode":
        child_index, relative_position = self.get_range_index(
            child_node.model.range, after_data_id=after_data_id, before_data_id=before_data_id
        )
        if relative_position is DataRangePosition.OVERLAP and not self.is_overlaps_enabled():
            _, existing_child_node = self._children[child_index]
            raise OverlapError(
                f"The {self} does not allow for overlap but the new child {child_node} "
                f"overlaps the existing child {existing_child_node}. Use DataService."
                f"set_overlaps_enabled({self.model.id.hex()}, True) if overlapping children "
                f"should be allowed.",
                child_node,
                existing_child_node,
            )
        if relative_position is DataRangePosition.WITHIN and not self.is_overlaps_enabled():
            _, overlapping_child_node = self._children[child_index]
            raise OverlapError(
                f"The {self} does not allow for overlap but the new child {child_node} "
                f"is within child {overlapping_child_node}. Use DataService.set_overlaps_enabled("
                f"{self.model.id.hex()}, True) if overlapping children should be allowed.",
                child_node,
                overlapping_child_node,
            )
        if relative_position is DataRangePosition.AFTER:
            child_index += 1

        # Keep ``self._children`` sorted.
        start = child_node.model.range.start
        min_child_index = cast(int, bisect.bisect_left(self._children, (start, child_node)))
        max_child_index = cast(int, bisect.bisect_left(self._children, (start + 1, child_node)))
        child_index = max(child_index, min_child_index)
        child_index = min(child_index, max_child_index)

        # Insert the child in the children array sorted by their start offset
        self._children.insert(child_index, (child_node.model.range.start, child_node))
        # Add the child to the range tree if necessary.
        if self._children_tree is not None:
            child_range = child_node.model.range
            if child_range.length() > 0:
                # The interval tree does not handle 0-sized intervals.
                self._children_tree.addi(child_range.start, child_range.end, child_node)
        # Update the children index cache
        self._children_index_by_id[child_node.model.id] = child_index
        for child_index in range(child_index + 1, len(self._children)):
            _, child = self._children[child_index]
            self._children_index_by_id[child.model.id] = child_index

        # Update the unmapped data

        # This is the range that should be removed from the unmapped ranges
        child_range = child_node.model.range
        unmapped_range_right_index = cast(
            int, bisect.bisect_left(self._unmapped_ranges, (child_range.start,))
        )
        if unmapped_range_right_index > 0:
            _, unmapped_range_left = self._unmapped_ranges[unmapped_range_right_index - 1]
            # The range to the left starts before the range to remove
            if unmapped_range_left.end > child_range.end:
                # The range to remove is within an existing unmapped range. It requires
                # splitting the existing unmapped range

                # Get the halves of the split ``unmapped_range_left``.
                left_half = Range(unmapped_range_left.start, child_range.start)
                right_half = Range(child_range.end, unmapped_range_left.end)

                # Insert the halves into ``self._unmapped_ranges``.
                self._unmapped_ranges[unmapped_range_right_index - 1] = (
                    unmapped_range_left.start,
                    left_half,
                )
                self._unmapped_ranges.insert(
                    unmapped_range_right_index, (child_range.end, right_half)
                )

                # Pop existing range size; add ``left_half``, ``right_half``.
                self._pop_size(unmapped_range_left)
                self._push_size(left_half)
                self._push_size(right_half)

            elif unmapped_range_left.end > child_range.start:
                # The range to remove overlaps the end of an existing unmapped range. It
                # requires truncating the existing unmapped range
                trunc_range_left = Range(unmapped_range_left.start, child_range.start)
                self._unmapped_ranges[unmapped_range_right_index - 1] = (
                    unmapped_range_left.start,
                    trunc_range_left,
                )

                # Swap existing range size for the truncated version.
                self._pop_size(unmapped_range_left)
                self._push_size(trunc_range_left)

        if unmapped_range_right_index < len(self._unmapped_ranges):
            _, unmapped_range_right = self._unmapped_ranges[unmapped_range_right_index]
            # The range to the right starts at or after the range to remove
            while unmapped_range_right.end <= child_range.end:
                # The range to remove covers an existing unmapped range. It requires removing the
                # existing unmapped range and we need to start looking at unmapped ranges afterward
                self._unmapped_ranges.pop(unmapped_range_right_index)

                self._pop_size(unmapped_range_right)

                if unmapped_range_right_index >= len(self._unmapped_ranges):
                    break
                _, unmapped_range_right = self._unmapped_ranges[unmapped_range_right_index]
            if unmapped_range_right.start < child_range.end < unmapped_range_right.end:
                # The range to remove overlaps the end of an existing unmapped range. It
                # requires truncating the existing unmapped range
                trunc_range_right = Range(child_range.end, unmapped_range_right.end)
                self._unmapped_ranges[unmapped_range_right_index] = (
                    child_range.end,
                    trunc_range_right,
                )

                # Swap existing range size for the truncated version.
                self._pop_size(unmapped_range_right)
                self._push_size(trunc_range_right)

        return child_node

    def insert(
        self,
        item: DataModel,
        after_data_id: Optional[bytes] = None,
        before_data_id: Optional[bytes] = None,
    ) -> "DataNode":
        child_node = DataNode(item, self)
        return self.insert_node(child_node, after_data_id, before_data_id)

    def remove(self, item: "DataNode"):
        new_unmapped_range = item.model.range
        child_index = self._children_index_by_id[item.model.id]
        self._children.pop(child_index)
        # Update the children index cache
        for child_index in range(child_index, len(self._children)):
            _, child = self._children[child_index]
            self._children_index_by_id[child.model.id] = child_index
        del self._children_index_by_id[item.model.id]
        if self._children_tree is not None:
            if new_unmapped_range.length() > 0:
                # The interval tree does not support 0-sized ranges
                self._children_tree.removei(new_unmapped_range.start, new_unmapped_range.end, item)

        #
        # Updated the unmapped range after the child is removed
        #

        # Build a list of mapped data left over within the "freed" range.
        overlapping_children = list(self.get_children_in_range(new_unmapped_range))
        new_unmapped_ranges = [new_unmapped_range]
        # Remove the mapped data taken by remaining children from the "freed" range. This can leave
        # the entire unmapped range intact, create multiple smaller unmapped ranges, or leave it
        # emtpy.
        for overlapping_child in overlapping_children:
            updated_unmapped_ranges: List[Range] = []
            for new_unmapped_range in new_unmapped_ranges:
                updated_unmapped_ranges.extend(
                    new_unmapped_range.split(overlapping_child.model.range)
                )
            new_unmapped_ranges = updated_unmapped_ranges

        if len(new_unmapped_ranges) == 0:
            # This can happen if the "freed" range is fully occupied by the remaining children
            return

        # Check if the left over unmapped range(s) can be merged with existing unmapped range(s)
        new_unmapped_range_left = new_unmapped_ranges[0]
        new_unmapped_range_right = new_unmapped_ranges[-1]

        left_child_empty = False
        right_child_empty = False
        left_child_index = bisect.bisect_left(self._children, (new_unmapped_range_left.start,))
        right_child_index = bisect.bisect_left(self._children, (new_unmapped_range_right.end,))
        if left_child_index < len(self._children):
            _, left_child = self._children[left_child_index]
            if (
                left_child.model.range.start == new_unmapped_range_left.start
                and left_child.model.range.length() == 0
            ):
                left_child_empty = True

        if right_child_index < len(self._children):
            _, right_child = self._children[right_child_index]
            if (
                right_child.model.range.start == new_unmapped_range_right.end
                and right_child.model.range.length() == 0
            ):
                right_child_empty = True

        unmapped_range_right_index = bisect.bisect_left(
            self._unmapped_ranges, (new_unmapped_range_left.start,)
        )
        if (
            0 < unmapped_range_right_index < len(self._unmapped_ranges)
            and len(new_unmapped_ranges) == 1
            and not left_child_empty
            and not right_child_empty
        ):
            # Check if the existing unmapped range on the left can be merged with the existing
            # unmapped range on the right
            _, unmapped_range_left = self._unmapped_ranges[unmapped_range_right_index - 1]
            _, unmapped_range_right = self._unmapped_ranges[unmapped_range_right_index]
            if (
                unmapped_range_left.end == new_unmapped_range_left.start
                and unmapped_range_right.start == new_unmapped_range_right.end
            ):

                # Remove old range from sizes before we reassign.
                self._pop_size(self._unmapped_ranges[unmapped_range_right_index - 1][1])

                # Merge the existing unmapped ranges (which involves removing one of them)
                merge = Range(unmapped_range_left.start, unmapped_range_right.end)
                self._unmapped_ranges[unmapped_range_right_index - 1] = (
                    unmapped_range_left.start,
                    merge,
                )

                # Add size of merge and pop the size of removed range.
                self._push_size(merge)
                self._pop_size(self._unmapped_ranges[unmapped_range_right_index][1])

                self._unmapped_ranges.pop(unmapped_range_right_index)
                return
        if unmapped_range_right_index > 0 and not left_child_empty:
            _, unmapped_range_left = self._unmapped_ranges[unmapped_range_right_index - 1]
            if unmapped_range_left.end == new_unmapped_range_left.start:

                # Remove old range from sizes before we reassign.
                self._pop_size(self._unmapped_ranges[unmapped_range_right_index - 1][1])

                # Left replacement range.
                repl_l = Range(unmapped_range_left.start, new_unmapped_range_left.end)

                self._unmapped_ranges[unmapped_range_right_index - 1] = (
                    unmapped_range_left.start,
                    repl_l,
                )

                # Add the left range size.
                self._push_size(repl_l)

                if len(new_unmapped_ranges) == 1:
                    return
                # The new range on the left has been handled
                del new_unmapped_ranges[0]
        if unmapped_range_right_index < len(self._unmapped_ranges) and not right_child_empty:
            _, unmapped_range_right = self._unmapped_ranges[unmapped_range_right_index]
            if unmapped_range_right.start == new_unmapped_range_right.end:

                # Remove old range from sizes before we reassign.
                self._pop_size(self._unmapped_ranges[unmapped_range_right_index][1])

                # Right replacement range.
                repl_r = Range(new_unmapped_range_right.start, unmapped_range_right.end)

                self._unmapped_ranges[unmapped_range_right_index] = (
                    new_unmapped_range_right.start,
                    repl_r,
                )

                # Add the left replacement range size.
                self._push_size(repl_r)

                if len(new_unmapped_ranges) == 1:
                    return
                # The new range on the right has been handled
                del new_unmapped_ranges[1]
        # Insert the remaining unmapped ranges
        for new_unmapped_range in new_unmapped_ranges:
            if new_unmapped_range.length() == 0:
                # This can happen when there are multiple 0-sized children next to each other and
                # one of them is removed. The unmapped range would contain a single empty range
                # which still be present by the time it gets here
                continue
            new_range = Range(new_unmapped_range.start, new_unmapped_range.end)
            self._unmapped_ranges.insert(
                unmapped_range_right_index,
                (
                    new_unmapped_range.start,
                    new_range,
                ),
            )
            self._push_size(new_range)

            unmapped_range_right_index += 1

    def translate_children(
        self, patch_infos: List[Tuple[Range, int, DataRangePosition, int]]
    ) -> None:
        # Notes on internal variables:
        # `i`: Index in `self._children` of current child.
        # `patch_child_idx`: Index in `self._children` of child the current patch is associated with
        # `total_size_change`: Running total magnitude of translation.
        #
        # N.B.: `patch_infos` is assumed to be sorted as in `apply_patches()`.
        i, total_size_change, num_children = 0, 0, len(self._children)
        if num_children == 0:
            return
        # Loop over all patches for this node.
        for _, patch_child_idx, pos, size_change in patch_infos:
            assert pos is not DataRangePosition.OVERLAP
            # For UNMAPPED ranges, patch_child_idx is the idx of the NEXT child
            # In this case we would want the while condition to be `... and i < patch_child_idx`
            # This transformation accomplishes that
            if pos is DataRangePosition.UNMAPPED:
                patch_child_idx -= 1
            # Translate all children at or before the current patch's node.
            while i < num_children and i <= patch_child_idx:
                child = self._children[i][1]
                child.translate(total_size_change)
                self._children[i] = (child.model.range.start, child)
                i += 1
            total_size_change += size_change

        # If we got through all the patches, translate the remaining children.
        while i < num_children:
            child = self._children[i][1]
            child.translate(total_size_change)
            self._children[i] = (child.model.range.start, child)
            i += 1

    def translate(self, translate_offset: int):
        if translate_offset == 0:
            return
        if not self.parent:
            raise ValueError(f"Can't translate root data node {self.model.id.hex()}")
        LOGGER.debug(f"Translating data {self.model.id.hex()} by {translate_offset} byte(s)")
        new_model = dataclasses.replace(
            self.model, range=self.model.range.translate(translate_offset)
        )
        if self.parent._children_tree is not None:
            self.parent._children_tree.removei(self.model.range.start, self.model.range.end, self)
            self.model = new_model
            self.parent._children_tree.addi(self.model.range.start, self.model.range.end, self)
        else:
            self.model = new_model

    def resize(self, size_diff: int):
        if size_diff == 0:
            return
        LOGGER.debug(f"Resizing data {self.model.id.hex()} by {size_diff} byte(s)")
        new_model = dataclasses.replace(
            self.model, range=Range(self.model.range.start, self.model.range.end + size_diff)
        )
        if self.parent is not None and self.parent._children_tree is not None:
            self.parent._children_tree.removei(self.model.range.start, self.model.range.end, self)
            self.model = new_model
            self.parent._children_tree.addi(self.model.range.start, self.model.range.end, self)
        else:
            self.model = new_model

    def __hash__(self):
        return hash(self.model.id)

    def __eq__(self, other):
        return self.model.id == other.model.id

    def __repr__(self):
        return f"DataNode({self.model.id.hex()}, {self.model.range})"

    def __lt__(self, other: "DataNode") -> bool:
        if not isinstance(other, DataNode):
            return False
        return self.model.range.start < other.model.range.start


PatchPosition = Tuple[int, DataRangePosition]
PatchAncestor = Tuple[DataNode, Range]
PatchInfo = Tuple[int, Tuple[PatchPosition, ...], DataPatch, Range, List[PatchAncestor]]


class DataService(DataServiceInterface):
    _data_store: Dict[bytes, bytes]
    _data_node_store: Dict[bytes, DataNode]
    _patchlog: List[Tuple[List[DataPatch], Dict[bytes, Dict[int, bytes]]]]
    _savepoints: Dict[str, int]
    _savepoint_idxs: Dict[int, str]

    def __init__(self):
        self._data_store = dict()
        self._data_node_store = dict()
        self._patchlog = []
        self._savepoints = dict()
        self._savepoint_idxs = dict()

    async def create(self, data_id: bytes, data: bytes, alignment: int = 1) -> DataModel:
        if data_id in self._data_node_store:
            raise AlreadyExistError(f"The data {data_id.hex()} already exists")
        model = DataModel(data_id, Range(0, len(data)), alignment, None)
        self._data_store[data_id] = data
        self._data_node_store[data_id] = DataNode(model)
        return model

    async def create_mapped(
        self,
        data_id: bytes,
        parent_id: bytes,
        range: Range,
        alignment: int = 1,
        after_data_id: Optional[bytes] = None,
        before_data_id: Optional[bytes] = None,
    ) -> DataModel:
        if data_id in self._data_node_store:
            raise AlreadyExistError(f"The data {data_id.hex()} already exists")
        parent_node = self._data_node_store.get(parent_id)
        if parent_node is None:
            raise NotFoundError(f"The parent data {parent_id.hex()} does not exist")
        parent_alignment = parent_node.model.alignment
        if range.start % parent_alignment != 0:
            raise NotFoundError(
                f"The provided data is not aligned according to the parent "
                f"{parent_node.model.id.hex()} requirements of being {parent_alignment} bytes aligned"
            )
        model = DataModel(data_id, range, alignment, parent_id)
        self._data_node_store[model.id] = parent_node.insert(model, after_data_id, before_data_id)
        LOGGER.debug(f"Inserted child {data_id.hex()} into {parent_id.hex()} at {range}")
        return model

    async def get_by_id(self, data_id: bytes) -> DataModel:
        data_node = self._data_node_store.get(data_id)
        if data_node is None:
            raise NotFoundError(f"The data {data_id.hex()} does not exist")
        return data_node.model

    async def get_by_ids(self, data_ids: Iterable[bytes]) -> Iterable[DataModel]:
        data_models = []
        for data_id in data_ids:
            data_models.append(await self.get_by_id(data_id))
        return data_models

    async def get_data_length(self, data_id: bytes) -> int:
        return (await self.get_by_id(data_id)).range.length()

    async def get_unmapped_range(self, data_id: bytes, offset: int) -> Range:
        data_node = self._data_node_store.get(data_id)
        if data_node is None:
            raise NotFoundError(f"The data {data_id.hex()} does not exist")
        return data_node.get_unmapped_range(offset)

    async def get_index_within_parent(self, data_id: bytes) -> int:
        data_node = self._data_node_store.get(data_id)
        if data_node is None:
            raise NotFoundError(f"The data {data_id.hex()} does not exist")
        if data_node.parent is None:
            raise ValueError(f"The data {data_id.hex()} is a root node")
        return data_node.parent.get_child_index(data_node)

    async def get_range_within_parent(self, data_id: bytes) -> Range:
        model = await self.get_by_id(data_id)
        if not model.is_mapped():
            return Range(0, 0)
        else:
            return model.range

    def _get_root_absolute_range(
        self, data_id: bytes, data_range: Range = None
    ) -> Tuple[DataNode, Range]:
        data_node = self._data_node_store.get(data_id)
        if data_node is None:
            raise NotFoundError(f"The data {data_id.hex()} does not exist")
        if data_range is None:
            data_range = data_node.model.range
        else:
            data_range = data_range.translate(data_node.model.range.start).intersect(
                data_node.model.range
            )
        while data_node.parent is not None:
            data_node = data_node.parent
            data_range = data_range.translate(data_node.model.range.start)
        return data_node, data_range

    async def get_range_within_ancestor(self, data_id: bytes, ancestor_id: bytes) -> Range:
        data_node = self._data_node_store.get(data_id)
        if data_node is None:
            raise NotFoundError(f"The data {data_id.hex()} does not exist")
        data_range = data_node.model.range
        if data_id == ancestor_id:
            return Range.from_size(0, data_range.length())
        while data_node.parent is not None:
            if data_node.parent.model.id == ancestor_id:
                return data_range
            data_node = data_node.parent
            data_range = data_range.translate(data_node.model.range.start)

        raise NotFoundError(f"The data {data_id.hex()} has no such ancestor {ancestor_id.hex()}")

    async def get_data_range_within_root(self, data_id: bytes) -> Range:
        _, data_range = self._get_root_absolute_range(data_id)
        return data_range

    async def get_data(self, data_id: bytes, data_range: Range = None) -> bytes:
        data_node, data_range = self._get_root_absolute_range(data_id, data_range)
        data = self._data_store[data_node.model.id]
        return data[data_range.start : data_range.end]

    async def set_alignment(self, data_id: bytes, alignment: int):
        data_node = self._data_node_store.get(data_id)
        if data_node is None:
            raise NotFoundError(f"The data {data_id.hex()} does not exist")
        data_node.model = dataclasses.replace(data_node.model, alignment=alignment)

    async def set_overlaps_enabled(self, data_id: bytes, enable_overlaps: bool):
        data_node = self._data_node_store.get(data_id)
        if data_node is None:
            raise NotFoundError(f"The data {data_id.hex()} does not exist")
        data_node.set_overlaps_enabled(enable_overlaps)

    async def get_unmapped_ranges(
        self, data_id: bytes, sort_by_size: bool = False, bounds: Optional[Range] = None
    ) -> Iterable[Range]:
        node = self._data_node_store.get(data_id)
        if node is None:
            raise NotFoundError(f"The data {data_id.hex()} does not exist")
        entire_range = Range(0, node.model.range.length())
        if bounds is not None and not bounds.within(entire_range):
            raise OutOfBoundError(f"``{bounds}`` not subset of ``{entire_range}``.")
        return node.get_unmapped_ranges(sort_by_size, bounds)

    async def apply_patches(
        self,
        patches: Optional[List[DataPatch]] = None,
        moves: Optional[List[DataMove]] = None,
    ) -> List[DataPatchesResult]:
        """
        Apply multiple patches at once. The patches must meet the following guidelines:

        - Patches should not overlap each other.
        - Patches that cause a size change cannot affect any of the node's children, and they cannot
          overlap boundaries of the node, its siblings or its ancestors.
        - There can only be at most two patches between sibling nodes: one after the left child and
          one before the right child. There may be more patches that resolve to the same position if
          they are applied at a greater depth.
        """
        if patches is None:
            patches = []
        moved_data_ids = set()
        delayed_patches = []
        current_patches = []
        if moves is not None and len(moves) > 0:
            # The moves can only happen once their after/before data IDs has been moved
            move_ids = set()
            moves_by_dependency = defaultdict(list)
            moves_ready: Deque[DataMove] = deque()
            remaining_moves = len(moves)
            for move in moves:
                move_ids.add(move.data_id)

            for move in moves:
                # Figure out which moves depends on which
                if move.after_data_id and move.after_data_id in move_ids:
                    moves_by_dependency[move.after_data_id].append(move)
                    continue
                elif move.before_data_id and move.before_data_id in move_ids:
                    moves_by_dependency[move.before_data_id].append(move)
                    continue
                moves_ready.append(move)

            while len(moves_ready) > 0:
                move = moves_ready.popleft()
                remaining_moves -= 1
                move_dependencies = moves_by_dependency[move.data_id]
                for move_dependency in move_dependencies:
                    # These moves are now considered ready
                    moves_ready.append(move_dependency)
                data_node = self._data_node_store.get(move.data_id)
                if data_node is None:
                    raise NotFoundError(f"The data {move.data_id.hex()} does not exist")
                if not data_node.model.is_mapped():
                    raise ValueError(f"The data {move.data_id.hex()} is not mapped")
                data = await self.get_data(move.data_id)
                parent_node = data_node.parent
                assert parent_node is not None
                patches.append(
                    DataPatch(
                        data_node.model.range,
                        parent_node.model.id,
                        b"\x00" * len(data),
                    )
                )
                parent_node.remove(data_node)
                data_node.model = dataclasses.replace(data_node.model, range=move.range)
                parent_node.insert_node(
                    data_node, after_data_id=move.after_data_id, before_data_id=move.before_data_id
                )
                current_patches.append(
                    DataPatch(
                        Range.from_size(0, move.range.length()),
                        move.data_id,
                        data,
                    )
                )
                moved_data_ids.add(move.data_id)
            if remaining_moves != 0:
                # TODO: Make this error message more helpful for debugging. This should be a very
                #  rare case of foot-shooting but also very hard to track.
                raise ValueError("There is a circular dependencies on the moves")

        for patch in patches:
            # Determine if a patch can be applied immediately or if it needs to wait until after
            # the move is completed. This is to avoid issues when a patch applies to data that is
            # sized differently after the patch for the move (going from 0 to x for example).
            if patch.data_id not in moved_data_ids:
                current_patches.append(patch)
            else:
                if patch.range.length() != len(patch.data):
                    raise ValueError(
                        "Cannot apply a patch that causes a change in size to a node that is "
                        "being moved"
                    )
                delayed_patches.append(patch)

        # Maps ``patch.data_id`` to maps of original data being overwritten by patches.
        overwritten_map: Dict[bytes, Dict[int, bytes]] = {}

        # Save a copy of the patches we applied during this call.
        for patch in current_patches:

            # Maps hashes of ranges to original data within a patch.
            orig_patch_map: Dict[int, bytes] = overwritten_map.get(patch.data_id, {})
            overwritten_data = await self.get_data(patch.data_id, patch.range)
            orig_patch_map[hash(patch.range)] = overwritten_data
            overwritten_map[patch.data_id] = orig_patch_map

        # Add patches and overwritten history to patchlog.
        self._patchlog.append((copy.deepcopy(current_patches), overwritten_map))

        patches_by_root_id: Dict[bytes, List[PatchInfo]] = defaultdict(list)
        for patch in current_patches:
            data_node = self._data_node_store.get(patch.data_id)
            if data_node is None:
                raise NotFoundError(f"The data {patch.data_id.hex()} does not exist")
            if patch.range.end > data_node.model.range.end:
                raise OutOfBoundError(
                    f"The patch on {patch.data_id.hex()} at {patch.range} is outside the bound of"
                    f" {data_node}"
                )
            patch_data_length = len(patch.data)
            patch_range_length = patch.range.length()
            patch_length_diff = patch_data_length - patch_range_length

            if patch_length_diff != 0:
                # Validate that the patch does not overlap with any child of the targeted node.
                children = list(data_node.get_children_in_range(patch.range))
                for child in children:
                    raise PatchOverlapError(f"The {patch} overlaps with child {child}")

            # Build up the information required to sort the patches.
            ancestors_info: Deque[PatchAncestor] = deque()
            ancestors_indexes: Deque[PatchPosition] = deque()
            ancestor_node: Optional[DataNode] = data_node
            ancestor_patch_range = patch.range
            while ancestor_node is not None:
                if patch_length_diff != 0:
                    ancestor_children = ancestor_node.get_children_in_range(ancestor_patch_range)
                    # Validate that the patch overlaps with at most one child within the ancestor.
                    for i, child in enumerate(ancestor_children):
                        # "Overlapping" with 0-sized children is not a problem
                        if i != 0 and child.model.range.length() != 0:
                            raise PatchOverlapError(
                                f"The {patch} overlaps with more than one child within ancestor"
                                f" {ancestor_node}"
                            )
                        if not ancestor_patch_range.within(child.model.range):
                            raise OutOfBoundError(
                                f"The {patch} is not fully within ancestor {ancestor_node}"
                            )
                # Get the index for that patch within the ancestor children to eventually sort them
                patch_index, patch_position = ancestor_node.get_range_index(
                    ancestor_patch_range,
                    None if len(ancestors_info) == 0 else ancestors_info[0][0].model.id,
                    patch.after_data_id if len(ancestors_info) == 0 else None,
                    patch.before_data_id if len(ancestors_info) == 0 else None,
                )
                assert patch_position != DataRangePosition.OVERLAP, "Unexpected overlap"
                ancestors_indexes.appendleft((patch_index, patch_position))
                ancestors_info.appendleft((ancestor_node, ancestor_patch_range))

                ancestor_patch_range = ancestor_patch_range.translate(
                    ancestor_node.model.range.start
                )
                ancestor_node = ancestor_node.parent

            # Populate the dictionary used to segregate patches that affect different root data
            # nodes
            root_data_node, root_patch_range = ancestors_info[0]
            patches_by_root_id[root_data_node.model.id].append(
                (
                    root_patch_range.start,  # Used for sorting
                    tuple(ancestors_indexes),  # Used for sorting
                    patch,  # The original patch
                    root_patch_range,  # The patch range within the root node
                    list(ancestors_info),  # The nodes affected by the patch
                )
            )

        results_by_id: Dict[bytes, List[DataPatchResult]] = defaultdict(list)
        for node_data_id, node_data_patches in patches_by_root_id.items():
            try:
                node_data_patches.sort()
            except TypeError:
                offenders = []
                starts_and_ancestor_idxs = [
                    (data_patch[0], data_patch[1]) for data_patch in node_data_patches
                ]
                for _, dup_locations in _list_duplicates(starts_and_ancestor_idxs):
                    for loc in dup_locations:
                        # We only want to look at the patch for debugging purposes.
                        offenders.append(node_data_patches[loc][2])
                # That means the `DataPatch` instance had to be compared, meaning there are at
                # least 2 patches that are being applied to the same location
                raise PatchOverlapError(f"The patch overlaps another patch. Offenders: {offenders}")
            current_offset = None
            current_patch_info = None

            patch_info_by_node: Dict[
                DataNode, List[Tuple[Range, int, DataRangePosition, int]]
            ] = defaultdict(list)

            root_patches: List[Tuple[Range, bytes]] = []
            # Validate that there are no overlaps and populate the `patches_by_node` dictionary
            for (
                patch_start,
                patch_positions,
                patch,
                root_patch_range,
                patch_ancestors,
            ) in node_data_patches:
                prev_patch_info = current_patch_info
                prev_offset = current_offset
                current_patch_info = (patch_start, patch_positions)
                current_offset = root_patch_range.end
                if prev_patch_info is not None:
                    if root_patch_range.start < prev_offset:
                        raise PatchOverlapError("The patch overlaps another patch")
                    if current_patch_info == prev_patch_info:
                        # This doesn't get caught by a sort error if the patches are completely
                        # equal
                        raise PatchOverlapError("The patch overlaps another patch")
                size_diff = len(patch.data) - patch.range.length()
                root_patches.append((root_patch_range, patch.data))
                for ((patch_child_index, patch_child_position), (patch_node, patch_range)) in zip(
                    patch_positions, patch_ancestors
                ):
                    patch_info_by_node[patch_node].append(
                        (patch_range, patch_child_index, patch_child_position, size_diff)
                    )
                    results_by_id[patch_node.model.id].append(
                        DataPatchResult(
                            patch_range,
                            size_diff,
                            patch_child_index,
                            patch_child_position,
                        )
                    )

            # TODO: Deal with alignment
            # Update the root data.
            data = self._data_store[node_data_id]
            data_parts = []
            previous_patch_end = 0
            for patch_range, patch_data in root_patches:
                data_parts.append(data[previous_patch_end : patch_range.start])
                data_parts.append(patch_data)
                previous_patch_end = patch_range.end
            data_parts.append(data[previous_patch_end:])
            self._data_store[node_data_id] = b"".join(data_parts)

            # Translate and resize the nodes affected by the patches
            for node, patch_infos in patch_info_by_node.items():
                # Resize the node first so that the children can be translated into a valid range
                aggregate_size_change = 0
                for _, _, _, size_diff in patch_infos:
                    aggregate_size_change += size_diff
                node.resize(aggregate_size_change)
                node.translate_children(patch_infos)

        results = []
        for node_data_id, data_patch_results in results_by_id.items():
            results.append(DataPatchesResult(node_data_id, data_patch_results))

        if len(delayed_patches) > 0:
            # TODO: Merge the results
            await self.apply_patches(delayed_patches)
        return results

    async def delete_node(self, data_id: bytes) -> None:
        data_node_deleting = self._data_node_store[data_id]
        del self._data_node_store[data_id]

        if not data_node_deleting.is_root():
            parent = data_node_deleting.parent
            assert parent is not None
            node_index = parent.get_child_index(data_node_deleting)
            prev_node_index = node_index - 1
            prev_node_id: Optional[bytes]
            if prev_node_index >= 0:
                prev_node_id = parent.get_child(prev_node_index).model.id
            else:
                prev_node_id = None

            parent.remove(data_node_deleting)

            for i in range(data_node_deleting.get_num_children()):
                child = data_node_deleting.get_child(i)
                original_child_range = child.model.range
                new_child_range = Range(
                    original_child_range.start + data_node_deleting.model.range.start,
                    original_child_range.end + data_node_deleting.model.range.start,
                )
                child.model.range = new_child_range
                parent.insert_node(child, after_data_id=prev_node_id)
                prev_node_id = child.model.id
                child.set_parent(parent)

        else:
            # TODO: Make all children roots?
            raise NotImplementedError

    async def merge_siblings(self, new_data_id: bytes, merging_data_ids: Iterable[bytes]) -> None:
        await self.gather_siblings(new_data_id, merging_data_ids)
        nodes_to_merge = [self._data_node_store[data_id] for data_id in merging_data_ids]
        for data_node in nodes_to_merge:
            await self.delete_node(data_node.model.id)

    async def gather_siblings(
        self, new_data_id: bytes, gathering_data_ids: Iterable[bytes]
    ) -> None:
        nodes_to_gather = [self._data_node_store[data_id] for data_id in gathering_data_ids]

        # First check that all nodes share the same parent (and none are root)
        parent_nodes = [data_node.parent for data_node in nodes_to_gather if data_node.parent]
        nodes_share_single_parent = all(
            [
                parent_node is not None and parent_node.model.id == parent_nodes[0].model.id
                for parent_node in parent_nodes
            ]
        )
        if not nodes_share_single_parent:
            raise NonContiguousError(f"Not all nodes in {gathering_data_ids} share the same parent")

        # Next check that the provided nodes are contiguous
        parent_node = parent_nodes[0]
        node_ranges = sorted(
            (data_node.model.range for data_node in nodes_to_gather), key=lambda r: r.start
        )
        prev_end = node_ranges[0].start

        for r in node_ranges:
            if r.start != prev_end:
                raise NonContiguousError(
                    f"Nodes {gathering_data_ids} are not contiguous (gap between "
                    f"0x{prev_end:x} and 0x{r.start:x})"
                )
            else:
                prev_end = r.end

        # Create the merged data model
        merged_range_begin = node_ranges[0].start
        merged_range_end = max(r.end for r in node_ranges)
        new_range = Range(merged_range_begin, merged_range_end)

        new_model = DataModel(new_data_id, new_range, parent_id=parent_node.model.id)

        new_node = DataNode(new_model, parent_node)
        self._data_node_store[new_data_id] = new_node

        # Remove each gathered node from the parent and this store
        for data_node in nodes_to_gather:
            parent_node.remove(data_node)
            data_node.model.range = Range(
                data_node.model.range.start - merged_range_begin,
                data_node.model.range.end - merged_range_begin,
            )
            new_node.insert_node(data_node)
            data_node.set_parent(new_node)

        parent_node.insert_node(new_node)

    async def create_savepoint(self) -> str:
        """
        `self._savepoints: Dict[str, int]` maps savepoint IDs to indices in `self._patchlog`.

        This function saves the index in `self._patchlog`, and adds a pair to `self._savepoints`.
        """
        index = len(self._patchlog)

        # If we've saved this ``index`` before, just return that savepoint ID.
        if index in self._savepoint_idxs:
            return self._savepoint_idxs[index]

        # Otherwise, generate a new one.
        randhash = "%020x" % random.randrange(16**20)
        stamp = datetime.datetime.utcnow().strftime("%m-%d-%Y--%H:%M:%S")
        savepoint_id = f"{randhash}--{stamp}--PATCHLOG_INDEX:{index}"
        self._savepoints[savepoint_id] = index
        self._savepoint_idxs[index] = savepoint_id

        return savepoint_id

    async def get_patches_between_savepoints(
        self, start: str, end: str = ""
    ) -> List[List[DataPatch]]:
        """
        Returns a list of lists of patches between the given savepoint strings.
        """
        if start not in self._savepoints:
            raise ValueError(f"Savepoint `{start}` not found.")
        start_index = self._savepoints.get(start, len(self._patchlog))
        end_index = self._savepoints.get(end, len(self._patchlog))
        return [savepoint[0] for savepoint in self._patchlog[start_index:end_index]]

    async def delete_tree(self, data_id: bytes) -> None:
        data_node_deleting = self._data_node_store.get(data_id)
        if data_node_deleting is None:
            # Already deleted
            return

        parent = data_node_deleting.parent
        if parent is not None:
            parent.remove(data_node_deleting)

        def _delete_tree_helper(_data_node: DataNode):
            for i, child in _data_node._children:
                _delete_tree_helper(child)

            del self._data_node_store[_data_node.model.id]

        _delete_tree_helper(data_node_deleting)


def _list_duplicates(seq):
    """Helper function for better error messages."""
    tally = defaultdict(list)
    for i, item in enumerate(seq):
        tally[item].append(i)
    return ((key, locs) for key, locs in tally.items() if len(locs) > 1)
