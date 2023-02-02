import heapq
import itertools
from bisect import bisect_left, bisect_right
from collections import defaultdict
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple, TypeVar, Generic

from sortedcontainers import SortedList

from ofrak.model.data_model import DataModel, DataPatch, DataPatchesResult
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.error import OutOfBoundError, PatchOverlapError
from ofrak_type.error import NotFoundError, AlreadyExistError
from ofrak_type.range import Range

# Type alias; typechecker makes no distinction between this and bytes. It's just for humans (you?)
DataId = bytes


class DataService(DataServiceInterface):
    def __init__(self):
        self._model_store: Dict[DataId, DataModel] = dict()
        self._roots: Dict[DataId, _DataRoot] = dict()

    async def create_root(self, data_id: DataId, data: bytes) -> DataModel:
        if data_id in self._model_store:
            raise AlreadyExistError(f"A model with {data_id.hex()} already exists!")

        new_model = DataModel(data_id, Range(0, len(data)), data_id)

        self._model_store[data_id] = new_model
        self._roots[data_id] = _DataRoot(new_model, data)

        return new_model

    async def create_mapped(
        self,
        data_id: DataId,
        parent_id: DataId,
        range_in_parent: Range,
    ) -> DataModel:
        if data_id in self._model_store:
            raise AlreadyExistError(f"A model with {data_id.hex()} already exists!")

        parent_model = self._get_by_id(parent_id)
        range_in_root = range_in_parent.translate(parent_model.range.start)
        if range_in_root.end > parent_model.range.end:
            raise OutOfBoundError(
                f"Cannot map a new node into range {range_in_root} into {parent_model.range} of "
                f"{parent_id.hex()}"
            )

        new_model = DataModel(data_id, range_in_root, parent_model.root_id)
        self._roots[parent_model.root_id].add_mapped_model(new_model)
        self._model_store[data_id] = new_model

        return new_model

    async def get_by_id(self, data_id: DataId) -> DataModel:
        return self._get_by_id(data_id)

    async def get_by_ids(self, data_ids: Iterable[DataId]) -> Iterable[DataModel]:
        return [self._get_by_id(data_id) for data_id in data_ids]

    async def get_data_length(self, data_id: DataId) -> int:
        return self._get_by_id(data_id).range.length()

    async def get_data_range_within_root(self, data_id: DataId) -> Range:
        return self._get_by_id(data_id).range

    async def get_range_within_other(self, data_id: DataId, within_data_id: DataId) -> Range:
        model = self._get_by_id(data_id)
        within_model = self._get_by_id(within_data_id)
        if data_id == within_data_id:
            return Range.from_size(0, model.range.length())
        if self._is_root(data_id):
            raise ValueError(
                f"{data_id.hex()} is a root, not mapped into {within_data_id.hex()} (a root)!"
            )
        elif self._is_root(within_data_id) and model.root_id != within_model.id:
            raise ValueError(f"{data_id.hex()} is not mapped into {within_data_id.hex()} (a root)!")
        elif not self._is_root(within_data_id) and model.root_id != within_model.root_id:
            raise ValueError(
                f"{data_id.hex()} and {within_data_id.hex()} are not mapped into the same root!"
            )
        else:
            return within_model.range.intersect(model.range).translate(-within_model.range.start)

    async def get_data(self, data_id: DataId, data_range: Optional[Range] = None) -> bytes:
        model = self._get_by_id(data_id)
        root = self._get_root_by_id(model.root_id)
        if data_range is not None:
            translated_range = data_range.translate(model.range.start).intersect(root.model.range)
            return root.data[translated_range.start : translated_range.end]
        else:
            return root.data[model.range.start : model.range.end]

    async def apply_patches(self, patches: List[DataPatch]) -> List[DataPatchesResult]:
        patches_by_root: Dict[DataId, List[DataPatch]] = defaultdict(list)
        for patch in patches:
            target_data_model = self._get_by_id(patch.data_id)
            patches_by_root[target_data_model.root_id].append(patch)

        results = []
        for root_id, patches_for_root in patches_by_root.items():
            results.extend(self._apply_patches_to_root(root_id, patches_for_root))

        return results

    async def delete_models(self, data_ids: Iterable[DataId]) -> None:
        roots_to_delete = dict()
        mapped_to_delete = dict()

        for data_id in data_ids:
            try:
                model = self._get_by_id(data_id)
            except NotFoundError:
                continue
            if model.is_mapped():
                mapped_to_delete[model.id] = model
            else:
                roots_to_delete[model.id] = model

        for root_model in roots_to_delete.values():
            root = self._roots[root_model.id]
            for child_model in root.get_children():
                mapped_to_delete.pop(child_model.id, None)
                del self._model_store[child_model.id]

            del self._roots[root_model.id]
            del self._model_store[root_model.id]

        for model in mapped_to_delete.values():
            root = self._get_root_by_id(model.root_id)
            root.delete_mapped_model(model)
            del self._model_store[model.id]

    def _get_by_id(self, data_id: DataId) -> DataModel:
        model = self._model_store.get(data_id)
        if model is None:
            raise NotFoundError(f"No data model with ID {data_id.hex()} exists")
        else:
            return model

    def _get_root_by_id(self, data_id: DataId) -> "_DataRoot":
        root = self._roots.get(data_id)
        if root is None:
            raise NotFoundError(f"No data root with ID {data_id.hex()} exists")
        else:
            return root

    def _is_root(self, data_id: DataId) -> bool:
        return data_id in self._roots

    def _get_range_in_root(self, model: DataModel, r: Range) -> Range:
        if r.start < 0 or r.end > model.range.length():
            raise OutOfBoundError(
                f"The requested range {r} of model {model.id.hex()} is outside the "
                f"model's range {model.range}"
            )

        absolute_range = r.translate(model.range.start)
        return absolute_range

    def _apply_patches_to_root(
        self,
        root_data_id: DataId,
        patches: List[DataPatch],
    ) -> List[DataPatchesResult]:
        root: _DataRoot = self._roots[root_data_id]
        finalized_ordered_patches: List[Tuple[Range, bytes, int]] = []
        resize_tracker = _PatchResizeTracker()

        # Screen patches for inconsistencies/overlaps
        # And translate them as required by preceding patches
        raw_patch_ranges_in_root = []

        for patch in patches:
            target_model = self._get_by_id(patch.data_id)
            patch_range_in_prepatch_root = self._get_range_in_root(target_model, patch.range)

            if resize_tracker.overlaps_resized_range(patch_range_in_prepatch_root):
                raise PatchOverlapError(
                    f"Patch to {patch.range} of {patch.data_id.hex()} overlaps previously resized "
                    f"area of {patch.data_id.hex()} and cannot be applied!"
                )

            raw_patch_ranges_in_root.append(patch_range_in_prepatch_root)
            patch_range_in_patched_root = resize_tracker.translate_range(
                patch_range_in_prepatch_root
            )
            models_intersecting_patch_range = root.get_children_with_boundaries_intersecting_range(
                patch_range_in_prepatch_root
            )

            size_diff = len(patch.data) - patch.range.length()
            if size_diff == 0:
                finalized_ordered_patches.append(
                    (patch_range_in_patched_root, patch.data, size_diff)
                )
            elif models_intersecting_patch_range:
                raise PatchOverlapError(
                    f"Because patch to {patch.data_id.hex()} resizes data by {size_diff} bytes, "
                    f"the effects on {len(models_intersecting_patch_range)} model(s) "
                    f"intersecting the patch range {patch.range} ({patch_range_in_patched_root} "
                    f"in the root) could not be determined. If data must be resized, any resources "
                    f"overlapping the data must be deleted before patching and re-created "
                    f"afterwards along new data ranges. Intersecting models: {models_intersecting_patch_range}"
                )
            else:
                finalized_ordered_patches.append(
                    (patch_range_in_patched_root, patch.data, size_diff)
                )
                resize_tracker.add_new_resized_range(patch_range_in_patched_root, size_diff)

        affected_ranges = Range.merge_ranges(raw_patch_ranges_in_root)

        results = defaultdict(list)

        for affected_id, affected_range in root.get_children_affected_by_ranges(affected_ranges):
            results[affected_id].append(affected_range)

        for affected_range in affected_ranges:
            results[root_data_id].append(affected_range)

        new_root_data = bytearray(root.data)
        # Apply finalized patches to data and data models
        for patch_range, data, size_diff in finalized_ordered_patches:
            new_root_data[patch_range.start : patch_range.end] = data
            if size_diff != 0:
                root.resize_range(patch_range, size_diff)
        root.data = bytes(new_root_data)

        return [
            DataPatchesResult(data_id, results_for_id)
            for data_id, results_for_id in results.items()
        ]


T = TypeVar("T")


class _ShiftBreaksSortError(RuntimeError):
    pass


class _CompareFirstTuple(Tuple, Generic[T]):
    """
    Wrapper for tuple that ensures only the first item in the tuple is checked.
    Necessary because bisect methods don't have a `key` function
    Helpful for making sorted dictionary-like data structures
    """

    def __new__(cls, *args):
        return super().__new__(cls, args)

    def __lt__(self, other):
        return self[0] < other[0]

    def __eq__(self, other):
        return self[0] == other[0]

    # __gt__ function excluded, as it is not needed by built-in Python utils like `sort`

    @staticmethod
    def bisect_left(grid, val: int) -> int:
        return bisect_left(grid, _CompareFirstTuple(val, None))

    @staticmethod
    def bisect_right(grid, val: int) -> int:
        return bisect_right(grid, _CompareFirstTuple(val, None))


# These lists undergo inserts, appends, and removals fairly often. If they become a bottleneck,
#   another data structure (e.g. tree) would give better performance for those operations.
_GridYAxisT = List[_CompareFirstTuple[Set[DataId]]]
_GridXAxisT = List[_CompareFirstTuple[_GridYAxisT]]


class _DataRoot:
    """
    A root data model which may have other data models mapped into it
    """

    @property
    def length(self) -> int:
        return len(self.data)

    def __init__(self, model: DataModel, data: bytes):
        self.model: DataModel = model
        self.data = data
        self._children: Dict[DataId, DataModel] = dict()

        # A pair of sorted 2D arrays, where each "point" in the grid is a set of children's data IDs
        # The (X, Y) coordinates of each grid correspond to the range of these children
        # The coordinates are flipped between these 2 grids:
        #   (x,y) in _grid_starts_first is (y,x) in _grid_ends_first
        #   The same set object is shared by both points
        # Sometimes it is more efficient to search in one grid or the other
        self._grid_starts_first: _GridXAxisT = []  # X axis is range starts, Y axis is ends
        self._grid_ends_first: _GridXAxisT = []  # X axis is range ends, Y axis is starts

    def get_children(self) -> Iterable[DataModel]:
        return self._children.values()

    def add_mapped_model(self, model: DataModel):
        if model.range.start < 0 or model.range.end > self.length:
            raise OutOfBoundError(
                f"New mapped data model {model.id.hex()} is outside the bounds of its root "
                f"{self.model.id.hex()}: ({model.range} is outside of {self.model.range})"
            )

        self._children[model.id] = model

        # if there is not already a set at the coords of model.range, a new set is created
        # _grid_starts_first and _grid_ends_first must share this set
        # So we create it outside, then pass it into _add_to_grid, in case it is needed
        default_set: Set[DataId] = set()
        set1 = self._add_to_grid(
            self._grid_starts_first, model.range.start, model.range.end, default_set
        )
        set2 = self._add_to_grid(
            self._grid_ends_first, model.range.end, model.range.start, default_set
        )

        assert set1 is set2  # These sets should always be the same!
        set1.add(model.id)

    def delete_mapped_model(self, model: DataModel):
        if model.id not in self._children:
            raise NotFoundError(
                f"Data model with ID {model.id.hex()} is not a child of {self.model.id.hex()}"
            )

        ids_at_point = self._get_ids_at(model.range.start, model.range.end)
        ids_at_point.remove(model.id)
        if len(ids_at_point) == 0:
            self._remove_from_grid(self._grid_starts_first, model.range.start, model.range.end)
            self._remove_from_grid(self._grid_ends_first, model.range.end, model.range.start)

        del self._children[model.id]

    def resize_range(self, resized_range: Range, size_diff: int):
        try:
            for shifted_child_id, (start_shift, end_shift) in self._resize_range(
                resized_range, size_diff
            ):
                shifted_child = self._children[shifted_child_id]
                shifted_child.range = Range(
                    shifted_child.range.start + start_shift,
                    shifted_child.range.end + end_shift,
                )

        except _ShiftBreaksSortError:
            raise PatchOverlapError(
                "Cannot resize child overlapping with the boundaries of other children!"
            )

        self.model.range = Range(0, self.model.range.end + size_diff)

    def get_children_with_boundaries_intersecting_range(self, r: Range) -> List[DataModel]:
        intersecting_model_ids: Set[DataId] = set()

        for starts_in_range in self._get_ids_in_range(
            start_range=(r.start, r.end), start_inclusivity=(False, False)
        ):
            intersecting_model_ids.add(starts_in_range)

        for ends_in_range in self._get_ids_in_range(
            end_range=(r.start, r.end), end_inclusivity=(False, False)
        ):
            intersecting_model_ids.add(ends_in_range)

        return [self._children[data_id] for data_id in intersecting_model_ids]

    def get_children_affected_by_ranges(
        self, patch_ranges: List[Range]
    ) -> Iterable[Tuple[DataId, Range]]:
        children_overlapping_ranges: Dict[Range, Iterable[DataId]] = defaultdict(set)
        for patch_range in patch_ranges:
            children_overlapping_ranges[patch_range] = self._get_ids_in_range(
                start_range=(None, patch_range.end),
                end_range=(patch_range.start, None),
                start_inclusivity=(False, False),
                end_inclusivity=(False, False),
            )

        for patched_range, overlapping_data_ids in children_overlapping_ranges.items():
            for data_id in overlapping_data_ids:
                model = self._children[data_id]
                yield data_id, patched_range.intersect(model.range).translate(-model.range.start)

    def _get_ids_at(self, start: int, end: int) -> Set[DataId]:
        i = _CompareFirstTuple.bisect_left(self._grid_starts_first, start)
        if i >= len(self._grid_starts_first):
            raise KeyError()
        fetched_start: int
        column: _GridYAxisT
        fetched_start, column = self._grid_starts_first[i]
        if fetched_start != start:
            raise KeyError()

        j = _CompareFirstTuple.bisect_left(column, end)
        if j >= len(column) or column[j][0] != end:
            raise KeyError()

        return column[j][1]

    def _get_ids_in_range(
        self,
        start_range: Tuple[Optional[int], Optional[int]] = (None, None),
        end_range: Tuple[Optional[int], Optional[int]] = (None, None),
        start_inclusivity: Tuple[bool, bool] = (True, False),
        end_inclusivity: Tuple[bool, bool] = (True, False),
    ) -> Iterable[DataId]:
        start_min, start_max = start_range
        end_min, end_max = end_range

        if start_range != (None, None):
            starts_iter = self._iter_grid_axis(
                self._grid_starts_first, start_min, start_max, start_inclusivity
            )
            for _, ends in starts_iter:
                ends_iter = self._iter_grid_axis(ends, end_min, end_max, end_inclusivity)
                for _, vals in ends_iter:
                    yield from vals
        elif end_range != (None, None):
            ends_iter = self._iter_grid_axis(
                self._grid_ends_first, end_min, end_max, end_inclusivity
            )
            for _, starts in ends_iter:
                starts_iter = self._iter_grid_axis(starts, start_min, start_max, start_inclusivity)
                for _, vals in starts_iter:
                    yield from vals
        else:
            for _, column in self._grid_starts_first:
                for _, vals in column:
                    yield from vals

    def _resize_range(
        self, resized_range: Range, size_diff: int
    ) -> Iterable[Tuple[DataId, Tuple[int, int]]]:
        # Update the _grid_ends_first
        for ids_ending_after_range in self._shift_grid_axis(
            self._grid_ends_first,
            size_diff,
            merge_func=self._merge_columns,
            minimum=resized_range.end,
            inclusive=(True, False) if resized_range.length() != 0 else (False, False),
        ):
            for _, ids_starting_before_range in self._iter_grid_axis(
                ids_ending_after_range,
                maximum=resized_range.end,
            ):
                for model_id in ids_starting_before_range:
                    # Only end shifted
                    yield model_id, (0, size_diff)
            for ids_entirely_after_range in self._shift_grid_axis(
                ids_ending_after_range,
                size_diff,
                merge_func=set.union,
                minimum=resized_range.end,
            ):
                for model_id in ids_entirely_after_range:
                    # Both start and end shifted
                    yield model_id, (size_diff, size_diff)

        # Update the _grid_starts_first
        for _, ids_starting_before_range in self._iter_grid_axis(
            self._grid_starts_first,
            maximum=resized_range.start,
            inclusive=(True, True) if resized_range.length() != 0 else (True, False),
        ):
            for _ in self._shift_grid_axis(
                ids_starting_before_range,
                size_diff,
                merge_func=set.union,
                minimum=resized_range.start,
                inclusive=(False, False),
            ):
                # Only end shifted
                pass

        for ends in self._shift_grid_axis(
            self._grid_starts_first,
            size_diff,
            merge_func=self._merge_columns,
            minimum=resized_range.end,
            inclusive=(True, False),
        ):
            for _ in self._shift_grid_axis(
                ends,
                size_diff,
                merge_func=set.union,
            ):
                # Both start and end shifted
                pass

    @staticmethod
    def _add_to_grid(
        grid: _GridXAxisT,
        x: int,
        y: int,
        default: Set[DataId],
    ) -> Set[DataId]:
        i = _CompareFirstTuple.bisect_left(grid, x)
        if i >= len(grid) or grid[i][0] != x:
            column: _GridYAxisT = []
            grid.insert(i, _CompareFirstTuple(x, column))
        else:
            column = grid[i][1]

        j = _CompareFirstTuple.bisect_left(column, y)
        if j >= len(column) or column[j][0] != y:
            column.insert(j, _CompareFirstTuple(y, default))

        return column[j][1]

    @staticmethod
    def _remove_from_grid(grid: _GridXAxisT, x: int, y: int):
        i = _CompareFirstTuple.bisect_left(grid, x)
        if i >= len(grid) or grid[i][0] != x:
            raise KeyError(f"No column {x} in the grid!")
        else:
            column = grid[i][1]

        j = _CompareFirstTuple.bisect_left(column, y)
        if j >= len(column) or column[j][0] != y:
            raise KeyError(f"No point {y} in column {x} in the grid!")

        column.pop(j)
        if len(column) == 0:
            grid.pop(i)

    @staticmethod
    def _iter_grid_axis(
        grid: List[T],
        minimum: Optional[int] = None,
        maximum: Optional[int] = None,
        inclusive: Tuple[bool, bool] = (True, False),
    ) -> Iterable[T]:
        if minimum is not None:
            if inclusive[0]:
                min_i = _CompareFirstTuple.bisect_left(grid, minimum)
            else:
                min_i = _CompareFirstTuple.bisect_right(grid, minimum)
        else:
            min_i = 0

        if maximum is not None:
            if inclusive[1]:
                max_i = _CompareFirstTuple.bisect_right(grid, maximum)
            else:
                max_i = _CompareFirstTuple.bisect_left(grid, maximum)
        else:
            max_i = len(grid)

        i = min_i
        while i < max_i:
            yield grid[i]
            i += 1

    @staticmethod
    def _shift_grid_axis(
        axis: List[_CompareFirstTuple[T]],
        shift: int,
        merge_func: Callable[[T, T], T],
        minimum: Optional[int] = None,
        maximum: Optional[int] = None,
        inclusive: Tuple[bool, bool] = (True, False),
    ) -> Iterable[T]:
        """
        Shift a range of values in an axis, without affecting the sorted order of the points in
        the axis. With two exceptions:
        - If the minimum shifted point is shifted DOWN exactly enough to be equal to the previous
          point (which has by definition not been shifted), those two points are allowed to merge
        - If the maximum shifted point is shifted UP exactly enough to be equal to the next
          point (which has by definition not been shifted), those two points are allowed to merge

        At most one of these can happen when shifting. The `merge_func` parameter handles merging
        those two points. Since we may be shifting either a row or a column, the merged "points" may
        be either columns (if shifting rows) or sets of bytes (if shifting columns).
        """
        pre_yield = None
        post_yield = None

        if minimum is not None:
            if inclusive[0]:
                min_i = _CompareFirstTuple.bisect_left(axis, minimum)
            else:
                min_i = _CompareFirstTuple.bisect_right(axis, minimum)
        else:
            min_i = 0

        if 0 < min_i < (len(axis) - 1):
            post_shift_min = axis[min_i][0] + shift
            if post_shift_min < axis[min_i - 1][0]:
                raise _ShiftBreaksSortError(
                    f"shifting {minimum} to {maximum} by {shift} would collide at the lower range!"
                )
            elif post_shift_min == axis[min_i - 1][0]:
                # will merge the lowest val in shifted range into previous
                val1 = axis[min_i - 1][1]
                _, pre_yield = axis.pop(min_i)

        if maximum is not None:
            if inclusive[1]:
                max_i = _CompareFirstTuple.bisect_left(axis, maximum)
            else:
                max_i = _CompareFirstTuple.bisect_right(axis, maximum)
        else:
            max_i = len(axis)

        if 0 < (max_i + 1) < len(axis):
            post_shift_max = axis[max_i][0] + shift
            if post_shift_max > axis[max_i + 1][0]:
                raise _ShiftBreaksSortError(
                    f"shifting {minimum} to {maximum} by {shift} would collide at the upper range!"
                )
            elif post_shift_max == axis[max_i + 1][0]:
                # will merge the highest val in shifted range into next
                val1 = axis[max_i + 1][1]
                _, post_yield = axis.pop(max_i)

                max_i -= 1

        if pre_yield is not None:
            yield pre_yield
            axis[min_i - 1] = _CompareFirstTuple(post_shift_min, merge_func(val1, pre_yield))

        i = min_i
        while i < max_i:
            old_key, val = axis[i]
            axis[i] = _CompareFirstTuple(old_key + shift, val)
            yield val
            i += 1

        if post_yield is not None:
            yield post_yield
            axis[max_i + 2] = _CompareFirstTuple(post_shift_max, merge_func(val1, post_yield))

    @staticmethod
    def _merge_columns(
        col1: _GridYAxisT,
        col2: _GridYAxisT,
    ) -> _GridYAxisT:
        merged_columns: _GridYAxisT = []
        for key, _vals in itertools.groupby(heapq.merge(col1, col2), key=lambda x: x[0]):
            vals = tuple(v for _, v in _vals)
            if len(vals) == 1:
                val: Set[DataId] = vals[0]
            else:
                val = set.union(*vals)

            merged_columns.append(_CompareFirstTuple(key, val))

        return merged_columns


class _PatchResizeTracker:
    def __init__(self):
        # Map ORIGINAL offsets in
        self.resizing_shifts: SortedList[List[int]] = SortedList(key=lambda x: x[0])
        self.resized_ranges = []
        self.resizing_shifts.add([0, 0])

    def overlaps_resized_range(self, r: Range) -> bool:
        return any(
            resized_range.overlaps(r) or resized_range.start == r.start
            for resized_range in self.resized_ranges
        )

    def translate_range(self, r: Range) -> Range:
        return Range(
            self.get_shifted_point(r.start),
            self.get_shifted_point(r.end),
        )

    def get_shifted_point(self, point: int) -> int:
        i = self.resizing_shifts.bisect_right((point, 0))
        assert i != 0
        previous_shift_end, shift = self.resizing_shifts[i - 1]
        return point + shift

    def add_new_resized_range(self, r: Range, size_diff: int):
        self.resized_ranges.append(r)
        i = self.resizing_shifts.bisect_right((r.end, 0))
        total_offset_here = self.resizing_shifts[i - 1][1] + size_diff
        for node in self.resizing_shifts.islice(i):
            node[1] += size_diff
        self.resizing_shifts.add([r.end, total_offset_here])

    def get_total_size_diff(self) -> int:
        return self.resizing_shifts[-1][1]
