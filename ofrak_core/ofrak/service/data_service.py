from bisect import bisect_left, bisect_right
from collections import defaultdict
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple, TypeVar

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


class _RootChildBoundsDict(Iterable[T]):
    """
    Data structure very similar to SortedDict:
    https://grantjenks.com/docs/sortedcontainers/sorteddict.html

    It always has ints as keys, and only the methods necessary for the data service are implemented.

    The major, crucial difference is that a range of keys can be efficiently shifted with
    `shift_key_range` in O(n) time. This is necessary when resizing ranges, as any sorted way of
    storing a root's children must be able to update those keys. SortedDict provides no mechanism
    to do that, other than removing and re-adding the affected key-value pairs.
    """

    class ShiftBreaksSortError(RuntimeError):
        pass

    def __init__(self, value_constructor: Callable[..., T], value_combiner: Callable[[T, T], T]):
        self._keys: List[int] = []
        self._values: List[T] = []
        self._value_constructor = value_constructor
        self._value_combiner = value_combiner

    def __len__(self):
        return len(self._keys)

    def __getitem__(self, key: int) -> T:
        key_i = bisect_left(self._keys, key)
        if key_i >= len(self._keys) or self._keys[key_i] != key:
            self._keys.insert(key_i, key)
            self._values.insert(key_i, self._value_constructor())
        return self._values[key_i]

    def __setitem__(self, key: int, value: T):
        key_i = bisect_left(self._keys, key)
        if key_i >= len(self._keys) or self._keys[key_i] != key:
            self._keys.insert(key_i, key)
            self._values.insert(key_i, value)
        else:
            self._values[key_i] = value

    def __delitem__(self, key: int):
        key_i = bisect_left(self._keys, key)
        if self._keys[key_i] == key:
            self._keys.pop(key_i)
            self._values.pop(key_i)
        else:
            raise KeyError()

    def __add__(self, other: "_RootChildBoundsDict[T]"):
        i_1_iter = iter(range(len(self._keys)))
        i_2_iter = iter(range(len(other._keys)))

        merged_keys: List[int] = []
        merged_values: List[T] = []

        # Need all the remaining vals from other iterator when we reach the end of either iterator
        # So, before each `next()` call on an iterator, set `remainder` to point to other iterator
        remainder: Tuple[Iterator[int], _RootChildBoundsDict[T]] = (None, None)  # type: ignore

        i_1 = 0
        i_2 = 0

        def increment(incr_i_1: bool, incr_i_2: bool):
            nonlocal remainder
            nonlocal i_1
            nonlocal i_2

            if incr_i_1:
                remainder = i_2_iter, other
                i_1 = next(i_1_iter)
            if incr_i_2:
                remainder = i_1_iter, self
                i_2 = next(i_2_iter)

        try:
            increment(True, True)

            while True:
                k_1 = self._keys[i_1]
                k_2 = other._keys[i_2]
                if k_1 == k_2:
                    merged_keys.append(k_1)
                    merged_values.append(
                        self._value_combiner(self._values[i_1], other._values[i_2])
                    )
                    increment(True, True)
                elif k_1 < k_2:
                    merged_keys.append(k_1)
                    merged_values.append(self._values[i_1])
                    increment(True, False)
                else:  # k_1 > k_2
                    merged_keys.append(k_2)
                    merged_values.append(other._values[i_2])
                    increment(False, True)

        except StopIteration:
            remainder_key_iter, remainder_dict = remainder
            for remaining_i in remainder_key_iter:
                remaining_key = remainder_dict._keys[remaining_i]
                remaining_value = remainder_dict._values[remaining_i]
                merged_keys.append(remaining_key)
                merged_values.append(remaining_value)

            merged_dict = _RootChildBoundsDict.__new__(_RootChildBoundsDict)
            merged_dict._keys = merged_keys
            merged_dict._values = merged_values
            merged_dict._value_constructor = self._value_constructor
            merged_dict._value_combiner = self._value_combiner

            return merged_dict

    def __iter__(self) -> Iterator[T]:
        return iter(self._values)

    def irange(
        self,
        minimum: Optional[int] = None,
        maximum: Optional[int] = None,
        inclusive: Tuple[bool, bool] = (True, False),
    ) -> Iterable[T]:
        if minimum is not None:
            if inclusive[0]:
                min_i = bisect_left(self._keys, minimum)
            else:
                min_i = bisect_right(self._keys, minimum)
        else:
            min_i = 0

        if maximum is not None:
            if inclusive[1]:
                max_i = bisect_right(self._keys, maximum)
            else:
                max_i = bisect_left(self._keys, maximum)
        else:
            max_i = len(self._keys)

        value_i = min_i
        while value_i < max_i:
            yield self._values[value_i]
            value_i += 1

    def shift_key_range(
        self,
        shift: int,
        minimum: Optional[int] = None,
        maximum: Optional[int] = None,
    ) -> Iterable[T]:
        """
        Shift a number of keys by a certain amount, so that the same ordering of key/value pairs
        is maintained but some keys are altered. If any original key + `shift` already
        exists as another key, the values of each are merged with `value_combiner` such that the
        now-duplicated key maps to the merged values.

        Examples, using the initial pairs: (3, X), (5, Y), (7, Z)

        - shift_key_range(shift=3, minimum=5)
            resuls in pairs: (3, X), (8, Y), (10, Z)
            returns: Y, Z
        - shift_key_range(shift=-2, minimum=5)
            results in pairs: (3, value_combiner(X, Y)), (5, Z)
            returns: Y, Z
        -shift_key_range(shift=-2, minimum=5)
            raises ShiftBreaksSortError

        :returns: An iterator over the values associated with the shifted keys

        :raises ShiftBreaksSortError: If shifting the given keys by `shift` would break their
        ordering relative to unshifted keys
        """
        if minimum is not None:
            min_i = bisect_left(self._keys, minimum)
        else:
            min_i = 0

        if maximum is not None:
            max_i = bisect_right(self._keys, maximum)
        else:
            max_i = len(self._keys)

        key_i = min_i
        while key_i < max_i:
            new_key = self._keys[key_i] + shift
            if key_i > 0:
                if self._keys[key_i - 1] == new_key:
                    self._values[key_i - 1] = self._value_combiner(
                        self._values[key_i - 1], self._values[key_i]
                    )
                    self._keys.pop(key_i)
                    # Yield specifically the values whose keys were shifted
                    yield self._values.pop(key_i)
                    max_i -= 1
                    continue
                elif self._keys[key_i - 1] > new_key:
                    raise self.ShiftBreaksSortError(
                        f"shifting {minimum} to {maximum} by {shift} would collide at the lower range!"
                    )

            if max_i <= key_i + 1 < len(self._keys):
                if self._keys[key_i + 1] == new_key:
                    self._values[key_i + 1] = self._value_combiner(
                        self._values[key_i + 1], self._values[key_i]
                    )
                    self._keys.pop(key_i)
                    # Yield specifically the values whose keys were shifted
                    yield self._values.pop(key_i)
                    max_i -= 1
                    continue
                elif self._keys[key_i + 1] < new_key:
                    raise self.ShiftBreaksSortError(
                        f"shifting {minimum} to {maximum} by {shift} would collide at the upper range!"
                    )

            self._keys[key_i] = new_key
            yield self._values[key_i]
            key_i += 1


class _DataRoot:
    """
    A root data model which may have other data models mapped into it
    """

    ChildGridT = _RootChildBoundsDict[_RootChildBoundsDict[Set[bytes]]]

    @staticmethod
    def create_grid() -> ChildGridT:
        return _RootChildBoundsDict(
            lambda: _RootChildBoundsDict(set, lambda x, y: x.union(y)), lambda x, y: x + y
        )

    def __init__(self, model: DataModel, data: bytes):
        self.model: DataModel = model
        self.data = data
        self._children: Dict[DataId, DataModel] = dict()

        self._child_grid: _DataRoot.ChildGridT = self.create_grid()
        self._inverse_grid: _DataRoot.ChildGridT = self.create_grid()

    def get_children(self) -> Iterable[DataModel]:
        return self._children.values()

    def add_mapped_model(self, model: DataModel):
        if model.range.start < 0 or model.range.end > self.length:
            raise OutOfBoundError(
                f"New mapped data model {model.id.hex()} is outside the bounds of its root "
                f"{self.model.id.hex()}: ({model.range} is outside of {self.model.range})"
            )

        self._child_grid[model.range.start][model.range.end].add(model.id)
        self._inverse_grid[model.range.end][model.range.start].add(model.id)

        self._children[model.id] = model

    def delete_mapped_model(self, model: DataModel):
        if model.id not in self._children:
            raise NotFoundError(
                f"Data model with ID {model.id.hex()} is not a child of {self.model.id.hex()}"
            )

        self._child_grid[model.range.start][model.range.end].remove(model.id)
        self._inverse_grid[model.range.end][model.range.start].remove(model.id)

        if 0 == len(self._child_grid[model.range.start][model.range.end]):
            del self._child_grid[model.range.start][model.range.end]
        if 0 == len(self._child_grid[model.range.start]):
            del self._child_grid[model.range.start]

        if 0 == len(self._inverse_grid[model.range.end][model.range.start]):
            del self._inverse_grid[model.range.end][model.range.start]
        if 0 == len(self._inverse_grid[model.range.end]):
            del self._inverse_grid[model.range.end]

        del self._children[model.id]

    def resize_range(self, resized_range: Range, size_diff: int):
        try:
            for ids_ending_after_range in self._inverse_grid.shift_key_range(
                size_diff, minimum=resized_range.end
            ):
                for ids_starting_before_range in ids_ending_after_range.irange(
                    maximum=resized_range.end, inclusive=(True, False)
                ):
                    for model_id in ids_starting_before_range:
                        model = self._children[model_id]
                        model.range = Range(model.range.start, model.range.end + size_diff)
                for ids_entirely_after_range in ids_ending_after_range.shift_key_range(
                    size_diff, minimum=resized_range.end
                ):
                    for model_id in ids_entirely_after_range:
                        model = self._children[model_id]
                        model.range = model.range.translate(size_diff)

            for ends in self._child_grid.shift_key_range(size_diff, minimum=resized_range.end):
                ends.shift_key_range(size_diff)

        except _RootChildBoundsDict.ShiftBreaksSortError as e:
            raise PatchOverlapError(
                "Cannot resize child overlapping with the boundaries of other children!"
            )

        self.model.range = Range(0, self.model.range.end + size_diff)

    def get_children_with_boundaries_intersecting_range(self, r: Range) -> List[DataModel]:
        intersecting_model_ids: Set[bytes] = set()
        for starts_in_range in self._child_grid.irange(r.start, r.end, inclusive=(False, False)):
            intersecting_model_ids.update(model_id for ends in starts_in_range for model_id in ends)

        for ends_in_range in self._inverse_grid.irange(r.start, r.end, inclusive=(False, False)):
            intersecting_model_ids.update(
                model_id for starts in ends_in_range for model_id in starts
            )

        return [self._children[data_id] for data_id in intersecting_model_ids]

    def get_children_affected_by_ranges(
        self, patch_ranges: List[Range]
    ) -> Iterable[Tuple[DataId, Range]]:
        children_overlapping_ranges: Dict[Range, Set[DataId]] = defaultdict(set)
        for patch_range in patch_ranges:
            for starting_before_patch_end in self._child_grid.irange(
                minimum=None, maximum=patch_range.end
            ):
                for ending_after_patch_start in starting_before_patch_end.irange(
                    minimum=patch_range.start, maximum=None
                ):
                    children_overlapping_ranges[patch_range].update(ending_after_patch_start)

        for patched_range, overlapping_data_ids in children_overlapping_ranges.items():
            for data_id in overlapping_data_ids:
                model = self._children[data_id]
                yield data_id, patched_range.intersect(model.range).translate(-model.range.start)

    @property
    def length(self) -> int:
        return len(self.data)


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
