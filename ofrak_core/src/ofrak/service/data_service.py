import itertools
from collections import defaultdict
from typing import (
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Pattern,
    cast,
)

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
            return bytes(root.data[translated_range.start : translated_range.end])
        else:
            return bytes(root.data[model.range.start : model.range.end])

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

    async def search(self, data_id, query, start=None, end=None, max_matches=None):
        model = self._get_by_id(data_id)
        root = self._get_root_by_id(model.root_id)
        start = model.range.start if start is None else model.range.start + start
        end = model.range.end if end is None else min(model.range.end, model.range.start + end)
        if isinstance(query, bytes):
            matches = []
            while max_matches is None or len(matches) < max_matches:
                match_offset = root.data.find(query, start, end)
                if match_offset < 0:
                    break

                matches.append(match_offset - model.range.start)
                start = match_offset + 1

            return tuple(matches)
        else:
            query = cast(Pattern, query)
            match_iterator = query.finditer(root.data, start, end)

            if max_matches is not None:
                match_iterator = itertools.islice(match_iterator, max_matches)
            matches = (
                (match.start() - model.range.start, match.group(0)) for match in match_iterator
            )
            return tuple(matches)

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

        # Apply finalized patches to data and data models
        for patch_range, data, size_diff in finalized_ordered_patches:
            root.data[patch_range.start : patch_range.end] = data
            if size_diff != 0:
                root.resize_range(patch_range, size_diff)

        return [
            DataPatchesResult(data_id, results_for_id)
            for data_id, results_for_id in results.items()
        ]


class _MaxEndSegmentTree:
    """Segment tree for O(log n) range-maximum queries over end values."""

    __slots__ = ("_n", "_tree")

    def __init__(self, ends: List[int]):
        n = len(ends)
        self._n = n
        if n == 0:
            self._tree = []
            return
        self._tree = [0] * (2 * n)
        for i in range(n):
            self._tree[n + i] = ends[i]
        for i in range(n - 1, 0, -1):
            self._tree[i] = (
                self._tree[2 * i]
                if self._tree[2 * i] > self._tree[2 * i + 1]
                else self._tree[2 * i + 1]
            )

    def range_max(self, lo: int, hi: int) -> int:
        """Maximum value in [lo, hi). Returns -1 if empty."""
        if lo >= hi:
            return -1
        result = -1
        lo += self._n
        hi += self._n
        while lo < hi:
            if lo & 1:
                if self._tree[lo] > result:
                    result = self._tree[lo]
                lo += 1
            if hi & 1:
                hi -= 1
                if self._tree[hi] > result:
                    result = self._tree[hi]
            lo >>= 1
            hi >>= 1
        return result


class _DataRoot:
    """
    A root data model which may have other data models mapped into it.

    Uses SortedKeyLists for O(log n) boundary queries and a lazily-built
    segment tree for O(log n + k) interval overlap queries.
    """

    @property
    def length(self) -> int:
        return len(self.data)

    def __init__(self, model: DataModel, data: bytes):
        self.model: DataModel = model
        self.data = bytearray(data)
        self._children: Dict[DataId, DataModel] = dict()

        # SortedKeyList: key extracts the first element (start or end) for range queries
        self._by_start: SortedList = SortedList(key=lambda t: t[0])
        self._by_end: SortedList = SortedList(key=lambda t: t[0])

        # Lazily-built overlap query index: a snapshot of _by_start as a plain list
        # plus a segment tree over end values for O(log n + k) pruning.
        # Invalidated on any mutation; rebuilt on first overlap query.
        self._overlap_entries: Optional[List[Tuple[int, int, DataId]]] = None
        self._overlap_seg_tree: Optional[_MaxEndSegmentTree] = None

    def _invalidate_overlap_index(self):
        self._overlap_entries = None
        self._overlap_seg_tree = None

    def _ensure_overlap_index(self):
        if self._overlap_entries is None:
            entries = list(self._by_start)
            self._overlap_entries = entries
            self._overlap_seg_tree = _MaxEndSegmentTree([e[1] for e in entries])

    def get_children(self) -> Iterable[DataModel]:
        return self._children.values()

    def add_mapped_model(self, model: DataModel):
        if model.range.start < 0 or model.range.end > self.length:
            raise OutOfBoundError(
                f"New mapped data model {model.id.hex()} is outside the bounds of its root "
                f"{self.model.id.hex()}: ({model.range} is outside of {self.model.range})"
            )

        self._children[model.id] = model
        self._by_start.add((model.range.start, model.range.end, model.id))
        self._by_end.add((model.range.end, model.range.start, model.id))
        self._invalidate_overlap_index()

    def delete_mapped_model(self, model: DataModel):
        if model.id not in self._children:
            raise NotFoundError(
                f"Data model with ID {model.id.hex()} is not a child of {self.model.id.hex()}"
            )

        self._by_start.remove((model.range.start, model.range.end, model.id))
        self._by_end.remove((model.range.end, model.range.start, model.id))
        del self._children[model.id]
        self._invalidate_overlap_index()

    def resize_range(self, resized_range: Range, size_diff: int):
        """
        After a resizing patch at `resized_range`, shift all children whose ranges
        are affected. Children that span the resize point get their end shifted;
        children entirely after the resize point get both start and end shifted.

        In practice, this is only called when the root has zero or very few children
        (the framework deletes children before applying resizing patches).
        """
        children_to_update = []

        for model in self._children.values():
            if model.range.start >= resized_range.end:
                # Entirely after resize point: shift both
                children_to_update.append((model, size_diff, size_diff))
            elif model.range.end > resized_range.end or (
                model.range.end == resized_range.end and resized_range.length() != 0
            ):
                # Spans the resize point: only shift end
                children_to_update.append((model, 0, size_diff))

        # Remove old entries, update ranges, re-add
        for model, start_shift, end_shift in children_to_update:
            self._by_start.remove((model.range.start, model.range.end, model.id))
            self._by_end.remove((model.range.end, model.range.start, model.id))

            model.range = Range(
                model.range.start + start_shift,
                model.range.end + end_shift,
            )

            self._by_start.add((model.range.start, model.range.end, model.id))
            self._by_end.add((model.range.end, model.range.start, model.id))

        self._invalidate_overlap_index()
        self.model.range = Range(0, self.model.range.end + size_diff)

    def get_children_with_boundaries_intersecting_range(self, r: Range) -> List[DataModel]:
        """
        Find children whose start or end falls strictly inside range (r.start, r.end) (exclusive).
        Uses irange_key for integer-based comparisons on the sort key.
        """
        intersecting_ids: Set[DataId] = set()

        # Children whose START is strictly inside (r.start, r.end)
        for start, end, data_id in self._by_start.irange_key(r.start, r.end, (False, False)):
            intersecting_ids.add(data_id)

        # Children whose END is strictly inside (r.start, r.end)
        for end, start, data_id in self._by_end.irange_key(r.start, r.end, (False, False)):
            intersecting_ids.add(data_id)

        return [self._children[data_id] for data_id in intersecting_ids]

    def get_children_affected_by_ranges(
        self, patch_ranges: List[Range]
    ) -> Iterable[Tuple[DataId, Range]]:
        """
        For each patch range, find all children that overlap it.
        An interval [s, e) overlaps [q_start, q_end) iff s < q_end AND e > q_start.

        Uses a segment tree over end values for O(log n + k) pruning:
        recursively scan entries sorted by start, pruning subtrees where
        max(end) <= q_start.
        """
        self._ensure_overlap_index()
        entries = self._overlap_entries
        seg_tree = self._overlap_seg_tree
        assert entries is not None
        assert seg_tree is not None

        for patch_range in patch_ranges:
            q_start = patch_range.start
            q_end = patch_range.end
            # Binary search: find how many entries have start < q_end
            # Use bisect on the entries list (sorted by start = entry[0])
            cutoff = self._by_start.bisect_key_left(q_end)

            # Recursively scan [0, cutoff) with segment tree pruning
            stack = [(0, cutoff)]
            while stack:
                lo, hi = stack.pop()
                if lo >= hi:
                    continue
                if seg_tree.range_max(lo, hi) <= q_start:
                    continue  # No entry in [lo, hi) has end > q_start
                mid = (lo + hi) >> 1
                # Push right first so left is processed first (DFS order)
                stack.append((mid + 1, hi))
                start, end, data_id = entries[mid]
                if end > q_start:
                    model = self._children[data_id]
                    yield (
                        data_id,
                        patch_range.intersect(model.range).translate(-model.range.start),
                    )
                stack.append((lo, mid))


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
