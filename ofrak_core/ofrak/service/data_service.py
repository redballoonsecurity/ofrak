from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union, cast

from dataclasses import dataclass
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


# Helper classes
@dataclass
class _Waypoint:
    offset: int
    models_starting: Set[DataId]
    models_ending: Set[DataId]

    def is_empty(self) -> bool:
        return not self.models_starting and not self.models_ending


class _DataRoot:
    """
    A root data model which may have other data models mapped into it
    """

    def __init__(self, model: DataModel, data: bytes):
        self.model: DataModel = model
        self.data = data
        self._waypoints: Dict[int, _Waypoint] = dict()
        self._waypoint_offsets: SortedList[int] = SortedList()
        self._children: Dict[DataId, DataModel] = dict()

    def waypoints(self) -> Iterable[_Waypoint]:
        for waypoint_offset in self._waypoint_offsets:
            yield self._waypoints[waypoint_offset]

    def get_children(self) -> Iterable[DataModel]:
        return self._children.values()

    def add_mapped_model(self, model: DataModel):
        if model.range.start < 0 or model.range.end > self.length:
            raise OutOfBoundError(
                f"New mapped data model {model.id.hex()} is outside the bounds of its root "
                f"{self.model.id.hex()}: ({model.range} is outside of {self.model.range})"
            )

        start_offset = model.range.start
        start_waypoint = self._waypoints.get(start_offset)
        if start_waypoint is None:
            start_waypoint = _Waypoint(start_offset, set(), set())
            self._waypoints[start_offset] = start_waypoint
            self._waypoint_offsets.add(start_offset)
        start_waypoint.models_starting.add(model.id)

        ending_offset = model.range.end
        ending_waypoint = self._waypoints.get(ending_offset)
        if ending_waypoint is None:
            ending_waypoint = _Waypoint(ending_offset, set(), set())
            self._waypoints[ending_offset] = ending_waypoint
            self._waypoint_offsets.add(ending_offset)
        ending_waypoint.models_ending.add(model.id)

        self._children[model.id] = model

    def delete_mapped_model(self, model: DataModel):
        start_offset = model.range.start
        start_waypoint = self._waypoints.get(start_offset)
        ending_offset = model.range.end
        ending_waypoint = self._waypoints.get(ending_offset)

        if model.id not in self._children or start_waypoint is None or ending_waypoint is None:
            raise NotFoundError(
                f"Cannot delete mapped data model {model.id.hex()} from root {self.model.id.hex()}"
                f"because it is not part of that root!"
            )

        start_waypoint.models_starting.remove(model.id)
        ending_waypoint.models_ending.remove(model.id)

        if start_waypoint.is_empty():
            self._waypoint_offsets.remove(start_waypoint.offset)
            del self._waypoints[start_waypoint.offset]
        if ending_waypoint.is_empty():
            self._waypoint_offsets.remove(ending_waypoint.offset)
            del self._waypoints[ending_waypoint.offset]
        del self._children[model.id]

    def resize_range(self, resized_range: Range, size_diff: int):

        waypoints_to_shift = list(
            self._waypoint_offsets.irange(minimum=resized_range.end, inclusive=(True, True))
        )
        new_waypoints = dict()
        ends_already_shifted = set()
        for waypoint_offset in waypoints_to_shift:
            new_waypoint_offset = waypoint_offset + size_diff
            self._waypoint_offsets.remove(waypoint_offset)
            self._waypoint_offsets.add(new_waypoint_offset)

            waypoint = self._waypoints[waypoint_offset]
            del self._waypoints[waypoint_offset]

            for model_id in waypoint.models_starting:
                model = self._children[model_id]
                model.range = model.range.translate(size_diff)
                ends_already_shifted.add(model_id)

            for model_id in waypoint.models_ending.difference(ends_already_shifted):
                model = self._children[model_id]
                model.range = Range(model.range.start, model.range.end + size_diff)

            waypoint.offset = new_waypoint_offset
            new_waypoints[new_waypoint_offset] = waypoint

        for new_waypoint_offset, new_waypoint in new_waypoints.items():
            if new_waypoint_offset in self._waypoints:
                waypoint = self._waypoints[new_waypoint_offset]
                waypoint.models_starting.update(new_waypoint.models_starting)
                waypoint.models_ending.update(new_waypoint.models_ending)
            else:
                self._waypoints[new_waypoint_offset] = new_waypoint

        self.model.range = Range(0, self.model.range.end + size_diff)

    def get_children_with_boundaries_intersecting_range(self, r: Range) -> List[DataModel]:
        intersecting_model_ids = set()
        for waypoint_offset in self._waypoint_offsets.irange(
            r.start, r.end, inclusive=(False, False)
        ):
            waypoint = self._waypoints[waypoint_offset]
            if waypoint_offset != r.start:
                intersecting_model_ids.update(waypoint.models_ending)
            if waypoint_offset != r.end:
                intersecting_model_ids.update(waypoint.models_starting)

        return [self._children[data_id] for data_id in intersecting_model_ids]

    def get_children_affected_by_ranges(
        self, patch_ranges: List[Range]
    ) -> Iterable[Tuple[DataId, Range]]:
        # Build a flat map of various types of points of interest, to be scanned in order of offset
        points_of_interest: List[Tuple[int, int, Union[Range, Set[DataId]]]] = []

        # int values represent the order that different types of points should be processed in
        # (if they all had the same offset)
        POINT_CHILDREN_ENDS = -2  # End of one or more children
        POINT_RANGE_END = -1  # End of a patched range
        POINT_ZERO_LENGTH_RANGE = 0  # Special case of patched range: it
        POINT_RANGE_START = 1  # Start of a patched range
        POINT_CHILDREN_STARTS = 2  # Start of one or more children

        for r in patch_ranges:
            if r.length() == 0:
                points_of_interest.append((r.start, POINT_ZERO_LENGTH_RANGE, r))
            else:
                points_of_interest.append((r.start, POINT_RANGE_START, r))
                points_of_interest.append((r.end, POINT_RANGE_END, r))

        for waypoint in self.waypoints():
            # Make sure no 0-length children (start and end at same waypoint) are counted
            # These are never affected by a patch, UNLESS the patch is specifically to them
            # That case is handled outside this function
            # (the data ID the patch is "for" is always affected, so no need to check for it here)
            points_of_interest.append(
                (
                    waypoint.offset,
                    POINT_CHILDREN_ENDS,
                    waypoint.models_ending.difference(waypoint.models_starting),
                )
            )
            points_of_interest.append(
                (
                    waypoint.offset,
                    POINT_CHILDREN_STARTS,
                    waypoint.models_starting.difference(waypoint.models_ending),
                )
            )

        # the points representing data model and patch start/ends will be sorted by data offset
        # Ties (points w/ same offset) will be broken by the point type, enumerated above
        points_of_interest.sort()

        # Scan through the points of interest, tracking the current data models as we enter/leave
        # each one, as well as the current patch range.
        curr_overlapping_children: Set[DataId] = set()
        curr_range: Optional[Range] = None
        children_overlapping_ranges: Dict[Range, Set[DataId]] = defaultdict(set)
        for _, point_type, point in points_of_interest:
            # These cases are written out in the same order they would be executed for points with
            # the same offset.
            if point_type is POINT_CHILDREN_ENDS:
                children_ending: Set[bytes] = cast(Set[bytes], point)
                curr_overlapping_children.difference_update(children_ending)
            elif point_type is POINT_RANGE_END:
                curr_range = None
            elif point_type is POINT_ZERO_LENGTH_RANGE:
                zero_length_range = cast(Range, point)
                children_overlapping_ranges[zero_length_range].update(curr_overlapping_children)
            elif point_type is POINT_RANGE_START:
                curr_range = cast(Range, point)
            elif point_type is POINT_CHILDREN_STARTS:
                children_starting: Set[bytes] = cast(Set[bytes], point)
                curr_overlapping_children.update(children_starting)

            # At each point, if the point is in one of the patch ranges, associate any data models
            # overlapping with that point with the patch range.
            if curr_range:
                children_overlapping_ranges[curr_range].update(curr_overlapping_children)

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
