from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Set, Tuple

from dataclasses import dataclass
from sortedcontainers import SortedList

from ofrak.model.data_model import (
    DataModel,
    DataPatch,
    DataPatchesResult,
    DataPatchResult,
)
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

        new_model = DataModel(data_id, Range(0, len(data)), None)

        self._model_store[data_id] = new_model
        self._roots[data_id] = _DataRoot(new_model, data)

        return new_model

    async def create_mapped(
        self,
        data_id: DataId,
        parent_id: DataId,
        mapped_range: Range,
    ) -> DataModel:
        if data_id in self._model_store:
            raise AlreadyExistError(f"A model with {data_id.hex()} already exists!")

        parent_model = self._get_by_id(parent_id)
        mapped_range = mapped_range.translate(parent_model.range.start)
        if mapped_range.end > parent_model.range.end:
            raise OutOfBoundError(
                f"Cannot map a new node into range {mapped_range} into {parent_model.range} of "
                f"{parent_id.hex()}"
            )

        if parent_model.is_mapped():
            root_id = parent_model.root_id
        else:
            root_id = parent_model.id
        new_model = DataModel(data_id, mapped_range, root_id)
        self._roots[root_id].add_mapped_model(new_model)
        self._model_store[data_id] = new_model

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
                f"{data_id.hex()} is a root, not mapped into {within_data_id} (a root)!"
            )
        elif self._is_root(within_data_id) and model.root_id != within_model.id:
            raise ValueError(f"{data_id.hex()} is not mapped into {within_data_id} (a root)!")
        elif not self._is_root(within_data_id) and model.root_id != within_model.root_id:
            raise ValueError(
                f"{data_id.hex()} and {within_data_id} are not mapped into the same root!"
            )
        else:
            return within_model.range.intersect(model.range)

    async def get_data(self, data_id: DataId, data_range: Optional[Range] = None) -> bytes:
        model = self._get_by_id(data_id)
        if model.is_mapped():
            root = self._get_root_by_id(model.root_id)
        else:
            root = self._roots[data_id]
        if data_range is not None:
            translated_range = data_range.translate(model.range.start).intersect(root.model.range)
            return root.data[translated_range.start : translated_range.end]
        else:
            return root.data[model.range.start : model.range.end]

    async def apply_patches(self, patches: List[DataPatch]) -> List[DataPatchesResult]:
        patches_by_root: Dict[DataId, List[DataPatch]] = defaultdict(list)
        for patch in patches:
            target_data_model = self._get_by_id(patch.data_id)
            if target_data_model.is_mapped():
                patches_by_root[target_data_model.root_id].append(patch)
            else:
                patches_by_root[target_data_model.id].append(patch)

        results = []
        for root_id, patches_for_root in patches_by_root.items():
            results.extend(self._apply_patches_to_root(root_id, patches_for_root))

        return results

    async def delete_models(self, data_ids: Iterable[DataId]) -> None:
        roots_to_delete = dict()
        mapped_to_delete = dict()

        for data_id in data_ids:
            model = self._get_by_id(data_id)
            if model.root_id is None:
                roots_to_delete[model.id] = model
            else:
                mapped_to_delete[model.id] = model

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

    def _get_absolute_range(self, model: DataModel, r: Range) -> Range:
        if r.start < 0 or r.end > model.range.end:
            raise OutOfBoundError(
                f"The requested range {r} of model {model.id.hex()} is outside the "
                f"model's range {model.range}"
            )

        if model.root_id is None:
            return r
        else:
            root = self._get_root_by_id(model.root_id)
            absolute_range = r.translate(model.range.start)
            if absolute_range.end > root.model.range.end:
                raise OutOfBoundError(
                    f"The requested range {r} of model {model.id.hex()} is outside the "
                    f"root's range {root.model.range}"
                )
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
            raw_absolute_patch_range = self._get_absolute_range(target_model, patch.range)

            if resize_tracker.overlaps_resized_range(raw_absolute_patch_range):
                raise PatchOverlapError(
                    f"Patch to {patch.range} of {patch.data_id.hex()} overlaps previously resized "
                    f"area of {patch.data_id.hex()} and cannot be applied!"
                )

            raw_patch_ranges_in_root.append(raw_absolute_patch_range)
            absolute_patch_range = resize_tracker.translate_range(raw_absolute_patch_range)
            models_intersecting_patch_range = root.get_children_with_boundaries_intersecting_range(
                absolute_patch_range
            )

            size_diff = len(patch.data) - patch.range.length()
            if size_diff == 0:
                finalized_ordered_patches.append((absolute_patch_range, patch.data, size_diff))
            elif models_intersecting_patch_range:
                raise PatchOverlapError(
                    f"Because patch to {patch.data_id.hex()} resizes data by {size_diff} bytes, "
                    f"the effects on {len(models_intersecting_patch_range)} model(s) "
                    f"intersecting the patch range {patch.range} ({absolute_patch_range} in the "
                    f"root) could not be determined. If data must be resized, any resources "
                    f"overlapping the data must be deleted before patching and re-created "
                    f"afterwards along new data ranges."
                )
            else:
                finalized_ordered_patches.append((absolute_patch_range, patch.data, size_diff))
                resize_tracker.add_new_resized_range(absolute_patch_range, size_diff)

        results = defaultdict(list)
        for affected_range in Range.merge_ranges(raw_patch_ranges_in_root):
            for affected_model in root.get_children_intersecting_range(affected_range):
                results[affected_model.id].append(
                    DataPatchResult(
                        affected_range.intersect(affected_model.range).translate(
                            -affected_model.range.start
                        )
                    )
                )
            results[root_data_id].append(DataPatchResult(affected_range))

        # Apply finalized patches to data and data models
        for patch_range, data, size_diff in finalized_ordered_patches:
            root.data = root.data[: patch_range.start] + data + root.data[patch_range.end :]
            if size_diff > 0:
                for child_model in root.get_children():
                    if child_model.range.end <= patch_range.start:
                        continue
                    elif child_model.range.start >= patch_range.end:
                        child_model.range = child_model.range.translate(size_diff)
                    else:
                        child_model.range = Range(
                            child_model.range.start, child_model.range.end + size_diff
                        )

        root.model.range = Range(
            root.model.range.start, root.model.range.end + resize_tracker.get_total_size_diff()
        )

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

    #
    # def validate(self):
    #     assert self.models_ending.isdisjoint(self.models_starting)


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

    def get_children_intersecting_range(self, r: Range) -> List[DataModel]:
        intersecting_children = self.get_children_with_boundaries_intersecting_range(r)

        # intersecting_children doesn't yet include models fully encompassing this range
        # now look for models which start before the range, but don't end before or within the range
        # (therefore they end after the range)
        ids_ending_before_or_in_range = {model.id for model in intersecting_children}
        for offset_before_range in self._waypoint_offsets.irange(maximum=r.start, reverse=True):
            waypoint = self._waypoints[offset_before_range]
            ids_ending_before_or_in_range.update(waypoint.models_ending)

            intersecting_children.extend(
                [
                    self._children.get(data_id)
                    for data_id in waypoint.models_starting
                    if data_id not in ids_ending_before_or_in_range
                ]
            )

        return intersecting_children

    def get_children_with_boundaries_intersecting_range(self, r: Range) -> List[DataModel]:
        intersecting_model_ids = set()
        for waypoint_offset in self._waypoint_offsets.irange(
            r.start, r.end, inclusive=(True, False)
        ):
            waypoint = self._waypoints[waypoint_offset]
            if waypoint_offset != r.start:
                intersecting_model_ids.update(waypoint.models_ending)
            if waypoint_offset != r.end:
                intersecting_model_ids.update(waypoint.models_starting)

        return [self._children[data_id] for data_id in intersecting_model_ids]

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
            self.get_shifted_point(r.start, False),
            self.get_shifted_point(r.end, True),
        )

    def get_shifted_point(self, point: int, exclusive_point: bool) -> int:
        i = self.resizing_shifts.bisect_right((point, 0))
        if i == 0:
            return point
        else:
            previous_shift_end, shift = self.resizing_shifts[i - 1]
            if not exclusive_point and previous_shift_end == point:
                pass
            return point + shift

    def add_new_resized_range(self, r: Range, size_diff: int):
        self.resized_ranges.append(r)
        i = self.resizing_shifts.bisect_right((r.end, 0))
        total_offset_here = self.resizing_shifts[i - 1][1] + size_diff
        for node in self.resizing_shifts.islice(i):
            node[1] += size_diff
        self.resizing_shifts.add((r.end, total_offset_here))

    def get_total_size_diff(self) -> int:
        return self.resizing_shifts[-1][1]
