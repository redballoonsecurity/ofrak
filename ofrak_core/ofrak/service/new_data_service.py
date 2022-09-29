import itertools
from collections import defaultdict
from typing import Dict, Iterable, Optional, List, Union, cast, Tuple, Set

from sortedcontainers import SortedList, SortedDict

from ofrak.model.data_model import (
    DataModel,
    DataPatch,
    DataMove,
    DataPatchesResult,
    DataPatchResult,
)
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.error import OutOfBoundError, PatchOverlapError
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range

# Type alias; typechecker makes no distinction between this and bytes. It's just for the humans.
DataId = bytes


class _DataRoot:
    """
    A root data model which may have other data models mapped into it
    """

    def __init__(self, model: DataModel, data: bytes):
        self.model: DataModel = model
        self.data = data
        # TODO: convert these 2 to SortedDict
        self.children_by_start: SortedList[DataModel] = SortedList(
            key=lambda data_model: data_model.range.start
        )
        self.children_by_end: SortedList[DataModel] = SortedList(
            key=lambda data_model: data_model.range.end
        )
        self.children_by_offset: SortedDict[int, Set[DataModel]] = SortedDict({0: set()})

    @property
    def length(self) -> int:
        return len(self.data)

    def get_children_intersecting_range(self, r: Range) -> List[DataModel]:
        nearest_child_start_index = self.children_by_offset.bisect_left(r.start)
        _, children_intersecting_start = self.children_by_offset.peekitem(nearest_child_start_index)
        return list(children_intersecting_start)

    def get_children_with_boundaries_intersecting_range(self, r: Range) -> List[DataModel]:
        starts_intersecting_patch_range = self.children_by_start.islice(
            self.children_by_start.bisect_left(r),
            self.children_by_start.bisect_left(r),
        )

        ends_intersecting_patch_range = self.children_by_end.islice(
            self.children_by_end.bisect_left(r),
            self.children_by_end.bisect_left(r),
        )

        return [
            model
            for model in itertools.chain(
                starts_intersecting_patch_range, ends_intersecting_patch_range
            )
        ]

    def add_new_model(self, model: DataModel):
        if model.range.start < 0 or model.range.end > self.length:
            raise OutOfBoundError(
                f"New mapped data model {model.id.hex()} is outside the bounds of its root "
                f"{self.model.id.hex()}: ({model.range} is outside of {self.model.range})"
            )
        self.children_by_start.add(model)
        self.children_by_end.add(model)

        prev_waypoint_idx_to_start = self.children_by_offset.bisect_left(model.range.start)
        prev_waypoint_idx_to_end = self.children_by_offset.bisect_left(model.range.end)
        if model.range.start not in self.children_by_offset:
            _, models_at_nearest_waypoint = self.children_by_offset.peekitem(
                min(prev_waypoint_idx_to_start - 1, 0)
            )
            self.children_by_offset[model.range.start] = set(models_at_nearest_waypoint)

        if model.range.end not in self.children_by_offset:
            _, models_at_nearest_waypoint = self.children_by_offset.peekitem(
                min(prev_waypoint_idx_to_end - 1, 0)
            )
            self.children_by_offset[model.range.end] = set(models_at_nearest_waypoint)

        for waypoint in self.children_by_offset.islice(
            prev_waypoint_idx_to_start,
            prev_waypoint_idx_to_end,
        ):
            self.children_by_offset[waypoint].add(model)

    def delete_model(self, model: DataModel):
        self.children_by_start.remove(model)
        self.children_by_end.remove(model)

        start_waypoint_idx = self.children_by_offset.index(model.range.start)
        end_waypoint_idx = self.children_by_offset.index(model.range.end)

        for waypoint in self.children_by_offset.islice(
            start_waypoint_idx,
            end_waypoint_idx,
        ):
            waypoint.remove(model)


class NewDataService(DataServiceInterface):
    def __init__(self):
        self._model_store: Dict[DataId, DataModel] = dict()
        self._roots: Dict[DataId, _DataRoot] = dict()

    def _get_by_id(self, data_id: DataId) -> DataModel:
        model = self._model_store.get(data_id)
        if model is None:
            raise NotFoundError(f"No data model with ID {data_id.hex()} exists")
        else:
            return model

    def _get_root_by_id(self, data_id: DataId) -> _DataRoot:
        root = self._roots.get(data_id)
        if root is None:
            raise NotFoundError(f"No data root with ID {data_id.hex()} exists")
        else:
            return root

    def _get_absolute_range(self, id_or_model: Union[DataId, DataModel], r: Range) -> Range:
        if isinstance(id_or_model, DataId):
            model = self._get_by_id(cast(DataId, id_or_model))
        else:
            model = cast(DataModel, id_or_model)

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

    async def create(self, data_id: DataId, data: bytes, alignment: int = 0) -> DataModel:
        new_model = DataModel(data_id, Range(0, len(data)), alignment, None)

        self._model_store[data_id] = new_model
        self._roots[data_id] = _DataRoot(new_model, data)

    async def create_mapped(
        self,
        data_id: bytes,
        parent_id: bytes,
        range: Range,
        alignment: int = 0,
    ) -> DataModel:
        parent_model = self._get_by_id(parent_id)
        if parent_model.is_mapped():
            root_id = parent_model.root_id
        else:
            root_id = parent_model.id
        new_model = DataModel(data_id, range, alignment, root_id)
        self._roots[root_id].add_new_model(new_model)
        self._model_store[data_id] = new_model

    async def get_by_id(self, data_id: DataId) -> DataModel:
        return self._get_by_id(data_id)

    async def get_by_ids(self, data_ids: Iterable[bytes]) -> Iterable[DataModel]:
        return [self._get_by_id(data_id) for data_id in data_ids]

    # TODO: I think we can get rid of this, if resources hold their own data models
    async def get_data_length(self, data_id: bytes) -> int:
        return self._get_by_id(data_id).range.length()

    async def get_data_range_within_root(self, data_id: bytes) -> Range:
        return self._get_by_id(data_id).range

    async def get_data(self, data_id: bytes, data_range: Range = None) -> bytes:
        model = self._get_by_id(data_id)
        if model.is_mapped():
            root = self._get_root_by_id(model.root_id)
        else:
            root = self._roots[data_id]
        if data_range is not None:
            translated_range = data_range.translate(model.range.start)
            if data_range.end == Range.MAX:
                translated_range = Range(translated_range.start, model.range.end)
            elif translated_range.end > model.range.end:
                raise OutOfBoundError(
                    f"Requested data at {data_range} of model {data_id.hex()} is outside the "
                    f"model's range {model.range}"
                )
            return root.data[translated_range.start : translated_range.end]
        else:
            return root.data[model.range.start : model.range.end]

    async def set_alignment(self, data_id: bytes, alignment: int):
        self._get_by_id(data_id).alignment = alignment

    async def set_overlaps_enabled(self, data_id: bytes, enable_overlaps: bool):
        pass

    async def apply_patches(
        self,
        patches: Optional[List[DataPatch]] = None,
        moves: Optional[List[DataMove]] = None,  # We never use data moves. What's the point?
    ) -> List[DataPatchesResult]:
        if patches is None:
            patches = []
        if moves is None:
            moves = []

        patches_by_root: Dict[DataId, List[DataPatch]] = defaultdict(list)
        for patch in patches:
            target_data_model = self._get_by_id(patch.data_id)
            if target_data_model.is_mapped():
                patches_by_root[target_data_model.root_id].append(patch)
            else:
                patches_by_root[target_data_model.id].append(patch)

        results = []
        for root_id, patches_for_root in patches_by_root.items():
            results.extend(self._apply_patches_to_root(root_id, patches_for_root, []))

        return results

    async def delete_node(self, data_id: bytes) -> None:
        model = self._get_by_id(data_id)
        if model.root_id is None:
            # deleting a root node
            root = self._roots[model.id]
            for child_model in root.children_by_start:
                del self._model_store[child_model.id]

            del self._roots[model.id]

        else:
            root = self._get_root_by_id(model.root_id)
            root.delete_model(model)
            del self._model_store[data_id]

    async def delete_models(self, data_ids: Iterable[bytes]) -> None:
        roots_to_delete = set()
        mapped_to_delete = set()

        for data_id in data_ids:
            model = self._get_by_id(data_id)
            if model.root_id is None:
                roots_to_delete.add(model)
            else:
                mapped_to_delete.add(model)

        for root_model in roots_to_delete:
            root = self._roots[root_model.id]
            for child_model in root.children_by_start:
                mapped_to_delete.remove(child_model)
                del self._model_store[child_model.id]

            del self._roots[root_model.id]

        for model in mapped_to_delete:
            root = self._get_root_by_id(model.root_id)
            root.delete_model(model)
            del self._model_store[model.id]

    def _apply_patches_to_root(
        self,
        root_data_id: DataId,
        patches: List[DataPatch],
        moves: List[DataMove],
    ) -> List[DataPatchesResult]:
        root: _DataRoot = self._roots[root_data_id]
        finalized_ordered_patches: List[Tuple[Range, bytes]] = []
        resize_tracker = _PatchResizeTracker()

        # Screen patches for inconsistencies/overlaps
        # And translate them as required by preceding patches
        raw_patch_ranges_in_root = []

        for patch in patches:
            if resize_tracker.overlaps_resized_range(patch.range):
                raise PatchOverlapError(
                    f"Patch to {patch.range} of {patch.data_id.hex()} overlaps previously resized "
                    f"area of {patch.data_id.hex()} and cannot be applied!"
                )
            target_model = self._get_by_id(patch.data_id)

            raw_absolute_patch_range = self._get_absolute_range(target_model, patch.range)
            raw_patch_ranges_in_root.append(raw_absolute_patch_range)
            absolute_patch_range = resize_tracker.translate_range(raw_absolute_patch_range)
            models_intersecting_patch_range = root.get_children_with_boundaries_intersecting_range(
                absolute_patch_range
            )

            size_diff = patch.data - patch.range.length()
            if size_diff == 0:
                finalized_ordered_patches.append((patch.range, patch.data))
            elif models_intersecting_patch_range:
                raise PatchOverlapError(
                    f"Because patch to {patch.data_id.hex()} resizes data by {size_diff} bytes, "
                    f"the effects on {len(models_intersecting_patch_range)} model(s) "
                    f"intersecting the patch range {patch.range} could not be determined. If "
                    f"data must be resized, any resources overlapping the data must be "
                    f"deleted before patching and re-created afterwards along new data ranges."
                )
            else:
                finalized_ordered_patches.append((patch.range, patch.data))
                resize_tracker.add_new_resized_range(patch.range, size_diff)

        results = defaultdict(list)
        for affected_range in Range.merge_ranges(raw_patch_ranges_in_root):
            for affected_model in root.get_children_intersecting_range(affected_range.range):
                results[affected_model.id].append(DataPatchResult(affected_range))
            results[root_data_id].append(DataPatchResult(affected_range))

        # Apply finalized patches to data and data models
        for patch_range, data in finalized_ordered_patches:
            root.data[patch_range.start : patch_range.end] = data

        for child_model in root.children_by_start:
            new_child_range = resize_tracker.translate_range(child_model.range)
            child_model.range = new_child_range

        root.model.range = Range(root.model.range.start, resize_tracker.get_total_size_diff())

        return [
            DataPatchesResult(data_id, results_for_id)
            for data_id, results_for_id in results.items()
        ]


class _PatchResizeTracker:
    def __init__(self):
        # Map ORIGINAL offsets in
        self.resizing_shifts: SortedList[List[int]] = SortedList(key=lambda x: x[0])
        self.resized_ranges = []
        self.resizing_shifts.add([0, 0])

    def overlaps_resized_range(self, r: Range) -> bool:
        return any(resized_range.overlaps(r) for resized_range in self.resized_ranges)

    def translate_range(self, r: Range) -> Range:
        i = self.resizing_shifts.bisect_left((r.start, 0))
        if i == 0:
            return r
        i = min(i, len(self.resizing_shifts) - 1)
        return r.translate(self.resizing_shifts[i][1])

    def add_new_resized_range(self, r: Range, size_diff: int):
        self.resized_ranges.append(r)
        i = self.resizing_shifts.bisect_right((r.end, 0))
        total_offset_here = self.resizing_shifts[i - 1][1] + size_diff
        for node in self.resizing_shifts.islice(i):
            node[1] += size_diff
        self.resizing_shifts.insert(i, (r.end, total_offset_here))

    def get_total_size_diff(self) -> int:
        return self.resizing_shifts[-1][1]
