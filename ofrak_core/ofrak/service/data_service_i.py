from abc import ABCMeta, abstractmethod
from typing import List, Iterable, Optional

from ofrak.model.data_model import DataModel, DataPatch, DataPatchesResult
from ofrak.service.abstract_ofrak_service import AbstractOfrakService
from ofrak_type.range import Range


class DataServiceInterface(AbstractOfrakService, metaclass=ABCMeta):
    @abstractmethod
    async def create_root(self, data_id: bytes, data: bytes) -> DataModel:
        """
        Create a root data model with its own data bytes.

        :param data_id: Unique ID for the new data model
        :param data: Binary data belonging to the new data model

        :return: The new data model object

        :raises AlreadyExistError: if `data_id` is already associated with a model
        """
        raise NotImplementedError()

    @abstractmethod
    async def create_mapped(
        self,
        data_id: bytes,
        parent_id: bytes,
        range_in_parent: Range,
    ) -> DataModel:
        """
        Create a new data model which is mapped into another data model. That is, it does not hold
        its own data, but defines its own data as a subsection of another model's data. The model
        it maps from (`parent_id`) may be a root model or another mapped model; if `parent_id` is
        another mapped node, the new mapped node created here will be mapped to the same root as
        `parent_id` at a range translated to be within `parent_id` as defined by `range_in_parent`.

        :param data_id: Unique ID for the new data model
        :param parent_id: ID of the data model to map the new model into
        :param range_in_parent: Range in `parent_id` which the new model will map

        :return: The new data model object

        :raises AlreadyExistError: if `data_id` is already associated with a model
        :raises NotFoundError: if `parent_id` is not associated with any known model
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_by_id(self, data_id: bytes) -> DataModel:
        """
        Get the data model object associated with the given ID.

        :param data_id: A unique ID for a data model

        :return: The model associated with `data_id`

        :raises NotFoundError: if `data_id` is not associated with any known model
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_by_ids(self, data_ids: Iterable[bytes]) -> Iterable[DataModel]:
        """
        Get the data models object associated with the given IDs.

        :param data_ids: Multiple unique IDs for data models

        :return: The models associated with each ID in `data_ids`, in the same order their IDs were
        provided

        :raises NotFoundError: if any ID in `data_ids` is not associated with any known model
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_data_length(self, data_id: bytes) -> int:
        """
        Return the length of a single data model.

        :param data_id: A unique ID for a data model

        :return: The length of the data included in the model

        :raises NotFoundError: if `data_id` is not associated with any known model
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_data_range_within_root(self, data_id: bytes) -> Range:
        """
        Get the range that a model maps in its root. If the model specified by `data_id` is itself
        a root, returns a range covering that whole root (i.e. Range(0, length)).

        :param data_id: A unique ID for a data model

        :return: Range that `data_id` maps in its root

        :raises NotFoundError: if `data_id` is not associated with any known model
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_range_within_other(self, data_id: bytes, within_data_id: bytes) -> Range:
        """
        Get the range representing the intersection between two data models, assuming they are both
        mapped into the same root data. Either of `data_id` or `within_data_id` may be roots, but
        they cannot both be roots (unless they are the same).

        :param data_id: A unique ID for a data model
        :param within_data_id: A unique ID for a data model

        :return: The range where `data_id`'s model intersects `within_data_id`'s model

        :raises NotFoundError: if `data_id` or `within_data_id` is not associated with any known
        model
        :raises ValueError: if `data_id` is not mapped into `within_data_id` or they do not share
        the same root
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_data(self, data_id: bytes, data_range: Optional[Range] = None) -> bytes:
        """
        Get the data (or section of data) of a model. The optional `data_range` parameter specifies
        which a range within `data_id`'s data to return; if this range actually falls outside the
        boundaries of `data_id`'s data, an empty bytestring is returned.

        :param data_id: A unique ID for a data model
        :param data_range: An optional range within the model's data to return

        :return: Bytes of data from the model associated with `data_id` - all bytes by default, a
        specific slice if `data_range` is provided, and empty bytes if `data_range` is provided but
        is outside the modeled data.

        :raises NotFoundError: if `data_id` is not associated with any known model
        """
        raise NotImplementedError()

    @abstractmethod
    async def apply_patches(
        self,
        patches: List[DataPatch],
    ) -> List[DataPatchesResult]:
        """
        Modify the data of a number of models, modeled as a list of `DataPatch` structures each
        specifying: a target data model (by ID), new data, and a range to overwrite with the new
        data. The listed patches are applied in order, so that subsequent patches may effectively
        'erase' an earlier patch. Patches may resize data if the new data is not the same size as
        the range it is overwriting. Such patches create additional restrictions:

        1. If `patches` contains a patch that resizes a range of data, no subsequent patch in
        `patches` is allowed to modify that resized range.
        2. Resizing patches are not allowed to overwrite ranges that contain the borders of any
        data models. For example, if model B maps Range(0, 6) of model A, a patch that resizes
        Range(4, 10) of model A is not allowed (whether it increases or decreases the size).

        :param patches: A list of patch data structures to be applied, in order

        :return: A list of data structures describing all modified ranges of each data model
        affected by `patches`

        :raises NotFoundError: if any data ID in the `patches` list is not associated with any
        known model
        :raises PatchOverlapError: if a patch targets a region of data which has already been
        modified by a patch which resized that region
        :raises PatchOverlapError: if a patch would resize a region of data which contains the
        start or end of one or more data models
        """
        raise NotImplementedError()

    @abstractmethod
    async def delete_models(self, data_ids: Iterable[bytes]) -> None:
        """
        Delete one or more data models. If a root model is deleted, all models mapped into that
        root are also deleted.

        :param data_ids: Multiple unique IDs for data models

        :raises NotFoundError: if any ID in `data_ids` is not associated with any known model
        """
        raise NotImplementedError()
