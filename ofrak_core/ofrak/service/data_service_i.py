from abc import ABCMeta, abstractmethod
from typing import List, Iterable, Optional

from ofrak.model.data_model import DataModel, DataPatch, DataPatchesResult, DataMove
from ofrak.service.abstract_ofrak_service import AbstractOfrakService
from ofrak_type.range import Range


class DataServiceInterface(AbstractOfrakService, metaclass=ABCMeta):
    @abstractmethod
    async def create(self, data_id: bytes, data: bytes) -> DataModel:
        raise NotImplementedError()

    @abstractmethod
    async def create_mapped(
        self,
        data_id: bytes,
        root_id: bytes,
        mapped_range: Range,
    ) -> DataModel:
        raise NotImplementedError()

    @abstractmethod
    async def get_by_id(self, data_id: bytes) -> DataModel:
        raise NotImplementedError()

    @abstractmethod
    async def get_by_ids(self, data_ids: Iterable[bytes]) -> Iterable[DataModel]:
        raise NotImplementedError()

    @abstractmethod
    async def get_data_length(self, data_id: bytes) -> int:
        raise NotImplementedError()

    @abstractmethod
    async def get_data_range_within_root(self, data_id: bytes) -> Range:
        raise NotImplementedError()

    @abstractmethod
    async def get_range_within_other(self, data_id: bytes, within_data_id: bytes) -> Range:
        raise NotImplementedError()

    @abstractmethod
    async def get_data(self, data_id: bytes, data_range: Range = None) -> bytes:
        raise NotImplementedError()

    @abstractmethod
    async def apply_patches(
        self,
        patches: Optional[List[DataPatch]] = None,
        moves: Optional[List[DataMove]] = None,
    ) -> List[DataPatchesResult]:
        raise NotImplementedError()

    @abstractmethod
    async def delete_models(self, data_ids: Iterable[bytes]) -> None:
        """
        Delete one or more data models. If a root model is deleted, all models mapped into that
        root are also deleted.

        :param data_ids:
        :return:
        """
        raise NotImplementedError()
