from abc import ABC, abstractmethod
from typing import Iterable, Optional, Set, Type, List, Tuple, MutableMapping

from ofrak.model.component_model import ComponentRunResult
from ofrak.model.resource_model import MutableResourceModel, ResourceAttributes
from ofrak.model.tag_model import ResourceTag
from ofrak.model.viewable_tag_model import ViewableResourceTag, ResourceViewInterface
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.id_service_i import IDServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface
from ofrak_type import Range


class ResourceTracker:
    def __init__(self, model: MutableResourceModel):
        self.model: MutableResourceModel = model
        self.attribute_reads: Set[Type[ResourceAttributes]] = set()
        self.data_reads: Set[Range] = set()
        self.data_writes: List[Tuple[Range, bytes]] = list()

        # TODO: Possibly makes sense as a WeakKeyDictionary or WeakValueDictionary, so entries are
        #  discarded when view is no longer in use.
        #  Need to be careful of circular references in that case
        self.views: MutableMapping[ViewableResourceTag, ResourceViewInterface] = dict()

        self.is_deleted: bool = False  # Set after the resource is actually deleted
        self.is_new: bool = False

    def is_dirty(self) -> bool:
        return self.modified() or self.is_deleted

    def model_modified(self) -> bool:
        return self.model.diff.modified()

    def data_modified(self) -> bool:
        return len(self.data_writes) > 0

    def modified(self) -> bool:
        return self.model_modified() or self.data_modified()

    def why_dirty(self) -> str:
        if not self.is_dirty():
            return "Not dirty!"

        reasons = []
        if self.model_modified():
            field_names: List[str] = []

            diff_infos = []
            for field_name in field_names:
                val = getattr(self.model.diff, field_name)
                if len(val) > 0:
                    diff_infos.append(f"{field_name}: {val}")
            diff_info = "\n\t".join(diff_infos)
            reasons.append(f"Model was modified: \n\t{diff_info}")

        if self.data_modified():
            reasons.append("Data patches are queued")

        if self.is_deleted:
            reasons.append("Resource has been deleted")

        assert len(reasons) > 0, "Resource is dirty but could not extract the reason(s)!"

        return "\n".join(reasons)


class OFRAKContext2Interface(ABC):
    @property
    @abstractmethod
    def resource_service(self) -> ResourceServiceInterface:
        raise NotImplementedError()

    @property
    @abstractmethod
    def data_service(self) -> DataServiceInterface:
        raise NotImplementedError()

    @property
    @abstractmethod
    def id_service(self) -> IDServiceInterface:
        raise NotImplementedError()

    @abstractmethod
    async def get_resources(self, *resource_ids: bytes) -> Iterable["Resource"]:
        raise NotImplementedError()

    @abstractmethod
    def fork(
        self,
        job_id: Optional[bytes] = None,
        component_id: Optional[bytes] = None,
        component_version: Optional[int] = None,
    ) -> "OFRAKContext2":
        raise NotImplementedError()

    @abstractmethod
    async def push(self):
        """
        Push pending changes to global state


        1. Handle deleted resources
        2. Handle deleted data models (as a result of 1)
        3. Handle data patches
        4. Handle dependencies
        5. Push updated resource models
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def pull(
        self,
        modified_resource_ids: Iterable[bytes],
        deleted_resource_ids: Iterable[bytes],
    ):
        """
        Pull from global state to update local state
        How do we know what state to update? This will need to take a list or something of resource
        models or IDs (IDs are better)
        Then the result of a component run (or whatever) can be pulled into here.

        1. Pull resource models
        2. Update resource views
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    def get_cumulative_result(self) -> ComponentRunResult:
        raise NotImplementedError()

    @abstractmethod
    async def create_root_resource(
        self, name: str, data: bytes, tags: Iterable[ResourceTag] = ()
    ) -> "Resource":
        raise NotImplementedError()

    @abstractmethod
    async def create_root_resource_from_file(self, file_path: str) -> "Resource":
        raise NotImplementedError()

    @abstractmethod
    async def start_context(self):
        raise NotImplementedError()

    @abstractmethod
    async def shutdown_context(self):
        raise NotImplementedError()
