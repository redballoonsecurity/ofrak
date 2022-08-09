from collections import defaultdict
from dataclasses import dataclass, field
from typing import Set, Type, Dict, List, TypeVar, Optional

from ofrak.model.data_model import DataPatch, DataMove
from ofrak.model.resource_model import ResourceAttributes
from ofrak_type.range import Range

CLIENT_COMPONENT_ID = b"__client_context__"
CLIENT_COMPONENT_VERSION = -1


@dataclass
class ComponentConfig:
    """
    Base class for all components' configs. All subclasses should also be dataclasses.
    """


CC = TypeVar("CC", bound=Optional[ComponentConfig])


@dataclass
class ComponentRunResult:
    """
    Dataclass created after one or more components complete, holding high-level information about
    what resources were affected by a component or components
    """

    components_run: Set[bytes] = field(default_factory=set)
    resources_modified: Set[bytes] = field(default_factory=set)
    resources_deleted: Set[bytes] = field(default_factory=set)
    resources_created: Set[bytes] = field(default_factory=set)

    def update(self, other_results: "ComponentRunResult"):
        self.components_run.update(other_results.components_run)
        self.resources_modified.update(other_results.resources_modified)
        self.resources_created.update(other_results.resources_created)
        self.resources_deleted.update(other_results.resources_deleted)


@dataclass
class ComponentResourceAccessTracker:
    data_accessed: Set[Range] = field(default_factory=set)
    attributes_accessed: Set[Type[ResourceAttributes]] = field(default_factory=set)


@dataclass
class ComponentResourceModificationTracker:
    data_patches: List[DataPatch] = field(default_factory=list)
    data_moves: List[DataMove] = field(default_factory=list)


@dataclass
class ComponentContext:
    component_id: bytes
    component_version: int
    access_trackers: Dict[bytes, ComponentResourceAccessTracker] = field(
        default_factory=lambda: defaultdict(ComponentResourceAccessTracker)
    )
    modification_trackers: Dict[bytes, ComponentResourceModificationTracker] = field(
        default_factory=lambda: defaultdict(ComponentResourceModificationTracker)
    )
    resources_created: Set[bytes] = field(default_factory=set)
    resources_deleted: Set[bytes] = field(default_factory=set)

    def mark_resource_modified(self, r_id: bytes):
        # Creates a new tracker if none exists, and leaves tracker untouched if it already exists
        _ = self.modification_trackers[r_id]

    def get_modified_resource_ids(self, include_deleted=False) -> Set[bytes]:
        modified_resource_ids = set(self.modification_trackers.keys())
        if not include_deleted:
            modified_resource_ids = modified_resource_ids.difference(self.resources_deleted)
        return modified_resource_ids


class ClientComponentContext(ComponentContext):
    def __init__(self):
        super().__init__(CLIENT_COMPONENT_ID, CLIENT_COMPONENT_VERSION)
