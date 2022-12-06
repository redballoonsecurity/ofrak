import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Type, TypeVar

from ofrak.model.data_model import DataPatch
from ofrak.model.resource_model import ResourceAttributes
from ofrak_type.range import Range

CLIENT_COMPONENT_ID = b"__client_context__"
CLIENT_COMPONENT_VERSION = -1


@dataclass
class ComponentConfig:
    """
    Base class for all components' configs. All subclasses should also be dataclasses.
    """


@dataclass(frozen=True)
class ComponentExternalTool:
    """
    An external tool or utility (like `zip` or `squashfs`) a component depends on. Includes some
    basic information on installation, either via package manager or bespoke process.

    Part of this class's responsibility is to check if the tool is installed. Most tools are
    simple command-line utilities whose installation can be check by running:
        `<tool> <install_check_arg>`
    For dependencies which do NOT follow this pattern, subclass ComponentExternalTool and redefine
    the `is_tool_installed` method to perform the check.

    :ivar tool: Name of the command-line tool that will be run
    :ivar tool_homepage: Like to homepage of the tool, with install instructions etc.
    :ivar install_check_arg: Argument to pass to the tool to check if it can be found and run on
    the host, typically something like "--help"
    :ivar apt_package: An `apt` package that installs this tool, if such a package exists
    :ivar brew_package: An `brew` package that installs this tool, if such a package exists

    """

    tool: str
    tool_homepage: str
    install_check_arg: str
    apt_package: Optional[str] = None
    brew_package: Optional[str] = None

    def is_tool_installed(self) -> bool:
        """
        Check if a tool is installed by running it with the `install_check_arg`.
        This method runs `<tool> <install_check_arg>`.

        :return: True if the `tool` command returned zero, False if `tool` could not be found or
        returned non-zero exit code.
        """
        try:
            retcode = subprocess.call(
                [self.tool, self.install_check_arg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return False

        return 0 == retcode


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
