import asyncio
import dataclasses
import inspect
import logging
from abc import ABC, abstractmethod
from typing import (
    Dict,
    Iterable,
    List,
    Optional,
    Callable,
    Any,
    cast,
)

from ofrak.component.interface import ComponentInterface
from ofrak.model.component_model import ComponentContext, CC, ComponentRunResult, ComponentConfig
from ofrak.model.data_model import DataPatchesResult
from ofrak.model.job_model import (
    JobRunContext,
)
from ofrak.model.resource_model import (
    ResourceContext,
    MutableResourceModel,
)
from ofrak.model.viewable_tag_model import ResourceViewContext
from ofrak.resource import Resource, ResourceFactory
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.dependency_handler import DependencyHandlerFactory
from ofrak.service.resource_service_i import ResourceServiceInterface
from ofrak_type.error import NotFoundError

LOGGER = logging.getLogger(__name__)


class AbstractComponent(ComponentInterface[CC], ABC):
    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
    ):
        self._resource_factory = resource_factory
        self._data_service = data_service
        self._resource_service = resource_service
        self._dependency_handler_factory = DependencyHandlerFactory()

    @classmethod
    def get_id(cls) -> bytes:
        return cls.id if cls.id is not None else cls.__name__.encode()

    async def run(
        self,
        job_id: bytes,
        resource_id: bytes,
        job_context: JobRunContext,
        resource_context: ResourceContext,
        resource_view_context: ResourceViewContext,
        config: CC,
    ) -> ComponentRunResult:
        """

        :param job_id:
        :param resource_id:
        :param job_context:
        :param resource_context:
        :param resource_view_context:
        :param config:
        :return: The IDs of all resources modified by this component
        """
        component_context = ComponentContext(self.get_id(), self.get_version())
        resource = await self._resource_factory.create(
            job_id,
            resource_id,
            resource_context,
            resource_view_context,
            component_context,
            job_context,
        )
        if config is None:
            config = self.get_default_config()
        await self._run(resource, config)
        deleted_resource_models: List[MutableResourceModel] = list()

        for deleted_r_id in component_context.resources_deleted:
            mutable_resource_model = resource_context.resource_models.get(deleted_r_id)
            if mutable_resource_model:
                deleted_resource_models.append(mutable_resource_model)
            else:
                raise NotFoundError(
                    f"The resource {deleted_r_id.hex()} was deleted but not in "
                    f"the resource context"
                )

        # Save deleted resource so they won't interfere with patches
        # This is where deleted resources are actually deleted from their respective databases
        await self._save_resources(
            job_id,
            deleted_resource_models,
            resource_context,
            resource_view_context,
            job_context,
            component_context,
        )

        dependency_handler = self._dependency_handler_factory.create(
            self._resource_service,
            self._data_service,
            component_context,
            resource_context,
        )
        patch_results = await self.apply_all_patches(component_context)
        await dependency_handler.handle_post_patch_dependencies(patch_results)
        dependency_handler.create_component_dependencies(self.get_id(), self.get_version())
        dependency_handler.create_resource_dependencies(self.get_id())

        # Get modified resources
        modified_resource_models: Dict[bytes, MutableResourceModel] = dict()
        modified_resource_ids = component_context.get_modified_resource_ids()
        for modified_r_id in modified_resource_ids:
            mutable_resource_model = resource_context.resource_models.get(modified_r_id)
            if mutable_resource_model:
                modified_resource_models[modified_r_id] = mutable_resource_model
            else:
                raise NotFoundError(
                    f"The resource {modified_r_id.hex()} was modified but not in "
                    f"the resource context"
                )

        # Save modified resources
        await self._save_resources(
            job_id,
            modified_resource_models.values(),
            resource_context,
            resource_view_context,
            job_context,
            component_context,
        )

        component_result = ComponentRunResult(
            {self.get_id()},
            modified_resource_ids,
            component_context.resources_deleted,
            component_context.resources_created,
        )
        return component_result

    @abstractmethod
    async def _run(self, resource: Resource, config: CC):
        raise NotImplementedError()

    async def _save_resources(
        self,
        job_id: bytes,
        mutable_resource_models: Iterable[MutableResourceModel],
        resource_context: ResourceContext,
        resource_view_context: ResourceViewContext,
        job_context: Optional[JobRunContext],
        component_context: ComponentContext,
    ):
        locator_tasks = list()
        for mutable_resource_model in mutable_resource_models:
            locator_tasks.append(
                self._resource_factory.create(
                    job_id,
                    mutable_resource_model.id,
                    resource_context,
                    resource_view_context,
                    component_context,
                    job_context,
                )
            )
        resources = await asyncio.gather(*locator_tasks)
        for resource in resources:
            await resource.save()

    @staticmethod
    def _get_default_config_from_method(
        component_method: Callable[[Any, Resource, CC], Any]
    ) -> Optional[CC]:
        run_signature = inspect.signature(component_method)
        config_arg_type = run_signature.parameters["config"]
        default_arg: CC = config_arg_type.default

        if isinstance(default_arg, ComponentConfig):
            try:
                return cast(CC, dataclasses.replace(default_arg))
            except TypeError as e:
                raise TypeError(
                    f"ComponentConfig subclass {type(default_arg)} is not a dataclass! This is "
                    f"required in order to copy the default config to ensure the default is "
                    f"non-mutable."
                ) from e
        elif default_arg is not None and default_arg is not config_arg_type.empty:
            raise TypeError(
                f"Default config {default_arg} must be either an instance of ComponentConfig, "
                f"None, or left empty!"
            )
        else:
            return None

    async def apply_all_patches(
        self, component_context: ComponentContext
    ) -> List[DataPatchesResult]:
        # Build a list of patches, making sure that there is at most one patch that causes a resize
        patches = []
        moves = []
        for resource_id, tracker in component_context.modification_trackers.items():
            moves.extend(tracker.data_moves)
            tracker.data_moves.clear()
            patches.extend(tracker.data_patches)
            tracker.data_patches.clear()
        if len(patches) > 0 or len(moves) > 0:
            return await self._data_service.apply_patches(patches, moves)
        else:
            return []

    def get_version(self) -> int:
        return 1

    def _log_component_has_run_warning(self, resource: Resource):
        LOGGER.warning(
            f"{self.get_id().decode()} has already been run on resource {resource.get_id().hex()}"
        )
