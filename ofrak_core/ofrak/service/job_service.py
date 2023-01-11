import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from typing import (
    Awaitable,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
    cast,
    Any,
)

from ofrak.component.unpacker import Unpacker

from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.component.interface import ComponentInterface
from ofrak.component.packer import Packer
from ofrak.model.component_model import CC, ComponentRunResult
from ofrak.model.job_model import (
    JobModel,
    JobRunContext,
    JobRunContextFactory,
)
from ofrak.model.job_request_model import (
    JobAnalyzerRequest,
    JobComponentRequest,
    JobMultiComponentRequest,
)
from ofrak.model.resource_model import EphemeralResourceContextFactory
from ofrak.model.tag_model import ResourceTag
from ofrak.model.viewable_tag_model import ResourceViewContext
from ofrak.service.component_locator_i import (
    ComponentLocatorInterface,
    ComponentFilter,
)
from ofrak.model.component_filters import (
    ComponentTargetFilter,
    AnalyzerOutputFilter,
    ComponentOrMetaFilter,
    ComponentAndMetaFilter,
    ComponentPrioritySelectingMetaFilter,
    ComponentNotMetaFilter,
    ComponentWhitelistFilter,
    ComponentTypeFilter,
)
from ofrak.service.job_service_i import (
    JobServiceInterface,
    ComponentAutoRunFailure,
)
from ofrak.service.resource_service_i import (
    ResourceServiceInterface,
    ResourceFilter,
    ResourceFilterCondition,
)
from ofrak_type.error import NotFoundError

TargetCache = Dict[ResourceTag, List[ComponentInterface]]
LOGGER = logging.getLogger(__name__)

MAX_CONCURRENT_COMPONENTS = 512

ANALYZERS_FILTER = ComponentTypeFilter(Analyzer)  # type: ignore
IDENTIFIERS_FILTER = ComponentTypeFilter(Identifier)  # type: ignore
UNPACKERS_FILTER = ComponentTypeFilter(Unpacker)  # type: ignore
PACKERS_FILTER = ComponentTypeFilter(Packer)  # type: ignore

M = TypeVar("M")

_RunTaskResultT = Tuple[Union[ComponentRunResult, BaseException], M]


@dataclass
class _ComponentAutoRunRequest:
    target_resource_id: bytes
    component_filter: ComponentFilter


class JobService(JobServiceInterface):
    def __init__(
        self,
        component_locator: ComponentLocatorInterface,
        resource_service: ResourceServiceInterface,
        resource_context_factory: EphemeralResourceContextFactory,
        job_context_factory: JobRunContextFactory,
    ):
        self._job_store: Dict[bytes, JobModel] = dict()
        self._component_locator = component_locator
        self._resource_service = resource_service
        self._resource_context_factory = resource_context_factory
        self._job_context_factory = job_context_factory

        self._active_component_tasks: Dict[Tuple[bytes, bytes], Awaitable[_RunTaskResultT]] = dict()

    async def create_job(self, id: bytes, name: str) -> JobModel:
        model = JobModel(id, name)
        self._job_store[id] = model
        return model

    async def _run_component(
        self,
        metadata: M,
        job_id: bytes,
        resource_id: bytes,
        component: ComponentInterface,
        job_context: JobRunContext,
        config: CC,
    ) -> _RunTaskResultT:
        """
        Run a component, return the result as well as some (optional) metadata (such as the request
        that triggered the component to run). If it raises an error, the error is returned
        as an object rather than being raised.

        Once the component finishes, log it and remove this task from the set of active tasks.
        """
        LOGGER.info(
            f"JOB {job_id.hex()} - Running {component.get_id().decode()} on "
            f"resource {resource_id.hex()}"
        )

        # Create a new resource context for every component
        fresh_resource_context = self._resource_context_factory.create()
        fresh_resource_view_context = ResourceViewContext()
        result: Union[ComponentRunResult, BaseException]
        try:
            result = await component.run(
                job_id,
                resource_id,
                job_context,
                fresh_resource_context,
                fresh_resource_view_context,
                config,
            )
            _log_component_run_result_info(job_id, resource_id, component, result)
        except Exception as e:
            result = e
        component_task_id = (resource_id, component.get_id())
        del self._active_component_tasks[component_task_id]

        return result, metadata

    def _create_run_component_task(
        self,
        metadata: Any,
        job_id: bytes,
        resource_id: bytes,
        component: ComponentInterface,
        job_context: JobRunContext,
        config: CC = None,
    ) -> Awaitable[_RunTaskResultT]:
        component_task_id = (resource_id, component.get_id())
        if component_task_id in self._active_component_tasks:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug(
                    f"JOB {job_id.hex()} - Found already running task {component.get_id().decode()}"
                    f" on resource {resource_id.hex()}, awaiting result."
                )
            duplicate_task = self._active_component_tasks[component_task_id]

            return duplicate_task
        else:
            component_task = asyncio.create_task(
                self._run_component(
                    metadata,
                    job_id,
                    resource_id,
                    component,
                    job_context,
                    config,
                )
            )
            self._active_component_tasks[component_task_id] = component_task
            return component_task

    async def run_component(
        self,
        request: JobComponentRequest,
        job_context: Optional[JobRunContext] = None,
    ) -> ComponentRunResult:
        component = self._component_locator.get_by_id(request.component_id)
        if job_context is None:
            job_context = self._job_context_factory.create()
        result, _ = await self._create_run_component_task(
            request,
            request.job_id,
            request.resource_id,
            component,
            job_context,
            request.config,
        )
        if isinstance(result, BaseException):
            raise result
        else:
            return result

    async def run_analyzer_by_attribute(
        self,
        request: JobAnalyzerRequest,
        job_context: Optional[JobRunContext] = None,
    ) -> ComponentRunResult:

        if job_context is None:
            job_context = self._job_context_factory.create()

        target_resource_model = await self._resource_service.get_by_id(request.resource_id)
        component_filter: ComponentFilter = ComponentAndMetaFilter(
            ANALYZERS_FILTER,
            AnalyzerOutputFilter(
                request.attributes,
            ),
            _build_tag_filter(tuple(target_resource_model.get_tags())),
        )

        components_result = await self._auto_run_components(
            (
                _ComponentAutoRunRequest(
                    request.resource_id,
                    component_filter,
                ),
            ),
            request.job_id,
            job_context,
        )
        if components_result.components_run:
            return components_result
        else:
            raise NotFoundError(
                f"Unable to find any analyzer for attributes {request.attributes.__name__}"
            )

    def _build_target_cache(self, component_filter: ComponentFilter) -> TargetCache:
        components = self._component_locator.get_components_matching_filter(component_filter)
        target_cache = defaultdict(list)
        for component in components:
            if component.targets is None:
                continue
            for target in component.targets:
                target_cache[target].append(component)
        return target_cache

    async def run_components(
        self,
        request: JobMultiComponentRequest,
    ) -> ComponentRunResult:
        resource = await self._resource_service.get_by_id(request.resource_id)
        component_filter = _build_auto_run_filter(request)

        tags_to_target = tuple(resource.tags)
        components_result = ComponentRunResult()
        while len(tags_to_target) > 0:
            job_context = self._job_context_factory.create()
            component_tag_filter = _build_tag_filter(tags_to_target)
            final_filter = ComponentAndMetaFilter(component_filter, component_tag_filter)
            individual_component_results = await self._auto_run_components(
                (
                    _ComponentAutoRunRequest(
                        request.resource_id,
                        final_filter,
                    ),
                ),
                request.job_id,
                job_context,
            )

            components_result.update(individual_component_results)
            resource_tracker = job_context.trackers[request.resource_id]
            tags_added = resource_tracker.tags_added
            tags_to_target = tuple(tags_added)

        return components_result

    async def run_components_recursively(
        self, request: JobMultiComponentRequest
    ) -> ComponentRunResult:
        components_result = ComponentRunResult()
        component_filter = _build_auto_run_filter(request)

        initial_target_resource_models = await self._get_initial_recursive_target_resources(
            request.resource_id, component_filter
        )

        # Create a mock context to match all existing tags
        previous_job_context: JobRunContext = self._job_context_factory.create()
        for existing_resource_model in initial_target_resource_models:
            previous_job_context.trackers[existing_resource_model.id].tags_added.update(
                existing_resource_model.tags
            )
        iterations = 0
        tags_added_count = 1  # initialize just so loop starts

        while tags_added_count > 0:
            job_context = self._job_context_factory.create()
            _run_components_requests = []
            for resource_id, previous_tracker in previous_job_context.trackers.items():
                final_filter = ComponentAndMetaFilter(
                    component_filter,
                    _build_tag_filter(tuple(previous_tracker.tags_added)),
                )
                _run_components_requests.append(
                    _ComponentAutoRunRequest(
                        resource_id,
                        final_filter,
                    )
                )

            iteration_components_result = await self._auto_run_components(
                _run_components_requests,
                request.job_id,
                job_context,
            )
            components_result.update(iteration_components_result)

            tags_added_count = 0
            for resource_id, tracker in job_context.trackers.items():
                if len(tracker.tags_added) > 0:
                    tags_added_count += len(tracker.tags_added)
            previous_job_context = job_context
            LOGGER.info(
                f"Completed iteration {iterations} of run_components_recursively on "
                f"{request.resource_id.hex()}. {len(components_result.resources_modified)} "
                f"resources modified and {tags_added_count} tags added."
            )
            iterations += 1
        return components_result

    async def pack_recursively(
        self,
        job_id: bytes,
        resource_id: bytes,
    ) -> ComponentRunResult:
        packer_filter = PACKERS_FILTER
        target_cache = self._build_target_cache(packer_filter)
        all_components_result = ComponentRunResult()
        if len(target_cache) == 0:
            return all_components_result
        resources = await self._resource_service.get_descendants_by_id(
            resource_id,
            r_filter=ResourceFilter(
                include_self=True,
                tags=tuple(target_cache.keys()),
                tags_condition=ResourceFilterCondition.OR,
            ),
        )
        resources = list(resources)  # we'll need that Iterable more than once
        job_context = self._job_context_factory.create()

        # We want to start with the deepest packers. Packers at the same levels can run
        # concurrently. So we first ask for the relative depth of each returned resource.
        resource_depths = await self._resource_service.get_depths(
            [resource.id for resource in resources]
        )

        resources_by_depth = defaultdict(list)
        for resource, depth in zip(resources, resource_depths):
            resources_by_depth[depth].append(resource)

        for depth in sorted(resources_by_depth.keys(), reverse=True):
            for resource in resources_by_depth[depth]:
                component_filter: ComponentFilter = ComponentAndMetaFilter(
                    PACKERS_FILTER,
                    _build_tag_filter(tuple(resource.get_tags())),
                )

                request = _ComponentAutoRunRequest(
                    resource.id,
                    component_filter,
                )

                component_result = await self._auto_run_components(
                    [request],
                    job_id,
                    job_context,
                )
                n_packers_run = len(component_result.components_run)
                if n_packers_run == 0:
                    all_components_result.update(component_result)
                    break
                if n_packers_run > 1:
                    raise ValueError(f"Multiple packers are targeting resource {resource.id.hex()}")
        return all_components_result

    async def _get_initial_recursive_target_resources(
        self, resource_id: bytes, component_filter: ComponentFilter
    ):
        possible_targets: Set[ResourceTag] = set()
        for component in self._component_locator.get_components_matching_filter(component_filter):
            possible_targets.update(component.targets)
        initial_target_resource_models = await self._resource_service.get_descendants_by_id(
            resource_id,
            r_filter=ResourceFilter(
                include_self=True, tags=possible_targets, tags_condition=ResourceFilterCondition.OR
            ),
        )
        return initial_target_resource_models

    async def _auto_run_components(
        self,
        requests: Iterable[_ComponentAutoRunRequest],
        job_id: bytes,
        job_context: JobRunContext,
    ) -> ComponentRunResult:
        queue: List[Tuple[_ComponentAutoRunRequest, ComponentInterface]] = []
        for request in requests:
            components = self._component_locator.get_components_matching_filter(
                request.component_filter
            )
            if not components:
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug(
                        f"JOB {job_id.hex()} - Found no components to run on "
                        f"{request.target_resource_id.hex()} matching filters "
                        f"{request.component_filter}"
                    )
            else:
                for component in components:
                    queue.append((request, component))

        concurrent_run_tasks: List[Awaitable[_RunTaskResultT]] = list()

        n_tasks_to_add = min(MAX_CONCURRENT_COMPONENTS, len(queue))
        for _ in range(n_tasks_to_add):
            request, component = queue.pop()
            run_component_task = self._create_run_component_task(
                (request, type(component).__name__),
                job_id,
                request.target_resource_id,
                component,
                job_context,
            )
            concurrent_run_tasks.append(run_component_task)

        components_result = ComponentRunResult(set(), set(), set(), set())
        while len(queue) > 0 or len(concurrent_run_tasks) > 0:
            completed, pending = await asyncio.wait(
                concurrent_run_tasks, return_when=asyncio.FIRST_COMPLETED
            )
            LOGGER.debug(
                f"Completed {len(completed)} component run tasks, {len(pending)} pending and "
                f"{len(queue)} still in queue"
            )
            for completed_task in completed:
                component_run_result, component_run_metadata = completed_task.result()
                if isinstance(component_run_result, ComponentRunResult):
                    components_result.update(component_run_result)
                else:
                    component_run_error = cast(BaseException, component_run_result)
                    request_causing_run, component_name = component_run_metadata
                    raise ComponentAutoRunFailure(
                        request_causing_run.target_resource_id,
                        request_causing_run.component_filter,
                        component_name.encode(),
                    ) from component_run_error

            concurrent_run_tasks = list(pending)
            n_tasks_to_add = min(len(completed), len(queue))
            for _ in range(n_tasks_to_add):
                request, component = queue.pop()
                run_component_task = self._create_run_component_task(
                    (request, type(component).__name__),
                    job_id,
                    request.target_resource_id,
                    component,
                    job_context,
                )
                concurrent_run_tasks.append(run_component_task)

        return components_result


def _log_component_run_result_info(
    job_id: bytes,
    resource_id: bytes,
    component: ComponentInterface,
    component_result: ComponentRunResult,
    max_ids_to_log: int = 12,
):
    if LOGGER.getEffectiveLevel() > logging.INFO:
        return

    def truncate_id_seq(id_seq) -> Iterable[str]:
        for n, r_id in enumerate(id_seq):
            if n > max_ids_to_log:
                yield f" ... ({len(id_seq) - n} more)"
                return
            yield r_id.hex()

    logging_component_results = []
    if component_result.resources_modified:
        logging_component_results.append(
            f"Modified resources: {','.join(truncate_id_seq(component_result.resources_modified))}"
        )
    if component_result.resources_created:
        logging_component_results.append(
            f"Created resources: {','.join(truncate_id_seq(component_result.resources_created))}"
        )
    if component_result.resources_deleted:
        logging_component_results.append(
            f"Deleted resources: {','.join(truncate_id_seq(component_result.resources_deleted))}"
        )

    if logging_component_results:
        logging_component_results_str = "\n\t" + ("\n\t".join(logging_component_results))
    else:
        logging_component_results_str = ""
    LOGGER.info(
        f"JOB {job_id.hex()} - Finished running {component.get_id().decode()} on "
        f"{resource_id.hex()}:{logging_component_results_str}"
    )


@lru_cache(None)
def _build_tag_filter(tags: Tuple[ResourceTag]) -> ComponentFilter:
    """
    When auto-running components, most of the time only the *most specific* components should be
    run for a resource. For example, an APK resource is also a ZIP resource; we want to always run
    the APK Unpacker on resources that are tagged as both ZIP and APK, because APK is a more
    specific tag. However, Identifiers are a special case because they have benign side-effects, so
    it is desirable to greedily run all Identifiers that could target a resource, not only the most
    specific Identifiers.

    This function constructs a filter which allows only components that target at least one of the
    given tags, but for non-identifiers the filter is even stricter so that only the most specific
    components are filtered.

    :param tags: Tags to target, from the resource that is being auto-run on

    :return: A filter which allows a component to run if (it is an Identifier, AND it targets at
    least one of the given tags) OR (it is NOT an Identifier, AND it targets one of the most
    specific given tags that are targeted by components)
    """
    tags_by_specificity = ResourceTag.sort_tags_into_tiers(tags)

    filters_prioritized_by_specificity = tuple(
        ComponentTargetFilter(*tag_specificity_level)
        for tag_specificity_level in tags_by_specificity
    )
    return ComponentOrMetaFilter(
        ComponentAndMetaFilter(
            IDENTIFIERS_FILTER,
            ComponentTargetFilter(*tags),
        ),
        ComponentAndMetaFilter(
            ComponentNotMetaFilter(
                IDENTIFIERS_FILTER,
            ),
            ComponentPrioritySelectingMetaFilter(*filters_prioritized_by_specificity),
        ),
    )


@lru_cache(None)
def _build_auto_run_filter(
    request: JobMultiComponentRequest,
) -> ComponentFilter:
    filters: List[ComponentFilter] = []
    if request.components_allowed:
        filters.append(ComponentWhitelistFilter(*request.components_allowed))

    type_filters = []
    if request.all_unpackers:
        type_filters.append(UNPACKERS_FILTER)
    if request.all_identifiers:
        type_filters.append(IDENTIFIERS_FILTER)
    if request.all_analyzers:
        type_filters.append(ANALYZERS_FILTER)
    if request.all_packers:
        type_filters.append(PACKERS_FILTER)
    filters.append(ComponentOrMetaFilter(*type_filters))
    if request.components_disallowed:
        filters.append(
            ComponentNotMetaFilter(ComponentWhitelistFilter(*request.components_disallowed))
        )
    if request.tags_ignored:
        filters.append(ComponentNotMetaFilter(ComponentTargetFilter(*request.tags_ignored)))

    return ComponentAndMetaFilter(*filters)
