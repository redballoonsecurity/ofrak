import itertools
from dataclasses import dataclass
from typing import Tuple, Iterable, Dict, List, Set, Type, Optional

import pytest

from ofrak import OFRAKContext
from ofrak.core.magic import Magic
from ofrak.model.component_model import ComponentContext, ClientComponentContext
from ofrak.model.data_model import DataPatchesResult
from ofrak.model.resource_model import (
    ResourceContext,
    EphemeralResourceContext,
    ResourceModel,
    ResourceAttributeDependency,
    MutableResourceModel,
    ResourceAttributes,
    ModelAttributeDependenciesType,
    ModelDataDependenciesType,
)
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.dependency_handler import DependencyHandler
from ofrak.service.resource_service_i import ResourceServiceInterface
from ofrak_type.range import Range


@pytest.fixture
def resource_context():
    return EphemeralResourceContext()


@pytest.fixture
def resource_service(ofrak_context: OFRAKContext) -> ResourceServiceInterface:
    return ofrak_context.resource_service


@pytest.fixture
def data_service(ofrak_context: OFRAKContext) -> DataServiceInterface:
    return ofrak_context.data_service


@pytest.fixture
def dependency_handler(
    resource_context: ResourceContext,
    resource_service: ResourceServiceInterface,
    data_service: DataServiceInterface,
):
    return DependencyHandler(
        resource_service, data_service, ClientComponentContext(), resource_context
    )


COMPONENT_ID = b"mock component"
DEFAULT_ATTRS = Magic("lorem", "ipsum")
DEFAULT_ATTRS_TYPE = type(DEFAULT_ATTRS)


@dataclass
class DependencyInvalidationTestCase:
    label: str
    data_dependency_edges: Iterable[Tuple[bytes, bytes]]
    attribute_dependency_edges: Iterable[Tuple[bytes, bytes]]
    patch_results: List[DataPatchesResult]
    expected_resource_ids_invalidated: Iterable[bytes]
    resource_ids_to_delete: Optional[Iterable[bytes]] = ()

    async def set_up_test_case(
        self,
        resource_context: ResourceContext,
        resource_service: ResourceServiceInterface,
        data_service: DataServiceInterface,
    ):
        models: Dict[bytes, ResourceModel] = dict()
        for dependant_id, depends_on_id in itertools.chain(
            self.data_dependency_edges, self.attribute_dependency_edges
        ):
            if dependant_id not in models:
                models[dependant_id] = ResourceModel.create(dependant_id, data_id=dependant_id)

            if depends_on_id not in models:
                models[depends_on_id] = ResourceModel.create(depends_on_id, data_id=depends_on_id)
            models[dependant_id].attributes.update({DEFAULT_ATTRS_TYPE: DEFAULT_ATTRS})
            models[dependant_id].components_by_attributes.update({Magic: (COMPONENT_ID, 1)})
        for dependant_id, depends_on_id in self.data_dependency_edges:
            dependency = ResourceAttributeDependency(dependant_id, COMPONENT_ID, Magic)
            models[depends_on_id].data_dependencies.update({dependency: {Range(0x10, 0x20)}})
        for dependant_id, depends_on_id in self.attribute_dependency_edges:
            models[depends_on_id].attributes.update({DEFAULT_ATTRS_TYPE: DEFAULT_ATTRS})
            models[depends_on_id].components_by_attributes.update({Magic: (COMPONENT_ID, 1)})
            dependency = ResourceAttributeDependency(dependant_id, COMPONENT_ID, Magic)
            if Magic in models[depends_on_id].attribute_dependencies:
                models[depends_on_id].attribute_dependencies[Magic].add(dependency)
            else:
                models[depends_on_id].attribute_dependencies.update({Magic: {dependency}})

        resource_context.resource_models.update(
            {
                resource_id: MutableResourceModel.from_model(model)
                for resource_id, model in models.items()
            }
        )

        for resource_id, model in models.items():
            await resource_service.create(model)

            if resource_id in self.resource_ids_to_delete:
                await resource_service.delete_resource(resource_id)

        await data_service.create_root(data_id=b"root resource", data=b"e" * 0x20)

    def get_all_ids_with_attributes(self) -> Set[bytes]:
        all_ids = set()
        for dependant_id, depends_on_id in self.data_dependency_edges:
            all_ids.add(dependant_id)
        for dependant_id, depends_on_id in self.attribute_dependency_edges:
            all_ids.add(dependant_id)
            all_ids.add(depends_on_id)

        return all_ids


DEPENDENCY_INVALIDATION_TEST_CASES = [
    DependencyInvalidationTestCase(
        "no data invalidation one level deep",
        ((b"first level dependent", b"root resource"),),
        (),
        [
            DataPatchesResult(
                b"root resource",
                [Range(0x4, 0x8)],
            )
        ],
        (),
    ),
    DependencyInvalidationTestCase(
        "data invalidation one level deep",
        ((b"first level dependent", b"root resource"),),
        (),
        [
            DataPatchesResult(
                b"root resource",
                [Range(0x9, 0x12)],
            )
        ],
        (b"first level dependent",),
    ),
    DependencyInvalidationTestCase(
        "data invalidation causes attribute invalidation",
        ((b"first level dependent", b"root resource"),),
        ((b"second level dependent", b"first level dependent"),),
        [
            DataPatchesResult(
                b"root resource",
                [Range(0x9, 0x12)],
            )
        ],
        (b"first level dependent", b"second level dependent"),
    ),
    DependencyInvalidationTestCase(
        "data invalidation causes attribute invalidation through multiple paths",
        (
            (b"first level dependent A", b"root resource"),
            (b"first level dependent B", b"root resource"),
        ),
        (
            (b"second level dependent", b"first level dependent A"),
            (b"second level dependent", b"first level dependent B"),
        ),
        [
            DataPatchesResult(
                b"root resource",
                [Range(0x9, 0x12)],
            )
        ],
        (b"first level dependent A", b"first level dependent B", b"second level dependent"),
    ),
    DependencyInvalidationTestCase(
        "data invalidation causes attribute invalidation at multiple levels",
        (
            (b"first level dependent", b"root resource"),
            (b"second level dependent", b"root resource"),
        ),
        ((b"second level dependent", b"first level dependent"),),
        [
            DataPatchesResult(
                b"root resource",
                [Range(0x9, 0x12)],
            )
        ],
        (b"first level dependent", b"second level dependent"),
    ),
    DependencyInvalidationTestCase(
        "circular dependency",
        (
            (b"resource1", b"root resource"),
            (b"resource2", b"root resource"),
        ),
        (
            (b"resource1", b"resource2"),
            (b"resource2", b"resource1"),
        ),
        [
            DataPatchesResult(
                b"root resource",
                [Range(0x9, 0x12)],
            )
        ],
        (b"resource1", b"resource2"),
    ),
    DependencyInvalidationTestCase(
        "multi-level circular dependency",
        ((b"resource1", b"root resource"),),
        (
            (b"resource2", b"resource1"),
            (b"resource3", b"resource2"),
            (b"resource1", b"resource3"),
        ),
        [
            DataPatchesResult(
                b"root resource",
                [Range(0x9, 0x12)],
            )
        ],
        (b"resource1", b"resource2", b"resource3"),
    ),
    DependencyInvalidationTestCase(
        "data invalidation causes attribute invalidation through multiple paths, but a dependent "
        "is deleted",
        (
            (b"first level dependent A", b"root resource"),
            (b"first level dependent B", b"root resource"),
        ),
        (
            (b"second level dependent A", b"first level dependent A"),
            (b"second level dependent A", b"first level dependent B"),
            (b"second level dependent B", b"first level dependent B"),
        ),
        [
            DataPatchesResult(
                b"root resource",
                [Range(0x9, 0x12)],
            )
        ],
        (b"first level dependent A", b"first level dependent B", b"second level dependent A"),
        resource_ids_to_delete=(b"second level dependent B",),
    ),
]


@pytest.mark.parametrize("test_case", DEPENDENCY_INVALIDATION_TEST_CASES, ids=lambda tc: tc.label)
async def test_dependency_invalidation(
    dependency_handler: DependencyHandler,
    resource_context: ResourceContext,
    test_case: DependencyInvalidationTestCase,
):
    await test_case.set_up_test_case(
        resource_context, dependency_handler._resource_service, dependency_handler._data_service
    )
    await dependency_handler.handle_post_patch_dependencies(test_case.patch_results)

    resource_ids_with_valid_dependencies = test_case.get_all_ids_with_attributes().difference(
        set(test_case.expected_resource_ids_invalidated)
    )

    for resource_id in resource_ids_with_valid_dependencies:
        resource_m = resource_context.resource_models[resource_id]
        assert Magic in resource_m.attributes, resource_id
        assert Magic in resource_m.components_by_attributes, resource_id

    for resource_id in test_case.expected_resource_ids_invalidated:
        resource_m = resource_context.resource_models[resource_id]
        assert Magic in resource_m.attributes, resource_id
        assert Magic not in resource_m.components_by_attributes, resource_id


@dataclass
class DependencyCreationTestCase:
    label: str
    expected_attributes_dependencies: Dict[bytes, ModelAttributeDependenciesType]
    expected_data_dependencies: Dict[bytes, ModelDataDependenciesType]

    new_attributes: Dict[bytes, Set[ResourceAttributes]] = None
    accessed_attributes: Optional[Dict[bytes, Set[Type[ResourceAttributes]]]] = None
    accessed_data: Optional[Dict[bytes, Set[Range]]] = None
    new_resources: Optional[Set[bytes]] = None

    def set_up_contexts(self, cc: ComponentContext, rc: ResourceContext):
        all_resource_ids = set(self.new_attributes.keys())

        if self.accessed_attributes:
            all_resource_ids.update(self.accessed_attributes.keys())

        if self.accessed_data:
            all_resource_ids.update(self.accessed_data.keys())

        for r_id in all_resource_ids:
            rc.resource_models[r_id] = MutableResourceModel.from_model(ResourceModel.create(r_id))

        for r_id, new_r_attrs in self.new_attributes.items():
            _ = cc.modification_trackers[r_id]  # creates tracker, marks as modified
            resource_m = rc.resource_models[r_id]
            for attrs in new_r_attrs:
                resource_m.add_attributes(attrs)

        if self.accessed_attributes:
            for r_id, accessed_attrs in self.accessed_attributes.items():
                cc.access_trackers[r_id].attributes_accessed.update(accessed_attrs)

        if self.accessed_data:
            for r_id, accessed_data in self.accessed_data.items():
                cc.access_trackers[r_id].data_accessed.update(accessed_data)

        if self.new_resources:
            cc.resources_created.update(self.new_resources)


DEPENDENCY_CREATION_TEST_CASES = [
    DependencyCreationTestCase(
        "simple dependency: resource1 depends on resource2 attrs",
        {
            b"resource2": {
                DEFAULT_ATTRS_TYPE: {
                    ResourceAttributeDependency(b"resource1", COMPONENT_ID, DEFAULT_ATTRS_TYPE)
                }
            }
        },
        {},
        new_attributes={b"resource1": {DEFAULT_ATTRS}},
        accessed_attributes={b"resource2": {DEFAULT_ATTRS_TYPE}},
    ),
    DependencyCreationTestCase(
        "simple dependency: resource1 depends on resource2 data",
        {},
        {
            b"resource2": {
                ResourceAttributeDependency(b"resource1", COMPONENT_ID, DEFAULT_ATTRS_TYPE): {
                    Range(0x10, 0x30),
                }
            }
        },
        new_attributes={b"resource1": {DEFAULT_ATTRS}},
        accessed_data={b"resource2": {Range(0x10, 0x30)}},
    ),
    DependencyCreationTestCase(
        "newly created resources depend on resource2 data",
        {},
        {
            b"root": {
                ResourceAttributeDependency(b"new_r1", COMPONENT_ID, DEFAULT_ATTRS_TYPE): {
                    Range(0x10, 0x30),
                },
                ResourceAttributeDependency(b"new_r2", COMPONENT_ID, DEFAULT_ATTRS_TYPE): {
                    Range(0x10, 0x30),
                },
                ResourceAttributeDependency(b"new_r3", COMPONENT_ID, DEFAULT_ATTRS_TYPE): {
                    Range(0x10, 0x30),
                },
            }
        },
        new_attributes={
            b"new_r1": {DEFAULT_ATTRS},
            b"new_r2": {DEFAULT_ATTRS},
            b"new_r3": {DEFAULT_ATTRS},
        },
        accessed_data={b"root": {Range(0x10, 0x30)}},
        new_resources={b"new_r1", b"new_r2", b"new_r3"},
    ),
    DependencyCreationTestCase(
        "newly created resources don't depend on each other",
        {},
        {},
        new_attributes={b"new_r1": {DEFAULT_ATTRS}, b"new_r2": {DEFAULT_ATTRS}},
        accessed_data={b"new_r1": {Range(0x10, 0x30)}, b"new_r2": {Range(0x10, 0x30)}},
        new_resources={b"new_r1", b"new_r2"},
    ),
]


@pytest.mark.parametrize("test_case", DEPENDENCY_CREATION_TEST_CASES, ids=lambda tc: tc.label)
async def test_dependency_creation(
    dependency_handler: DependencyHandler,
    resource_context: ResourceContext,
    test_case: DependencyCreationTestCase,
):
    test_case.set_up_contexts(dependency_handler._component_context, resource_context)

    dependency_handler.create_resource_dependencies(COMPONENT_ID)

    for (
        r_id,
        expected_attributes_dependencies,
    ) in test_case.expected_attributes_dependencies.items():
        resource_m = resource_context.resource_models[r_id]
        assert expected_attributes_dependencies == resource_m.attribute_dependencies

    for r_id, expected_data_dependencies in test_case.expected_data_dependencies.items():
        resource_m = resource_context.resource_models[r_id]
        assert expected_data_dependencies == resource_m.data_dependencies
