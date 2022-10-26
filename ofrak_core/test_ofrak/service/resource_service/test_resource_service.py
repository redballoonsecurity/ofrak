import random

import pytest

from ofrak.core.addressable import Addressable
from ofrak.core.basic_block import BasicBlock
from ofrak.core.binary import GenericBinary
from ofrak.core.code_region import CodeRegion
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.data import DataWord
from ofrak.core.filesystem import File
from ofrak.core.instruction import Instruction
from ofrak.core.memory_region import MemoryRegion
from ofrak.model.resource_model import (
    ResourceModel,
    ResourceModelDiff,
    ResourceAttributeDependency,
)
from ofrak.service.resource_service_i import (
    ResourceServiceInterface,
    ResourceFilter,
    ResourceFilterCondition,
    ResourceAttributeValueFilter,
    ResourceAttributeValuesFilter,
    ResourceAttributeRangeFilter,
    ResourceSort,
    ResourceSortDirection,
)
from ofrak_type.error import AlreadyExistError, NotFoundError
from ofrak_type.range import Range
from test_ofrak.service.conftest import (
    R_ID_3_1_1_1_1,
    R_ID_3_1_1_1,
    R_ID_3_1_1,
    R_ID_3_1,
    R_ID_3_ROOT,
    TestIndexAttributes,
    R_ID_3_1_2,
    R_ID_3_1_3,
    R_ID_3_1_1_1_2,
    R_ID_3_1_1_1_3,
    TestNestedIndexAttributes,
    R_ID_2_1,
    R_ID_1_3,
    R_ID_1_ROOT,
    R_ID_2_ROOT,
    R_ID_1_1,
    R_ID_2_1_1_1_1,
)
from test_ofrak.service.resource_service.conftest import (
    GetAncestorsTestCase,
    GetDescendantsTestCase,
    GetDescendantsTestCaseMultipleResults,
    GetDescendantsTestCaseOrderedResults,
)


class TestResourceService:
    async def test_create(self, resource_service, tree1_resource_models, tree2_resource_models):
        # Can creates resources normally
        for model in tree1_resource_models:
            created = await resource_service.create(model)
            assert created == model

        # Cannot create same resource twice
        for model in tree1_resource_models:
            stored = await resource_service.get_by_id(model.id)
            assert stored == model
            with pytest.raises(AlreadyExistError):
                await resource_service.create(model)

        # Cannot create resource with missing parent
        for model in tree2_resource_models:
            if model.id is R_ID_2_ROOT:
                continue

            with pytest.raises(NotFoundError):
                await resource_service.create(model)

        # Can create a resource with data ID
        model = tree2_resource_models[0]
        model.data_id = b"\xDD\x01"
        await resource_service.create(model)

        # Can create a resource with tags
        model = tree2_resource_models[1]
        model.tags.add(Addressable)
        await resource_service.create(model)

        # Can create a resource with indexable attributes
        model = tree2_resource_models[2]
        model.attributes[Addressable.attributes_type] = Addressable.attributes_type(0x100)
        await resource_service.create(model)

    async def test_get_by_data_ids(self, resource_service, tree1_resource_models):
        resources_by_data_id = {bytes(i): model for i, model in enumerate(tree1_resource_models)}

        for i, model in resources_by_data_id.items():
            model.data_id = bytes(i)
            await resource_service.create(model)

        data_id_sequence = list(resources_by_data_id.keys())
        random.shuffle(data_id_sequence)
        for i, got_model in enumerate(await resource_service.get_by_data_ids(data_id_sequence)):
            assert got_model.data_id == data_id_sequence[i]
            assert got_model == resources_by_data_id[got_model.data_id]

        # All data IDs are missing
        with pytest.raises(NotFoundError):
            await resource_service.get_by_data_ids([b"\xFF"])

        # Just one data ID is missing
        with pytest.raises(NotFoundError):
            await resource_service.get_by_data_ids(data_id_sequence + [b"\xFF"])

        assert await resource_service.get_by_data_ids([]) == []

    async def test_get_by_ids(
        self, basic_populated_resource_service: ResourceServiceInterface, tree1_resource_models
    ):
        # tree1_resource_models -> depth = 0
        resources_by_id = {model.id: model for model in tree1_resource_models}

        r_id_sequence = list(resources_by_id.keys())
        random.shuffle(r_id_sequence)
        for i, got_model in enumerate(
            await basic_populated_resource_service.get_by_ids(r_id_sequence)
        ):
            assert got_model.id == r_id_sequence[i]
            assert got_model == resources_by_id[got_model.id]

        # All resource IDs are missing
        with pytest.raises(NotFoundError):
            await basic_populated_resource_service.get_by_ids([b"\xFF"])

        # Just one resource ID is missing
        with pytest.raises(NotFoundError):
            await basic_populated_resource_service.get_by_ids(r_id_sequence + [b"\xFF"])

        assert await basic_populated_resource_service.get_by_ids([]) == []

    async def test_get_by_id(
        self, basic_populated_resource_service: ResourceServiceInterface, tree1_resource_models
    ):
        for model in tree1_resource_models:
            got_model = await basic_populated_resource_service.get_by_id(model.id)
            assert got_model == model

    async def test_get_depths(
        self, populated_resource_service: ResourceServiceInterface, tree3_resource_models
    ):
        expected_depths_dict = {}
        for model in tree3_resource_models:
            if model.parent_id in expected_depths_dict.keys():
                expected_depths_dict[model.id] = expected_depths_dict[model.parent_id] + 1
            else:
                expected_depths_dict[model.id] = 0
        model_ids = [model.id for model in tree3_resource_models]
        expected_depths = [expected_depths_dict[model_id] for model_id in model_ids]
        got_depths = await populated_resource_service.get_depths(model_ids)
        assert got_depths == expected_depths

        # All resource IDs are missing
        with pytest.raises(NotFoundError):
            await populated_resource_service.get_depths([b"\xFF"])

        # Just one resource ID is missing
        with pytest.raises(NotFoundError):
            await populated_resource_service.get_depths(model_ids + [b"\xFF"])

        assert await populated_resource_service.get_depths([]) == []

    GET_ANCESTORS_TEST_CASES = [
        GetAncestorsTestCase(
            "simple",
            R_ID_3_1_1_1_1,
            [R_ID_3_1_1_1, R_ID_3_1_1, R_ID_3_1, R_ID_3_ROOT],
        ),
        GetAncestorsTestCase(
            "max count",
            R_ID_3_1_1_1_1,
            [R_ID_3_1_1_1, R_ID_3_1_1],
            max_count=2,
        ),
        GetAncestorsTestCase(
            "tags filter: single tag",
            R_ID_3_1_1_1_1,
            [R_ID_3_1_1_1_1, R_ID_3_1_1_1, R_ID_3_1_1, R_ID_3_1],
            r_filter=ResourceFilter(
                include_self=True,
                tags=(MemoryRegion,),
                attribute_filters=None,
            ),
        ),
        GetAncestorsTestCase(
            "tags filter: OR",
            R_ID_3_1_1_1_1,
            [R_ID_3_1_1_1, R_ID_3_1_1],
            r_filter=ResourceFilter(
                include_self=True,
                tags=(ComplexBlock, BasicBlock),
                tags_condition=ResourceFilterCondition.OR,
                attribute_filters=None,
            ),
        ),
        GetAncestorsTestCase(
            "tags filter: AND",
            R_ID_3_1_1_1_1,
            [R_ID_3_ROOT],
            r_filter=ResourceFilter(
                include_self=True,
                tags=(File, GenericBinary),
                tags_condition=ResourceFilterCondition.AND,
                attribute_filters=None,
            ),
        ),
        GetAncestorsTestCase(
            "attributes filter: exact value",
            R_ID_3_1_1_1_1,
            [R_ID_3_1_1],
            r_filter=ResourceFilter(
                include_self=True,
                attribute_filters=(ResourceAttributeValueFilter(TestIndexAttributes.TestIndex, 4),),
            ),
        ),
        GetAncestorsTestCase(
            "attributes filter: multiple exact values",
            R_ID_3_1_1_1_1,
            [R_ID_3_1_1_1, R_ID_3_1_1, R_ID_3_ROOT],
            r_filter=ResourceFilter(
                include_self=True,
                attribute_filters=(
                    ResourceAttributeValuesFilter(
                        TestIndexAttributes.TestIndex,
                        (4, 2, 5),
                    ),
                ),
            ),
        ),
        GetAncestorsTestCase(
            "attributes filter: value range",
            R_ID_3_1_1_1_1,
            [R_ID_3_1_1_1, R_ID_3_1],
            r_filter=ResourceFilter(
                include_self=True,
                attribute_filters=(
                    ResourceAttributeRangeFilter(
                        TestIndexAttributes.TestIndex,
                        2,
                        4,
                    ),
                ),
            ),
        ),
    ]

    @pytest.mark.parametrize("test_case", GET_ANCESTORS_TEST_CASES, ids=lambda tc: tc.label)
    async def test_get_ancestors_by_id(
        self, populated_resource_service: ResourceServiceInterface, test_case: GetAncestorsTestCase
    ):
        results = list(
            await populated_resource_service.get_ancestors_by_id(
                test_case.resource_id,
                test_case.max_count,
                test_case.r_filter,
            )
        )
        assert len(results) == len(test_case.expected_results)
        for got_model, expected_model in zip(results, test_case.expected_results):
            assert got_model.id == expected_model

    GET_DESCENDANTS_TEST_CASES = [
        GetDescendantsTestCase(
            "simple",
            R_ID_3_ROOT,
            [
                R_ID_3_1_1_1,
                R_ID_3_1_1,
                R_ID_3_1_2,
                R_ID_3_1_3,
                R_ID_3_1,
                R_ID_3_1_1_1_1,
                R_ID_3_1_1_1_2,
                R_ID_3_1_1_1_3,
            ],
        ),
        GetDescendantsTestCaseMultipleResults(
            "max count",
            R_ID_3_1_1_1,
            [
                [R_ID_3_1_1_1_1, R_ID_3_1_1_1_2],
                [R_ID_3_1_1_1_3, R_ID_3_1_1_1_2],
                [R_ID_3_1_1_1_1, R_ID_3_1_1_1_3],
            ],
            max_count=2,
        ),
        GetDescendantsTestCase(
            "max depth",
            R_ID_3_ROOT,
            [R_ID_3_1, R_ID_3_1_1, R_ID_3_1_2, R_ID_3_1_3, R_ID_3_1_1_1],
            max_depth=3,
        ),
        GetDescendantsTestCaseMultipleResults(
            "max count and max depth",
            R_ID_3_ROOT,
            [
                [R_ID_3_1, R_ID_3_1_1, R_ID_3_1_2, R_ID_3_1_3],
                [R_ID_3_1, R_ID_3_1_1, R_ID_3_1_2, R_ID_3_1_1_1],
                [R_ID_3_1, R_ID_3_1_1, R_ID_3_1_3, R_ID_3_1_1_1],
                [R_ID_3_1, R_ID_3_1_2, R_ID_3_1_3, R_ID_3_1_1_1],
                [R_ID_3_1_1, R_ID_3_1_2, R_ID_3_1_3, R_ID_3_1_1_1],
            ],
            max_count=4,
            max_depth=3,
        ),
        GetDescendantsTestCase(
            "tags filter: single tag (tag filter cheapest)",
            R_ID_3_ROOT,
            [R_ID_3_1_1, R_ID_3_1_2, R_ID_3_1_3],
            r_filter=ResourceFilter(
                include_self=True,
                tags=(ComplexBlock,),
                attribute_filters=None,
            ),
        ),
        GetDescendantsTestCase(
            "tags filter: single tag (ancestor filter cheapest)",
            R_ID_3_ROOT,
            [R_ID_3_1_1, R_ID_3_1_2, R_ID_3_1_3],
            r_filter=ResourceFilter(
                include_self=True,
                tags=(ComplexBlock,),
                attribute_filters=None,
            ),
            extra_resources=[((ComplexBlock,), ())] * 10,
        ),
        GetDescendantsTestCase(
            "tags filter: OR (tag filter cheapest)",
            R_ID_3_ROOT,
            [R_ID_3_1, R_ID_3_1_1_1_1, R_ID_3_1_1_1_2, R_ID_3_1_1_1_3],
            r_filter=ResourceFilter(
                include_self=True,
                tags=(CodeRegion, Instruction),
                tags_condition=ResourceFilterCondition.OR,
                attribute_filters=None,
            ),
        ),
        GetDescendantsTestCase(
            "tags filter: OR (ancestor filter cheapest)",
            R_ID_3_ROOT,
            [R_ID_3_1, R_ID_3_1_1_1_1, R_ID_3_1_1_1_2, R_ID_3_1_1_1_3],
            r_filter=ResourceFilter(
                include_self=True,
                tags=(CodeRegion, Instruction),
                tags_condition=ResourceFilterCondition.OR,
                attribute_filters=None,
            ),
            extra_resources=([((CodeRegion,), ())] * 10) + ([((Instruction,), ())] * 10),
        ),
        GetDescendantsTestCase(
            "tags filter: AND (tag filter cheapest)",
            R_ID_3_ROOT,
            [R_ID_3_ROOT],
            r_filter=ResourceFilter(
                include_self=True,
                tags=(File, GenericBinary),
                tags_condition=ResourceFilterCondition.AND,
                attribute_filters=None,
            ),
        ),
        GetDescendantsTestCase(
            "tags filter: AND (ancestor filter cheapest)",
            R_ID_3_ROOT,
            [R_ID_3_ROOT],
            r_filter=ResourceFilter(
                include_self=True,
                tags=(File, GenericBinary),
                tags_condition=ResourceFilterCondition.AND,
                attribute_filters=None,
            ),
            extra_resources=[((File, GenericBinary), ())] * 10,
        ),
        GetDescendantsTestCase(
            "attributes filter: exact value (attributes filter cheapest)",
            R_ID_3_ROOT,
            [R_ID_3_1_1, R_ID_3_1_2],
            r_filter=ResourceFilter(
                include_self=True,
                attribute_filters=(ResourceAttributeValueFilter(TestIndexAttributes.TestIndex, 4),),
            ),
        ),
        GetDescendantsTestCase(
            "attributes filter: exact value (ancestor filter cheapest)",
            R_ID_3_ROOT,
            [R_ID_3_1_1, R_ID_3_1_2],
            r_filter=ResourceFilter(
                include_self=True,
                attribute_filters=(ResourceAttributeValueFilter(TestIndexAttributes.TestIndex, 4),),
            ),
            extra_resources=[((), (TestIndexAttributes(8),))] * 10,
        ),
        GetDescendantsTestCase(
            "attributes filter: multiple exact values (attributes filter cheapest)",
            R_ID_3_ROOT,
            [R_ID_3_1_1, R_ID_3_1_2, R_ID_3_1_1_1, R_ID_3_ROOT],
            r_filter=ResourceFilter(
                include_self=True,
                attribute_filters=(
                    ResourceAttributeValuesFilter(
                        TestIndexAttributes.TestIndex,
                        (4, 2, 5),
                    ),
                ),
            ),
        ),
        GetDescendantsTestCase(
            "attributes filter: multiple exact values (ancestor filter cheapest)",
            R_ID_3_ROOT,
            [R_ID_3_1_1, R_ID_3_1_2, R_ID_3_1_1_1, R_ID_3_ROOT],
            r_filter=ResourceFilter(
                include_self=True,
                attribute_filters=(
                    ResourceAttributeValuesFilter(
                        TestIndexAttributes.TestIndex,
                        (4, 2, 5),
                    ),
                ),
            ),
            extra_resources=[((), (TestIndexAttributes(2),))] * 20,
        ),
        GetDescendantsTestCase(
            "attributes filter: value range (attributes filter cheapest)",
            R_ID_3_ROOT,
            [R_ID_3_1_1_1, R_ID_3_1],
            r_filter=ResourceFilter(
                include_self=True,
                attribute_filters=(
                    ResourceAttributeRangeFilter(
                        TestIndexAttributes.TestIndex,
                        2,
                        4,
                    ),
                ),
            ),
        ),
        GetDescendantsTestCase(
            "attributes filter: value range (ancestor filter cheapest)",
            R_ID_3_ROOT,
            [R_ID_3_1_1_1, R_ID_3_1],
            r_filter=ResourceFilter(
                include_self=True,
                attribute_filters=(
                    ResourceAttributeRangeFilter(
                        TestIndexAttributes.TestIndex,
                        2,
                        4,
                    ),
                ),
            ),
            extra_resources=[((), (TestIndexAttributes(3),))] * 10,
        ),
        GetDescendantsTestCase(
            "attributes filter: value range, no max (ancestor filter cheapest)",
            R_ID_3_ROOT,
            [R_ID_3_1_1_1, R_ID_3_1, R_ID_3_1_1, R_ID_3_1_2, R_ID_3_ROOT, R_ID_3_1_3],
            r_filter=ResourceFilter(
                include_self=True,
                attribute_filters=(
                    ResourceAttributeRangeFilter(
                        TestIndexAttributes.TestIndex,
                        min=2,
                    ),
                ),
            ),
            extra_resources=[((), (TestIndexAttributes(3),))] * 10,
        ),
        GetDescendantsTestCase(
            "attributes filter: value range, no min (ancestor filter cheapest)",
            R_ID_3_ROOT,
            [R_ID_3_1_1_1_1, R_ID_3_1_1_1, R_ID_3_1],
            r_filter=ResourceFilter(
                include_self=True,
                attribute_filters=(
                    ResourceAttributeRangeFilter(
                        TestIndexAttributes.TestIndex,
                        max=4,
                    ),
                ),
            ),
            extra_resources=[((), (TestIndexAttributes(3),))] * 10,
        ),
        GetDescendantsTestCase(
            "resource filter: 0 cost filter (no resources with attribute)",
            R_ID_3_ROOT,
            [],
            r_filter=ResourceFilter(
                attribute_filters=(ResourceAttributeRangeFilter(Addressable.VirtualAddress, min=0),)
            ),
        ),
        GetDescendantsTestCase(
            "resource filter: 0 cost filter (no resources with value)",
            R_ID_3_ROOT,
            [],
            r_filter=ResourceFilter(
                attribute_filters=(ResourceAttributeValueFilter(TestIndexAttributes.TestIndex, 0),)
            ),
        ),
        GetDescendantsTestCaseOrderedResults(
            "resource sort: ascendant",
            R_ID_3_ROOT,
            [
                [R_ID_3_1_3],  # 9
                [R_ID_3_ROOT],  # 5
                [R_ID_3_1_1, R_ID_3_1_2],  # 4
                [R_ID_3_1],  # 3
                [R_ID_3_1_1_1],  # 2
                [R_ID_3_1_1_1_1],  # 1
            ],
            r_filter=ResourceFilter(include_self=True),
            r_sort=ResourceSort(
                TestIndexAttributes.TestIndex,
                ResourceSortDirection.DESCENDANT,
            ),
        ),
        GetDescendantsTestCaseOrderedResults(
            "resource sort: descendant",
            R_ID_3_ROOT,
            [
                [R_ID_3_1_1_1_1],  # 1
                [R_ID_3_1_1_1],  # 2
                [R_ID_3_1],  # 3
                [R_ID_3_1_1, R_ID_3_1_2],  # 4
                [R_ID_3_ROOT],  # 5
                [R_ID_3_1_3],  # 9
            ],
            r_filter=ResourceFilter(include_self=True),
            r_sort=ResourceSort(
                TestIndexAttributes.TestIndex,
                ResourceSortDirection.ASCENDANT,
            ),
        ),
        GetDescendantsTestCaseOrderedResults(
            "resource sort: sort and filter differ",
            R_ID_3_ROOT,
            [
                [R_ID_3_1_1_1_1],  # 1
                [R_ID_3_1_1_1],  # 2
                [R_ID_3_1_2],  # 4
            ],
            r_filter=ResourceFilter(
                include_self=True,
                attribute_filters=(ResourceAttributeRangeFilter(MemoryRegion.Size, 4, 64),),
            ),
            r_sort=ResourceSort(
                TestIndexAttributes.TestIndex,
            ),
        ),
        GetDescendantsTestCaseOrderedResults(
            "resource sort: sort and filter are the same",
            R_ID_3_ROOT,
            [
                [R_ID_3_1_1_1],  # 2
                [R_ID_3_1],  # 3
            ],
            r_filter=ResourceFilter(
                include_self=True,
                attribute_filters=(
                    ResourceAttributeRangeFilter(
                        TestIndexAttributes.TestIndex,
                        2,
                        4,
                    ),
                ),
            ),
            r_sort=ResourceSort(
                TestIndexAttributes.TestIndex,
            ),
        ),
        GetDescendantsTestCase(
            "resource sort: 0 cost sort",
            R_ID_3_ROOT,
            [],
            r_sort=ResourceSort(
                Addressable.VirtualAddress,
            ),
        ),
        GetDescendantsTestCaseOrderedResults(
            "resource sort: sort by nested index",
            R_ID_3_ROOT,
            [
                [R_ID_3_1_3],  # 5
                [R_ID_3_1_1_1],  # 6
                [R_ID_3_1_1_1_1],  # 7
                [R_ID_3_1_2],  # 8
            ],
            r_filter=ResourceFilter(
                include_self=True,
                attribute_filters=(
                    ResourceAttributeRangeFilter(
                        TestNestedIndexAttributes.TestNestedIndex,
                        min=2,
                    ),
                ),
            ),
            r_sort=ResourceSort(
                TestNestedIndexAttributes.TestNestedIndex,
            ),
        ),
    ]

    @pytest.mark.parametrize("test_case", GET_DESCENDANTS_TEST_CASES, ids=lambda tc: tc.label)
    async def test_get_descendants_by_id(
        self,
        populated_resource_service: ResourceServiceInterface,
        test_case: GetDescendantsTestCase,
    ):
        await test_case.initialize(populated_resource_service)
        results = list(
            await populated_resource_service.get_descendants_by_id(
                test_case.resource_id,
                test_case.max_count,
                test_case.max_depth,
                test_case.r_filter,
                test_case.r_sort,
            )
        )
        test_case.check_results(results)

    @pytest.mark.skip
    async def test_get_siblings_by_id(self, resource_service):
        # TODO: Implement test
        # Not done with the others because it is a special case of get_descendants_by_id
        pass

    async def test_update(self, populated_resource_service: ResourceServiceInterface):
        # Update nonexistant resource
        with pytest.raises(NotFoundError):
            await populated_resource_service.update(ResourceModelDiff(b"\xFF"))
        # Test we can add non-indexing resource model fields
        dependency = ResourceAttributeDependency(
            b"\xFF", b"dummy_component", MemoryRegion.attributes_type
        )
        new_data_dependencies = {(dependency, Range(0, 10))}
        new_attribute_dependencies = {(Addressable.attributes_type, dependency)}
        new_component_versions = {(b"dummy_component", 1)}
        new_attributes_components = {(Addressable.attributes_type, b"dummy_component", 1)}
        simple_addition_diff = ResourceModelDiff(
            id=R_ID_3_1,
            data_dependencies_added=new_data_dependencies,
            attribute_dependencies_added=new_attribute_dependencies,
            component_versions_added=new_component_versions,
            attributes_component_added=new_attributes_components,
        )
        new_model = await populated_resource_service.update(simple_addition_diff)
        assert new_model.data_dependencies[dependency] == {Range(0, 10)}
        assert new_model.attribute_dependencies[Addressable.attributes_type] == {dependency}
        assert new_model.component_versions.get(b"dummy_component") == 1
        assert (
            new_model.components_by_attributes.get(Addressable.attributes_type)[0]
            == b"dummy_component"
        )

        assert (await populated_resource_service.get_by_id(R_ID_3_1)) == new_model

        old_model = new_model

        # Updating is idempotent
        new_model = await populated_resource_service.update(simple_addition_diff)
        assert old_model == new_model

        # Test we can remove non-indexing resource model fields
        simple_removal_diff = ResourceModelDiff(
            id=R_ID_3_1,
            data_dependencies_removed={dependency},
            component_versions_removed={b"dummy_component"},
        )
        new_model = await populated_resource_service.update(simple_removal_diff)
        assert new_model != old_model
        assert new_model.data_dependencies[dependency] == set()
        assert new_model.attribute_dependencies[Addressable.attributes_type] == {dependency}
        assert new_model.component_versions.get(b"dummy_component") is None
        assert (
            new_model.components_by_attributes.get(Addressable.attributes_type)[0]
            == b"dummy_component"
        )

        # Test we can update tags, and get different results for the same query
        initial_instruction_results = list(
            await populated_resource_service.get_descendants_by_id(
                R_ID_3_1_1_1, r_filter=ResourceFilter.with_tags(Instruction)
            )
        )
        initial_data_word_results = list(
            await populated_resource_service.get_descendants_by_id(
                R_ID_3_1_1_1, r_filter=ResourceFilter.with_tags(DataWord)
            )
        )
        new_model = await populated_resource_service.update(
            ResourceModelDiff(
                R_ID_3_1_1_1_1,
                tags_removed={Instruction},
                tags_added={DataWord},
            )
        )
        assert Instruction not in new_model.tags
        assert DataWord in new_model.tags
        instruction_results = list(
            await populated_resource_service.get_descendants_by_id(
                R_ID_3_1_1_1, r_filter=ResourceFilter.with_tags(Instruction)
            )
        )
        data_word_results = list(
            await populated_resource_service.get_descendants_by_id(
                R_ID_3_1_1_1, r_filter=ResourceFilter.with_tags(DataWord)
            )
        )
        assert instruction_results != initial_instruction_results
        assert data_word_results != initial_data_word_results

        assert len(data_word_results) == 1
        assert data_word_results[0].id == R_ID_3_1_1_1_1

        # Test we can update attributes, and get different results for the same query
        initial_elf_index_results = list(
            await populated_resource_service.get_descendants_by_id(
                R_ID_3_1_1,
                r_filter=ResourceFilter(
                    include_self=True,
                    attribute_filters=(
                        ResourceAttributeRangeFilter(TestIndexAttributes.TestIndex, 1, 4),
                    ),
                ),
            )
        )
        new_model = await populated_resource_service.update(
            ResourceModelDiff(
                R_ID_3_1_1,
                attributes_removed={TestIndexAttributes},
                attributes_added={TestIndexAttributes: TestIndexAttributes(3)},
            )
        )
        assert new_model.attributes[TestIndexAttributes].val == 3
        elf_index_results = list(
            await populated_resource_service.get_descendants_by_id(
                R_ID_3_1_1,
                r_filter=ResourceFilter(
                    include_self=True,
                    attribute_filters=(
                        ResourceAttributeRangeFilter(TestIndexAttributes.TestIndex, 1, 4),
                    ),
                ),
            )
        )
        assert elf_index_results != initial_elf_index_results
        assert len(elf_index_results) == 3
        assert {model.id for model in elf_index_results} == {
            R_ID_3_1_1,
            R_ID_3_1_1_1,
            R_ID_3_1_1_1_1,
        }

    async def test_rebase_resource(
        self, basic_populated_resource_service: ResourceServiceInterface, tree2_resource_models
    ):
        for model in tree2_resource_models:
            await basic_populated_resource_service.create(model)

        # rebase from one tree to another
        await basic_populated_resource_service.rebase_resource(
            R_ID_2_1,
            R_ID_1_3,
        )

        new_model = await basic_populated_resource_service.get_by_id(R_ID_2_1)
        assert new_model.parent_id == R_ID_1_3

        new_ancestors = list(
            model.id
            for model in await basic_populated_resource_service.get_ancestors_by_id(R_ID_2_1)
        )
        assert new_ancestors[-2:] == [R_ID_1_3, R_ID_1_ROOT]

        new_ancestors_of_leaf = list(
            model.id
            for model in await basic_populated_resource_service.get_ancestors_by_id(R_ID_2_1_1_1_1)
        )
        assert new_ancestors_of_leaf[-2:] == [R_ID_1_3, R_ID_1_ROOT]

        # rebase root node
        await basic_populated_resource_service.rebase_resource(
            R_ID_2_ROOT,
            R_ID_1_1,
        )
        new_model = await basic_populated_resource_service.get_by_id(R_ID_2_ROOT)
        assert new_model.parent_id == R_ID_1_1
        new_ancestors = list(
            model.id
            for model in await basic_populated_resource_service.get_ancestors_by_id(R_ID_2_ROOT)
        )
        assert new_ancestors[-2:] == [R_ID_1_1, R_ID_1_ROOT]

        # rebasing nonexistant node
        with pytest.raises(NotFoundError):
            await basic_populated_resource_service.rebase_resource(
                b"\xFF",
                R_ID_1_1,
            )

        # rebasing to nonexistant node
        with pytest.raises(NotFoundError):
            await basic_populated_resource_service.rebase_resource(
                R_ID_1_1,
                b"\xFF",
            )

    async def test_delete_resource(self, populated_resource_service: ResourceServiceInterface):
        # delete leaf
        await populated_resource_service.delete_resource(R_ID_3_1_1_1_2)
        with pytest.raises(NotFoundError):
            await populated_resource_service.get_by_id(R_ID_3_1_1_1_2)

        # delete internal node
        await populated_resource_service.delete_resource(R_ID_3_1_1_1)
        with pytest.raises(NotFoundError):
            await populated_resource_service.get_by_id(R_ID_3_1_1_1)
        with pytest.raises(NotFoundError):
            await populated_resource_service.get_by_id(R_ID_3_1_1_1_1)
        with pytest.raises(NotFoundError):
            await populated_resource_service.get_by_id(R_ID_3_1_1_1_2)
        with pytest.raises(NotFoundError):
            await populated_resource_service.get_by_id(R_ID_3_1_1_1_3)

        # double delete doesn't raise
        await populated_resource_service.delete_resource(R_ID_3_1_1_1_2)

        # delete data id from resource service lookup by data id
        r_with_data_id = ResourceModel.create(
            b"\xFF",
            b"\xFF",
        )
        await populated_resource_service.create(r_with_data_id)
        assert r_with_data_id == await populated_resource_service.get_by_id(b"\xFF")
        await populated_resource_service.delete_resource(b"\xFF")
        with pytest.raises(NotFoundError):
            await populated_resource_service.get_by_id(b"\xFF")

    async def test_verify_ids_exist(self, populated_resource_service: ResourceServiceInterface):
        # delete a leaf and internal node
        await populated_resource_service.delete_resource(R_ID_3_1_1_1_2)
        await populated_resource_service.delete_resource(R_ID_3_1_1_1)

        id_verification = await populated_resource_service.verify_ids_exist(
            [
                R_ID_3_1_1_1_2,  # deleted
                R_ID_3_1_1_1,  # deleted
                R_ID_3_1_1,
                R_ID_3_1,
                R_ID_3_1_1_1_1,  # deleted
                R_ID_3_1_1_1_2,  # deleted
                R_ID_3_1_1_1_3,  # deleted
            ]
        )

        assert [False, False, True, True, False, False, False] == list(id_verification)

        assert await populated_resource_service.verify_ids_exist([]) == []

    async def test_nested_indexes(self, populated_resource_service):
        """
        Granular test of the get_value for nested indexes which is needed for the resource service
        :param populated_resource_service:
        :return:
        """
        m = ResourceModel(
            b"",
            attributes={
                TestIndexAttributes: TestIndexAttributes(4),
                TestNestedIndexAttributes: TestNestedIndexAttributes(5),
            },
        )

        assert 9 == TestNestedIndexAttributes.TestNestedIndex.get_value(m)

        m2 = ResourceModel(
            b"",
            attributes={
                TestNestedIndexAttributes: TestNestedIndexAttributes(5),
            },
        )

        # Check that if we can't calculate the index value, it is simply returned as None (as it is
        # for non-nested indexes)
        assert TestNestedIndexAttributes.TestNestedIndex.get_value(m2) is None

    async def test_get_root_resources(self, triple_populated_resource_service):
        roots = {
            model.id: model
            for model in await triple_populated_resource_service.get_root_resources()
        }

        expected_root_models = {
            R_ID_1_ROOT: ResourceModel(R_ID_1_ROOT),
            R_ID_2_ROOT: ResourceModel(R_ID_2_ROOT),
            R_ID_3_ROOT: ResourceModel.create(
                R_ID_3_ROOT, tags=(File, GenericBinary), attributes=(TestIndexAttributes(5),)
            ),
        }

        assert 3 == len(roots)
        assert expected_root_models[R_ID_1_ROOT] == roots[R_ID_1_ROOT]
        assert expected_root_models[R_ID_2_ROOT] == roots[R_ID_2_ROOT]
        assert expected_root_models[R_ID_3_ROOT] == roots[R_ID_3_ROOT]
