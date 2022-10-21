from dataclasses import dataclass
from itertools import chain
from typing import List

import pytest

from ofrak import ResourceModel, ResourceAttributes
from ofrak.core import (
    File,
    GenericBinary,
    MemoryRegion,
    CodeRegion,
    ComplexBlock,
    BasicBlock,
    Instruction,
)
from ofrak.model.resource_model import index
from ofrak.service.resource_service import ResourceService
from ofrak.service.resource_service_i import ResourceServiceInterface


@dataclass
class TestIndexAttributes(ResourceAttributes):
    # Not a pytest test class
    __test__ = False

    val: int

    @index
    def TestIndex(self) -> int:
        return self.val


@dataclass
class TestNestedIndexAttributes(ResourceAttributes):
    # Not a pytest test class
    __test__ = False

    val: int

    @index(nested_indexes=(TestIndexAttributes.TestIndex,))
    def TestNestedIndex(self) -> int:
        return self.val + self.TestIndex


R_ID_1_ROOT = b"\x01"
R_ID_1_1 = b"\x01\x01"
R_ID_1_2 = b"\x01\x02"
R_ID_1_3 = b"\x01\x03"
R_ID_1_4 = b"\x01\x04"
R_ID_1_2_1 = b"\x01\x02\x01"
R_ID_1_2_2 = b"\x01\x02\x02"
R_ID_1_2_3 = b"\x01\x02\x03"

R_ID_2_ROOT = b"\x02"
R_ID_2_1 = b"\x02\x01"
R_ID_2_1_1 = b"\x02\x01\x01"
R_ID_2_1_1_1 = b"\x02\x01\x01\x01"
R_ID_2_1_1_1_1 = b"\x02\x01\x01\x01\x01"

R_ID_3_ROOT = b"\x03"
R_ID_3_1 = b"\x03\x01"
R_ID_3_1_1 = b"\x03\x01\x01"
R_ID_3_1_2 = b"\x03\x01\x02"
R_ID_3_1_3 = b"\x03\x01\x03"
R_ID_3_1_1_1 = b"\x03\x01\x01\x01"
R_ID_3_1_1_1_1 = b"\x03\x01\x01\x01\x01"
R_ID_3_1_1_1_2 = b"\x03\x01\x01\x01\x02"
R_ID_3_1_1_1_3 = b"\x03\x01\x01\x01\x03"


@pytest.fixture
def resource_service() -> ResourceServiceInterface:
    return ResourceService()


@pytest.fixture
def tree1_resource_models() -> List[ResourceModel]:
    return [
        ResourceModel(R_ID_1_ROOT),
        ResourceModel(R_ID_1_1, parent_id=R_ID_1_ROOT),
        ResourceModel(R_ID_1_2, parent_id=R_ID_1_ROOT),
        ResourceModel(R_ID_1_3, parent_id=R_ID_1_ROOT),
        ResourceModel(R_ID_1_4, parent_id=R_ID_1_ROOT),
        ResourceModel(R_ID_1_2_1, parent_id=R_ID_1_2),
        ResourceModel(R_ID_1_2_2, parent_id=R_ID_1_2),
        ResourceModel(R_ID_1_2_3, parent_id=R_ID_1_2),
    ]


@pytest.fixture
def tree2_resource_models() -> List[ResourceModel]:
    return [
        ResourceModel(R_ID_2_ROOT),
        ResourceModel(R_ID_2_1, parent_id=R_ID_2_ROOT),
        ResourceModel(R_ID_2_1_1, parent_id=R_ID_2_1),
        ResourceModel(R_ID_2_1_1_1, parent_id=R_ID_2_1_1),
        ResourceModel(R_ID_2_1_1_1_1, parent_id=R_ID_2_1_1_1),
    ]


@pytest.fixture
def tree3_resource_models() -> List[ResourceModel]:
    # Elf indexes are arbitrary, just to create some indexable value
    return [
        ResourceModel.create(
            R_ID_3_ROOT, tags=(File, GenericBinary), attributes=(TestIndexAttributes(5),)
        ),
        ResourceModel.create(
            R_ID_3_1,
            parent_id=R_ID_3_ROOT,
            tags=(CodeRegion,),
            attributes=(TestIndexAttributes(3), MemoryRegion.attributes_type(1024)),
        ),
        ResourceModel.create(
            R_ID_3_1_1,
            parent_id=R_ID_3_1,
            tags=(ComplexBlock,),
            attributes=(TestIndexAttributes(4), MemoryRegion.attributes_type(64)),
        ),
        ResourceModel.create(
            R_ID_3_1_1_1,
            parent_id=R_ID_3_1_1,
            tags=(BasicBlock,),
            attributes=(
                TestIndexAttributes(2),
                MemoryRegion.attributes_type(16),
                TestNestedIndexAttributes(4),
            ),
        ),
        ResourceModel.create(
            R_ID_3_1_1_1_1,
            parent_id=R_ID_3_1_1_1,
            tags=(Instruction,),
            attributes=(
                TestIndexAttributes(1),
                MemoryRegion.attributes_type(4),
                TestNestedIndexAttributes(6),
            ),
        ),
        ResourceModel.create(
            R_ID_3_1_1_1_2,
            parent_id=R_ID_3_1_1_1,
            tags=(Instruction,),
        ),
        ResourceModel.create(
            R_ID_3_1_1_1_3,
            parent_id=R_ID_3_1_1_1,
            tags=(Instruction,),
        ),
        ResourceModel.create(
            R_ID_3_1_2,
            parent_id=R_ID_3_1,
            tags=(ComplexBlock,),
            attributes=(
                TestIndexAttributes(4),
                MemoryRegion.attributes_type(32),
                TestNestedIndexAttributes(4),
            ),
        ),
        ResourceModel.create(
            R_ID_3_1_3,
            parent_id=R_ID_3_1,
            tags=(ComplexBlock,),
            attributes=(
                TestIndexAttributes(9),
                MemoryRegion.attributes_type(64),
                TestNestedIndexAttributes(-4),
            ),
        ),
    ]


@pytest.fixture
async def basic_populated_resource_service(
    resource_service: ResourceServiceInterface, tree1_resource_models
):
    for model in tree1_resource_models:
        await resource_service.create(model)

    return resource_service


@pytest.fixture
async def populated_resource_service(
    resource_service: ResourceServiceInterface, tree3_resource_models
):
    for model in tree3_resource_models:
        await resource_service.create(model)

    return resource_service


@pytest.fixture
async def triple_populated_resource_service(
    resource_service: ResourceServiceInterface,
    tree1_resource_models,
    tree2_resource_models,
    tree3_resource_models,
):
    for model in chain(tree1_resource_models, tree2_resource_models, tree3_resource_models):
        await resource_service.create(model)

    return resource_service
