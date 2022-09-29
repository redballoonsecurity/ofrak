from dataclasses import dataclass
from typing import List, Optional, Dict, Tuple

import pytest
from ofrak_type.error import AlreadyExistError, NotFoundError
from ofrak_type.range import Range

from ofrak.model.data_model import DataPatch, DataModel, DataRangePosition
from ofrak.service.data_service import (
    DataService,
    DataNode,
)
from ofrak.service.error import (
    OutOfBoundError,
    OverlapError,
    PatchOverlapError,
    AmbiguousOrderError,
    NonContiguousError,
)

DATA_0 = b"\x00"
DATA_1 = b"\x01"
DATA_2 = b"\x02"
DATA_3 = b"\x03"
DATA_4 = b"\x04"
DATA_5 = b"\x05"
DATA_6 = b"\x06"
DATA_7 = b"\x07"
DATA_8 = b"\x08"

DATA_PARENT_0 = b"\xff\xff"
DATA_TEST_0 = b"\x01\x00"
DATA_TEST_1 = b"\x01\x01"


class DataNodeFactory:
    def __init__(self, size: int, overlaps_enabled: bool = False):
        self.size = size
        self.overlaps_enabled = overlaps_enabled
        self.inserts = []
        self.removes = []

    def insert(
        self,
        item: DataModel,
        after_data_id: Optional[bytes] = None,
        before_data_id: Optional[bytes] = None,
    ) -> "DataNodeFactory":
        self.inserts.append((item, after_data_id, before_data_id))
        return self

    def remove(self, id: bytes) -> "DataNodeFactory":
        self.removes.append(id)
        return self

    def create(self) -> DataNode:
        root_node = DataNode(DataModel(DATA_PARENT_0, Range(0, self.size)))
        root_node.set_overlaps_enabled(self.overlaps_enabled)
        children_by_id: Dict[bytes, DataNode] = dict()
        for item, after_data_id, before_data_id in self.inserts:
            node = root_node.insert(item, after_data_id, before_data_id)
            children_by_id[item.id] = node
        for remove in self.removes:
            root_node.remove(children_by_id[remove])
        return root_node

    def clone(self):
        node_factory = DataNodeFactory(self.size, self.overlaps_enabled)
        node_factory.inserts = self.inserts
        node_factory.removes = self.removes
        return node_factory


@pytest.fixture
def populated_data_node() -> DataNode:
    data_node = DataNode(DataModel(DATA_PARENT_0, Range(0, 0x20)))
    data_node.insert(DataModel(DATA_0, Range(0x3, 0x3)))
    data_node.insert(DataModel(DATA_1, Range(0x3, 0x3)), after_data_id=DATA_0)
    data_node.insert(DataModel(DATA_2, Range(0x3, 0x5)))
    data_node.insert(DataModel(DATA_3, Range(0x7, 0x7)))
    data_node.insert(DataModel(DATA_4, Range(0x9, 0x11)))
    data_node.insert(DataModel(DATA_5, Range(0x11, 0x14)))
    data_node.insert(DataModel(DATA_6, Range(0x16, 0x18)))
    data_node.insert(DataModel(DATA_7, Range(0x18, 0x18)))
    data_node.insert(DataModel(DATA_8, Range(0x18, 0x18)), after_data_id=DATA_7)
    return data_node


class DataNodeTestParams:
    def __init__(self, id: str, node_factory: DataNodeFactory, *params: object):
        self.node_factory = node_factory
        self.params = params
        self.id = id


def create_node_test_params(params_list: List[DataNodeTestParams]):
    extended_params = []
    for params in params_list:
        if not params.node_factory.overlaps_enabled:
            extended_params.append(pytest.param(params.node_factory, *params.params, id=params.id))
            node_factory = params.node_factory.clone()
            node_factory.overlaps_enabled = True
            extended_params.append(
                pytest.param(node_factory, *params.params, id=params.id + " - OL")
            )
        else:
            extended_params.append(
                pytest.param(params.node_factory, *params.params, id=params.id + " - OL")
            )
    return extended_params


class TestDataNode:
    @pytest.mark.parametrize(
        "node_factory,expected_unmapped_ranges",
        create_node_test_params(
            [
                DataNodeTestParams("No children", DataNodeFactory(0x40), [Range(0, 0x40)]),
                DataNodeTestParams(
                    "One child",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x10, 0x30))),
                    [Range(0x00, 0x10), Range(0x30, 0x40)],
                ),
                DataNodeTestParams(
                    "One empty child",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x20, 0x20))),
                    [Range(0x00, 0x20), Range(0x20, 0x40)],
                ),
                DataNodeTestParams(
                    "Two children with one at the end",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x10, 0x30)))
                    .insert(DataModel(DATA_1, Range(0x20, 0x40))),
                    [Range(0x00, 0x10)],
                ),
                DataNodeTestParams(
                    "Two children with one at the beginning",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x10, 0x30)))
                    .insert(DataModel(DATA_1, Range(0x00, 0x10))),
                    [Range(0x30, 0x40)],
                ),
                DataNodeTestParams(
                    "One child within another",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x10, 0x30)))
                    .insert(DataModel(DATA_1, Range(0x15, 0x25))),
                    [Range(0x00, 0x10), Range(0x30, 0x40)],
                ),
                DataNodeTestParams(
                    "One child wrapping another",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x15, 0x25)))
                    .insert(DataModel(DATA_1, Range(0x10, 0x30))),
                    [Range(0x00, 0x10), Range(0x30, 0x40)],
                ),
                DataNodeTestParams(
                    "Two sequential children",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x10, 0x20)))
                    .insert(DataModel(DATA_1, Range(0x20, 0x30))),
                    [Range(0x00, 0x10), Range(0x30, 0x40)],
                ),
                DataNodeTestParams(
                    "One child with new child overlapping left child",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x10, 0x25)))
                    .insert(DataModel(DATA_1, Range(0x15, 0x30))),
                    [Range(0x00, 0x10), Range(0x30, 0x40)],
                ),
                DataNodeTestParams(
                    "One child with new child overlapping right child",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x15, 0x30)))
                    .insert(DataModel(DATA_1, Range(0x10, 0x25))),
                    [Range(0x00, 0x10), Range(0x30, 0x40)],
                ),
                DataNodeTestParams(
                    "Two children with new child covering gap between",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x15, 0x18)))
                    .insert(DataModel(DATA_1, Range(0x22, 0x25)))
                    .insert(DataModel(DATA_2, Range(0x18, 0x22))),
                    [Range(0x00, 0x15), Range(0x25, 0x40)],
                ),
                DataNodeTestParams(
                    "Two children with with new child covering from the left and to the right",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x15, 0x18)))
                    .insert(DataModel(DATA_1, Range(0x22, 0x25)))
                    .insert(DataModel(DATA_2, Range(0x10, 0x30))),
                    [Range(0x00, 0x10), Range(0x30, 0x40)],
                ),
                DataNodeTestParams(
                    "Three children with new child covering gaps between",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x15, 0x18)))
                    .insert(DataModel(DATA_1, Range(0x19, 0x21)))
                    .insert(DataModel(DATA_2, Range(0x22, 0x25)))
                    .insert(DataModel(DATA_3, Range(0x18, 0x22))),
                    [Range(0x00, 0x15), Range(0x25, 0x40)],
                ),
                DataNodeTestParams(
                    "Three children with new child covering from the left and to the right",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x15, 0x18)))
                    .insert(DataModel(DATA_1, Range(0x19, 0x21)))
                    .insert(DataModel(DATA_2, Range(0x22, 0x25)))
                    .insert(DataModel(DATA_3, Range(0x10, 0x30))),
                    [Range(0x00, 0x10), Range(0x30, 0x40)],
                ),
                DataNodeTestParams(
                    "One child removed",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x10, 0x30)))
                    .remove(DATA_0),
                    [Range(0x00, 0x40)],
                ),
                DataNodeTestParams(
                    "Two consecutive children with left child removed",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x10, 0x20)))
                    .insert(DataModel(DATA_1, Range(0x20, 0x30)))
                    .remove(DATA_0),
                    [Range(0x00, 0x20), Range(0x30, 0x40)],
                ),
                DataNodeTestParams(
                    "Two consecutive children with right child removed",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x10, 0x20)))
                    .insert(DataModel(DATA_1, Range(0x20, 0x30)))
                    .remove(DATA_1),
                    [Range(0x00, 0x10), Range(0x20, 0x40)],
                ),
                DataNodeTestParams(
                    "Three consecutive children with middle child removed",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x10, 0x15)))
                    .insert(DataModel(DATA_1, Range(0x15, 0x25)))
                    .insert(DataModel(DATA_2, Range(0x25, 0x30)))
                    .remove(DATA_1),
                    [Range(0x00, 0x10), Range(0x15, 0x25), Range(0x30, 0x40)],
                ),
                DataNodeTestParams(
                    "Two consecutive 0-sized children with left child removed",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x20, 0x20)))
                    .insert(DataModel(DATA_1, Range(0x20, 0x20)), after_data_id=DATA_0)
                    .remove(DATA_0),
                    [Range(0x00, 0x20), Range(0x20, 0x40)],
                ),
                DataNodeTestParams(
                    "Two consecutive 0-sized children with right child removed",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x20, 0x20)))
                    .insert(DataModel(DATA_1, Range(0x20, 0x20)), after_data_id=DATA_0)
                    .remove(DATA_1),
                    [Range(0x00, 0x20), Range(0x20, 0x40)],
                ),
                DataNodeTestParams(
                    "One child surrounded by two 0-sized children with middle removed",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x10, 0x10)))
                    .insert(DataModel(DATA_1, Range(0x10, 0x30)))
                    .insert(DataModel(DATA_2, Range(0x30, 0x30)))
                    .remove(DATA_1),
                    [Range(0x00, 0x10), Range(0x10, 0x30), Range(0x30, 0x40)],
                ),
                DataNodeTestParams(
                    "One child containing another with smaller child removed",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x10, 0x30)))
                    .insert(DataModel(DATA_1, Range(0x15, 0x25)))
                    .remove(DATA_1),
                    [Range(0x00, 0x10), Range(0x30, 0x40)],
                ),
                DataNodeTestParams(
                    "One child containing another with larger child removed",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x10, 0x30)))
                    .insert(DataModel(DATA_1, Range(0x15, 0x25)))
                    .remove(DATA_0),
                    [Range(0x00, 0x15), Range(0x25, 0x40)],
                ),
                DataNodeTestParams(
                    "One child containing two others with larger child removed",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x10, 0x30)))
                    .insert(DataModel(DATA_1, Range(0x15, 0x18)))
                    .insert(DataModel(DATA_1, Range(0x22, 0x25)))
                    .remove(DATA_0),
                    [Range(0x00, 0x15), Range(0x18, 0x22), Range(0x25, 0x40)],
                ),
                DataNodeTestParams(
                    "One child containing empty one with larger child removed",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x10, 0x30)))
                    .insert(DataModel(DATA_1, Range(0x20, 0x20)))
                    .remove(DATA_0),
                    [Range(0x00, 0x20), Range(0x20, 0x40)],
                ),
                DataNodeTestParams(
                    "One child surrounded by two 0-sized children which contains a child with "
                    "larger child is removed",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x10, 0x10)))
                    .insert(DataModel(DATA_1, Range(0x10, 0x30)))
                    .insert(DataModel(DATA_2, Range(0x15, 0x25)))
                    .insert(DataModel(DATA_3, Range(0x30, 0x30)))
                    .remove(DATA_1),
                    [Range(0x00, 0x10), Range(0x10, 0x15), Range(0x25, 0x30), Range(0x30, 0x40)],
                ),
                DataNodeTestParams(
                    "One child surrounded by two 0-sized children which contains a zero-sized child "
                    "with larger child is removed",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x10, 0x10)))
                    .insert(DataModel(DATA_1, Range(0x10, 0x30)))
                    .insert(DataModel(DATA_2, Range(0x20, 0x20)))
                    .insert(DataModel(DATA_3, Range(0x30, 0x30)))
                    .remove(DATA_1),
                    [Range(0x00, 0x10), Range(0x10, 0x20), Range(0x20, 0x30), Range(0x30, 0x40)],
                ),
            ]
        ),
    )
    def test_get_unmapped_ranges(
        self,
        node_factory: DataNodeFactory,
        expected_unmapped_ranges: List[Range],
    ):
        root_node = node_factory.create()
        assert list(root_node.get_unmapped_ranges()) == expected_unmapped_ranges

    @pytest.mark.parametrize(
        "factory,test_range,expected_children_ids",
        create_node_test_params(
            [
                DataNodeTestParams(
                    "No children to the left",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x10, 0x40))),
                    Range(0x00, 0x05),
                    [],
                ),
                DataNodeTestParams(
                    "No children to the right",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x00, 0x30))),
                    Range(0x35, 0x40),
                    [],
                ),
                DataNodeTestParams(
                    "No overlaps and end equals child' start",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x10, 0x30))),
                    Range(0x00, 0x10),
                    [],
                ),
                DataNodeTestParams(
                    "No overlaps and start equals child's end",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x10, 0x30))),
                    Range(0x30, 0x40),
                    [],
                ),
                DataNodeTestParams(
                    "Empty and equal empty child",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x20, 0x20))),
                    Range(0x20, 0x20),
                    [DATA_0],
                ),
                DataNodeTestParams(
                    "Empty and equal child's start",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x10, 0x30))),
                    Range(0x10, 0x10),
                    [],
                ),
                DataNodeTestParams(
                    "Empty and equal child's end",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x10, 0x30))),
                    Range(0x30, 0x30),
                    [],
                ),
                DataNodeTestParams(
                    "Within child",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x10, 0x30))),
                    Range(0x15, 0x25),
                    [DATA_0],
                ),
                DataNodeTestParams(
                    "Within and start equals child's start",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x10, 0x30))),
                    Range(0x10, 0x15),
                    [DATA_0],
                ),
                DataNodeTestParams(
                    "Within and end equals child's end",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x10, 0x30))),
                    Range(0x25, 0x30),
                    [DATA_0],
                ),
                DataNodeTestParams(
                    "Empty and within child",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x10, 0x30))),
                    Range(0x20, 0x20),
                    [DATA_0],
                ),
                DataNodeTestParams(
                    "Contains one child",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x10, 0x30))),
                    Range(0x05, 0x35),
                    [DATA_0],
                ),
                DataNodeTestParams(
                    "Contains and start equal child's start",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x10, 0x30))),
                    Range(0x10, 0x35),
                    [DATA_0],
                ),
                DataNodeTestParams(
                    "Contains and end equal child's end",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x10, 0x30))),
                    Range(0x05, 0x30),
                    [DATA_0],
                ),
                DataNodeTestParams(
                    "Contains empty child",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x20, 0x20))),
                    Range(0x10, 0x30),
                    [DATA_0],
                ),
                DataNodeTestParams(
                    "Start with empty child",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x20, 0x20))),
                    Range(0x20, 0x30),
                    [],
                ),
                DataNodeTestParams(
                    "End with empty child",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x20, 0x20))),
                    Range(0x10, 0x20),
                    [],
                ),
                DataNodeTestParams(
                    "Equal child",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x10, 0x30))),
                    Range(0x10, 0x30),
                    [DATA_0],
                ),
                DataNodeTestParams(
                    "Contains multiple non-empty children with gaps",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x15, 0x15)))
                    .insert(DataModel(DATA_1, Range(0x25, 0x30))),
                    Range(0x5, 0x35),
                    [DATA_0, DATA_1],
                ),
                DataNodeTestParams(
                    "Overlaps multiple non-empty children with gaps",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x10, 0x15)))
                    .insert(DataModel(DATA_1, Range(0x25, 0x30))),
                    Range(0x12, 0x28),
                    [DATA_0, DATA_1],
                ),
                DataNodeTestParams(
                    "Overlaps multiple empty children with non-empty to the right",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x10, 0x10)))
                    .insert(DataModel(DATA_1, Range(0x10, 0x10)), after_data_id=DATA_0)
                    .insert(DataModel(DATA_2, Range(0x10, 0x20))),
                    Range(0x05, 0x15),
                    [DATA_0, DATA_1, DATA_2],
                ),
                DataNodeTestParams(
                    "Overlaps multiple empty children with non-empty to the left",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x20, 0x30)))
                    .insert(DataModel(DATA_1, Range(0x30, 0x30)))
                    .insert(DataModel(DATA_2, Range(0x30, 0x30)), after_data_id=DATA_1),
                    Range(0x25, 0x35),
                    [DATA_0, DATA_1, DATA_2],
                ),
                DataNodeTestParams(
                    "Start equals empty children's start with non-empty to the right",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x10, 0x10)))
                    .insert(DataModel(DATA_1, Range(0x10, 0x10)), after_data_id=DATA_0)
                    .insert(DataModel(DATA_2, Range(0x10, 0x20))),
                    Range(0x10, 0x15),
                    [DATA_2],
                ),
                DataNodeTestParams(
                    "End equals empty children's start with non-empty to the left",
                    DataNodeFactory(0x40)
                    .insert(DataModel(DATA_0, Range(0x20, 0x30)))
                    .insert(DataModel(DATA_1, Range(0x30, 0x30)))
                    .insert(DataModel(DATA_2, Range(0x30, 0x30)), after_data_id=DATA_1),
                    Range(0x25, 0x30),
                    [DATA_0],
                ),
                DataNodeTestParams(
                    "Within overlapping children",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x10, 0x25)))
                    .insert(DataModel(DATA_1, Range(0x15, 0x30))),
                    Range(0x18, 0x22),
                    [DATA_0, DATA_1],
                ),
                DataNodeTestParams(
                    "Empty and within overlapping children",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x10, 0x25)))
                    .insert(DataModel(DATA_1, Range(0x15, 0x30))),
                    Range(0x20, 0x20),
                    [DATA_0, DATA_1],
                ),
                DataNodeTestParams(
                    "Covering overlapping children",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x10, 0x25)))
                    .insert(DataModel(DATA_1, Range(0x15, 0x30))),
                    Range(0x05, 0x35),
                    [DATA_0, DATA_1],
                ),
                DataNodeTestParams(
                    "Overlapping empty and non-empty children",
                    DataNodeFactory(0x40, True)
                    .insert(DataModel(DATA_0, Range(0x10, 0x30)))
                    .insert(DataModel(DATA_1, Range(0x15, 0x15)))
                    .insert(DataModel(DATA_2, Range(0x25, 0x25))),
                    Range(0x12, 0x28),
                    [DATA_0, DATA_1, DATA_2],
                ),
            ]
        ),
    )
    def test_get_children_in_range(
        self,
        factory: DataNodeFactory,
        test_range: Range,
        expected_children_ids: List[bytes],
    ):
        root_node = factory.create()
        children_ids = frozenset(n.model.id for n in root_node.get_children_in_range(test_range))
        assert children_ids == frozenset(expected_children_ids)

    @pytest.mark.parametrize(
        "factory,test_position,test_relative_position",
        create_node_test_params(
            [
                DataNodeTestParams(
                    "At 0-sized node",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x20, 0x20))),
                    0x20,
                    None,
                ),
            ]
        ),
    )
    def test_get_unmapped_range_ambiguous(
        self,
        factory: DataNodeFactory,
        test_position: int,
        test_relative_position: DataRangePosition,
    ):
        root_node = factory.create()
        with pytest.raises(AmbiguousOrderError):
            root_node.get_unmapped_range(test_position, test_relative_position)

    @pytest.mark.parametrize(
        "factory, test_position,test_relative_position",
        create_node_test_params(
            [
                DataNodeTestParams(
                    "At 0-sized node with invalid value",
                    DataNodeFactory(0x40).insert(DataModel(DATA_0, Range(0x20, 0x20))),
                    0x20,
                    DataRangePosition.OVERLAP,
                )
            ]
        ),
    )
    def test_get_unmapped_range_invalid(
        self,
        factory: DataNodeFactory,
        test_position: int,
        test_relative_position: DataRangePosition,
    ):
        root_node = factory.create()
        with pytest.raises(ValueError):
            root_node.get_unmapped_range(test_position, test_relative_position)

    @pytest.mark.parametrize(
        "test_position,test_relative_position",
        [
            pytest.param(0x21, None, id="After the end of the node"),
            pytest.param(-1, None, id="Before the beginning of the node"),
        ],
    )
    def test_get_unmapped_range_outofbound(
        self,
        populated_data_node: DataNode,
        test_position: int,
        test_relative_position: DataRangePosition,
    ):
        with pytest.raises(OutOfBoundError):
            populated_data_node.get_unmapped_range(test_position, test_relative_position)

    @pytest.mark.parametrize(
        "test_position,test_relative_position,expected_range",
        [
            pytest.param(0x04, None, Range(0x04, 0x04), id="Within node"),
            pytest.param(0x01, None, Range(0x00, 0x03), id="Unmapped to the left"),
            pytest.param(0x19, None, Range(0x18, 0x20), id="Unmapped to the right"),
            pytest.param(0x00, None, Range(0x00, 0x03), id="Unmapped at the beginning"),
            pytest.param(0x20, None, Range(0x18, 0x20), id="Unmapped at the end"),
            pytest.param(0x15, None, Range(0x14, 0x16), id="Unmapped range between nodes"),
            pytest.param(
                0x14, None, Range(0x14, 0x16), id="Unmapped and equals to existing node end"
            ),
            pytest.param(
                0x16, None, Range(0x14, 0x16), id="Unmapped and equals to existing node start"
            ),
            pytest.param(
                0x07,
                DataRangePosition.BEFORE,
                Range(0x5, 0x7),
                id="Before and equals existing 0-sized node start",
            ),
            pytest.param(
                0x07,
                DataRangePosition.AFTER,
                Range(0x7, 0x9),
                id="After and equals existing 0-sized node start",
            ),
            pytest.param(
                0x03,
                None,
                Range(0x00, 0x03),
                id="Equals existing 0-sized node start with unmapped data on the left",
            ),
            pytest.param(
                0x18,
                None,
                Range(0x18, 0x20),
                id="Equals existing 0-sized node start with unmapped data on the right",
            ),
        ],
    )
    def test_get_unmapped_range_valid(
        self,
        populated_data_node: DataNode,
        test_position: int,
        test_relative_position: DataRangePosition,
        expected_range: Range,
    ):
        range = populated_data_node.get_unmapped_range(test_position, test_relative_position)
        assert range == expected_range

    @pytest.mark.parametrize(
        "test_range,within_id,after_id,before_id",
        [
            pytest.param(Range(0x7, 0x7), None, None, None, id="No position"),
            pytest.param(Range(0x7, 0x7), DATA_3, DATA_3, DATA_3, id="All positions"),
            pytest.param(Range(0x7, 0x7), None, DATA_3, DATA_3, id="After/before positions"),
            pytest.param(Range(0x7, 0x7), DATA_3, None, DATA_3, id="Within/before positions"),
            pytest.param(Range(0x7, 0x7), DATA_3, DATA_3, None, id="Within/after positions"),
            pytest.param(Range(0x7, 0x7), None, None, DATA_2, id="Invalid before position"),
            pytest.param(Range(0x7, 0x7), None, DATA_4, None, id="Invalid after position"),
            pytest.param(Range(0x7, 0x7), DATA_2, None, None, id="Invalid within position"),
        ],
    )
    def test_get_range_index_ambiguous(
        self,
        populated_data_node: DataNode,
        test_range: Range,
        within_id: bytes,
        after_id: bytes,
        before_id: bytes,
    ):
        with pytest.raises(AmbiguousOrderError):
            populated_data_node.get_range_index(
                test_range,
                before_data_id=before_id,
                after_data_id=after_id,
                within_data_id=within_id,
            )

    @pytest.mark.parametrize(
        "test_range,within_id,after_id,before_id,expected_index,expected_relative_position",
        [
            pytest.param(
                Range(0x11, 0x11),
                None,
                None,
                None,
                5,
                DataRangePosition.UNMAPPED,
                id="Empty/start/end equals existing non-empty node start/end",
            ),
            pytest.param(
                Range(0x14, 0x15),
                None,
                None,
                None,
                6,
                DataRangePosition.UNMAPPED,
                id="Start equals existing node end",
            ),
            pytest.param(
                Range(0x8, 0x9),
                None,
                None,
                None,
                4,
                DataRangePosition.UNMAPPED,
                id="End equals existing node start",
            ),
            pytest.param(
                Range(0x9, 0x9),
                None,
                None,
                None,
                4,
                DataRangePosition.UNMAPPED,
                id="Empty/start equals existing non-empty node start",
            ),
            pytest.param(
                Range(0x14, 0x14),
                None,
                None,
                None,
                6,
                DataRangePosition.UNMAPPED,
                id="Empty/start equals existing non-empty node end",
            ),
            pytest.param(
                Range(0x7, 0x8),
                None,
                None,
                None,
                4,
                DataRangePosition.UNMAPPED,
                id="Start equals existing empty node end",
            ),
            pytest.param(
                Range(0x6, 0x7),
                None,
                None,
                None,
                3,
                DataRangePosition.UNMAPPED,
                id="End equals existing empty node start",
            ),
            pytest.param(
                Range(0x0, 0x2), None, None, None, 0, DataRangePosition.UNMAPPED, id="Insert left"
            ),
            pytest.param(
                Range(0x19, 0x20),
                None,
                None,
                None,
                9,
                DataRangePosition.UNMAPPED,
                id="Insert right",
            ),
            pytest.param(
                Range(0x08, 0x12),
                None,
                None,
                None,
                4,
                DataRangePosition.OVERLAP,
                id="Overlaps by containing node",
            ),
            pytest.param(
                Range(0x06, 0x8),
                None,
                None,
                None,
                3,
                DataRangePosition.OVERLAP,
                id="Overlaps by containing empty node",
            ),
            pytest.param(
                Range(0x08, 0x10),
                None,
                None,
                None,
                4,
                DataRangePosition.OVERLAP,
                id="Overlaps node start",
            ),
            pytest.param(
                Range(0x12, 0x15),
                None,
                None,
                None,
                5,
                DataRangePosition.OVERLAP,
                id="Overlaps node end",
            ),
            pytest.param(
                Range(0x03, 0x06),
                None,
                None,
                None,
                2,
                DataRangePosition.OVERLAP,
                id="Overlaps non-empty node preceded by multiple empty nodes",
            ),
            pytest.param(
                Range(0x15, 0x18),
                None,
                None,
                None,
                6,
                DataRangePosition.OVERLAP,
                id="Overlaps non-empty node followed by multiple empty nodes",
            ),
            pytest.param(
                Range(0x7, 0x7),
                None,
                DATA_2,
                None,
                2,
                DataRangePosition.AFTER,
                id="Emtpy/start equals existing empty node start with after position ref to not "
                "empty node",
            ),
            pytest.param(
                Range(0x7, 0x7),
                None,
                None,
                DATA_4,
                4,
                DataRangePosition.BEFORE,
                id="Emtpy/start equals existing empty node start with before position ref to not "
                "empty node",
            ),
            pytest.param(
                Range(0x7, 0x7),
                None,
                DATA_3,
                None,
                3,
                DataRangePosition.AFTER,
                id="Emtpy/start equals existing empty node start with after position ref to empty "
                "node",
            ),
            pytest.param(
                Range(0x7, 0x7),
                None,
                None,
                DATA_3,
                3,
                DataRangePosition.BEFORE,
                id="Emtpy/start equals existing empty node start with before position ref to empty "
                "node",
            ),
            pytest.param(
                Range(0x3, 0x3),
                None,
                None,
                DATA_0,
                0,
                DataRangePosition.BEFORE,
                id="Empty/start equals existing empty node start with before position ref to empty "
                "node and insert left",
            ),
            pytest.param(
                Range(0x18, 0x18),
                None,
                DATA_8,
                None,
                8,
                DataRangePosition.AFTER,
                id="Empty/start equals existing empty node start with after position ref to empty "
                "node and insert right",
            ),
            pytest.param(
                Range(0x12, 0x13),
                None,
                None,
                None,
                5,
                DataRangePosition.WITHIN,
                id="Within existing node",
            ),
            pytest.param(
                Range(0x11, 0x13),
                None,
                None,
                None,
                5,
                DataRangePosition.WITHIN,
                id="Within with start equal existing node start",
            ),
            pytest.param(
                Range(0x12, 0x14),
                None,
                None,
                None,
                5,
                DataRangePosition.WITHIN,
                id="Within with end equal existing node end",
            ),
            pytest.param(
                Range(0x11, 0x14),
                None,
                None,
                None,
                5,
                DataRangePosition.WITHIN,
                id="Within existing node with bounds equal existing node bounds",
            ),
            pytest.param(
                Range(0x12, 0x12),
                None,
                None,
                None,
                5,
                DataRangePosition.WITHIN,
                id="Empty/within existing node",
            ),
            pytest.param(
                Range(0x11, 0x11),
                DATA_5,
                None,
                None,
                5,
                DataRangePosition.WITHIN,
                id="Empty/within with position equal existing node start",
            ),
            pytest.param(
                Range(0x11, 0x11),
                DATA_4,
                None,
                None,
                4,
                DataRangePosition.WITHIN,
                id="Empty/within with position equal existing node end",
            ),
            pytest.param(
                Range(0x3, 0x3),
                DATA_0,
                None,
                None,
                0,
                DataRangePosition.WITHIN,
                id="Within first of multiple empty node ",
            ),
            pytest.param(
                Range(0x3, 0x3),
                DATA_1,
                None,
                None,
                1,
                DataRangePosition.WITHIN,
                id="Within last empty node of multiple empty nodes followed by non-empty node",
            ),
            pytest.param(
                Range(0x3, 0x3),
                DATA_2,
                None,
                None,
                2,
                DataRangePosition.WITHIN,
                id="Empty/within last non-empty node of multiple empty nodes",
            ),
            pytest.param(
                Range(0x3, 0x4),
                DATA_2,
                None,
                None,
                2,
                DataRangePosition.WITHIN,
                id="Within last non-empty node of multiple empty nodes",
            ),
            pytest.param(
                Range(0x18, 0x18),
                DATA_8,
                None,
                None,
                8,
                DataRangePosition.WITHIN,
                id="Within last of multiple empty node",
            ),
            pytest.param(
                Range(0x18, 0x18),
                DATA_7,
                None,
                None,
                7,
                DataRangePosition.WITHIN,
                id="Within first empty node of multiple empty nodes preceded by non-empty node",
            ),
            pytest.param(
                Range(0x18, 0x18),
                DATA_6,
                None,
                None,
                6,
                DataRangePosition.WITHIN,
                id="Empty/within first non-empty node of multiple empty nodes",
            ),
            pytest.param(
                Range(0x17, 0x18),
                DATA_6,
                None,
                None,
                6,
                DataRangePosition.WITHIN,
                id="Within first non-empty node of multiple empty nodes",
            ),
        ],
    )
    def test_get_range_index_valid(
        self,
        populated_data_node: DataNode,
        test_range: Range,
        within_id: bytes,
        after_id: bytes,
        before_id: bytes,
        expected_index: int,
        expected_relative_position: DataRangePosition,
    ):
        index, relative_position = populated_data_node.get_range_index(
            test_range,
            within_data_id=within_id,
            before_data_id=before_id,
            after_data_id=after_id,
        )
        assert index == expected_index
        assert relative_position == expected_relative_position

    @pytest.mark.parametrize(
        "test_range",
        [
            pytest.param(Range(0x00, 0x30), id="Too large"),
            pytest.param(Range(0x15, 0x30), id="Overlap end"),
        ],
    )
    def test_insert_out_of_bound(self, populated_data_node: DataNode, test_range: Range):
        with pytest.raises(OutOfBoundError):
            populated_data_node.insert(DataModel(DATA_TEST_0, test_range))

    @pytest.mark.parametrize(
        "test_range",
        [
            pytest.param(Range(0x08, 0x12), id="Contains existing node"),
            pytest.param(Range(0x08, 0x10), id="Overlaps existing node start"),
            pytest.param(Range(0x12, 0x15), id="Overlaps existing node end"),
            pytest.param(Range(0x12, 0x13), id="Within existing node"),
            pytest.param(Range(0x12, 0x12), id="Empty/within existing node"),
            pytest.param(
                Range(0x03, 0x04), id="Overlaps non-empty node preceded by Multiple empty nodes"
            ),
            pytest.param(
                Range(0x17, 0x18), id="Overlaps non-empty node followed by multiple empty nodes"
            ),
        ],
    )
    def test_insert_overlap(self, populated_data_node: DataNode, test_range: Range):
        with pytest.raises(OverlapError):
            populated_data_node.insert(DataModel(DATA_TEST_0, test_range))

    @pytest.mark.parametrize(
        "test_range,after_id,before_id",
        [
            pytest.param(Range(0x7, 0x7), None, None, id="No position"),
            pytest.param(Range(0x7, 0x7), DATA_3, DATA_4, id="Both positions"),
            pytest.param(Range(0x7, 0x7), None, DATA_2, id="Invalid before position"),
            pytest.param(Range(0x7, 0x7), DATA_4, None, id="Invalid after position"),
        ],
    )
    def test_insert_ambiguous(
        self,
        populated_data_node: DataNode,
        test_range: Range,
        after_id: bytes,
        before_id: bytes,
    ):
        with pytest.raises(AmbiguousOrderError):
            populated_data_node.insert(
                DataModel(DATA_TEST_0, test_range),
                before_data_id=before_id,
                after_data_id=after_id,
            )

    @pytest.mark.parametrize(
        "test_range,after_id,before_id,expected_index",
        [
            pytest.param(
                Range(0x11, 0x11),
                None,
                None,
                5,
                id="Empty/start/end equals existing non-empty node start/end",
            ),
            pytest.param(Range(0x14, 0x15), None, None, 6, id="Start equals existing node end"),
            pytest.param(Range(0x8, 0x9), None, None, 4, id="End equals existing node start"),
            pytest.param(
                Range(0x9, 0x9),
                None,
                None,
                4,
                id="Empty/start equals existing non-empty node start",
            ),
            pytest.param(
                Range(0x14, 0x14),
                None,
                None,
                6,
                id="Empty/start equals existing non-empty node end",
            ),
            pytest.param(Range(0x7, 0x8), None, None, 4, id="Start equals existing empty node end"),
            pytest.param(Range(0x6, 0x7), None, None, 3, id="End equals existing empty node start"),
            pytest.param(Range(0x0, 0x2), None, None, 0, id="Insert left"),
            pytest.param(Range(0x19, 0x20), None, None, 9, id="Insert right"),
            pytest.param(
                Range(0x7, 0x7),
                DATA_2,
                None,
                3,
                id="Emtpy/start equals existing empty node start with after position ref to not empty "
                "node",
            ),
            pytest.param(
                Range(0x7, 0x7),
                None,
                DATA_4,
                4,
                id="Emtpy/start equals existing empty node start with before position ref to not empty "
                "node",
            ),
            pytest.param(
                Range(0x7, 0x7),
                DATA_3,
                None,
                4,
                id="Emtpy/start equals existing empty node start with after position ref to empty node",
            ),
            pytest.param(
                Range(0x7, 0x7),
                None,
                DATA_3,
                3,
                id="Emtpy/start equals existing empty node start with before position ref to empty node",
            ),
            pytest.param(
                Range(0x3, 0x3),
                None,
                DATA_0,
                0,
                id="Empty/start equals existing empty node start with before position ref to empty "
                "node and insert left",
            ),
            pytest.param(
                Range(0x18, 0x18),
                DATA_8,
                None,
                9,
                id="Empty/start equals existing empty node start with after position ref to empty "
                "node and insert right",
            ),
        ],
    )
    def test_insert_valid(
        self,
        populated_data_node: DataNode,
        test_range: Range,
        after_id: bytes,
        before_id: bytes,
        expected_index: int,
    ):
        data_node = populated_data_node.insert(
            DataModel(DATA_TEST_0, test_range),
            before_data_id=before_id,
            after_data_id=after_id,
        )
        assert data_node.model.range == test_range
        assert populated_data_node.get_child_index(data_node) == expected_index


@pytest.fixture
def data_service():
    return DataService()


@pytest.fixture
async def populated_data_service():
    data_service = DataService()
    await data_service.create(DATA_0, b"\x00" * 0x18)
    _ = await data_service.create_mapped(DATA_1, DATA_0, Range(0x0, 0x8))
    _ = await data_service.create_mapped(DATA_2, DATA_0, Range(0x8, 0x10))
    _ = await data_service.create_mapped(DATA_3, DATA_2, Range(0x0, 0x4))
    _ = await data_service.create_mapped(DATA_4, DATA_2, Range(0x4, 0x8))

    await data_service.create_mapped(DATA_5, DATA_0, Range(0x10, 0x18))
    return data_service


class TestDataService:
    async def test_create_existing(self, populated_data_service: DataService):
        with pytest.raises(AlreadyExistError):
            await populated_data_service.create(DATA_0, b"\x00" * 0x10)
        with pytest.raises(AlreadyExistError):
            await populated_data_service.create_mapped(DATA_1, DATA_0, Range(0x0, 0x8))

    async def test_create_missing_parent(self, populated_data_service: DataService):
        with pytest.raises(NotFoundError):
            await populated_data_service.create_mapped(DATA_TEST_1, DATA_TEST_0, Range(0x0, 0x8))

    async def test_create_out_of_bounds(self, populated_data_service: DataService):
        with pytest.raises(OutOfBoundError):
            await populated_data_service.create_mapped(DATA_TEST_0, DATA_2, Range(0x4, 0x10))

    async def test_patches_out_of_bounds(self, populated_data_service: DataService):
        with pytest.raises(OutOfBoundError):
            await populated_data_service.apply_patches(
                [DataPatch(Range(0x6, 0x9), DATA_1, b"\x01" * 0x3)]
            )

    async def test_patches_overlapping(self, populated_data_service: DataService):
        with pytest.raises(PatchOverlapError):
            await populated_data_service.apply_patches(
                [
                    DataPatch(Range(0x0, 0x2), DATA_2, b"\x01" * 5),
                    DataPatch(Range(0x1, 0x4), DATA_3, b"\x01" * 5),
                ]
            )
        with pytest.raises(PatchOverlapError):
            await populated_data_service.apply_patches(
                [
                    DataPatch(Range(0x0, 0x2), DATA_3, b"\x01" * 5),
                    DataPatch(Range(0x1, 0x1), DATA_2, b"\x01" * 5),
                ]
            )
        with pytest.raises(PatchOverlapError):
            await populated_data_service.apply_patches(
                [
                    DataPatch(Range(0x2, 0x2), DATA_3, b"\x01" * 5),
                    DataPatch(Range(0x2, 0x2), DATA_3, b"\x01" * 5),
                ]
            )
        with pytest.raises(PatchOverlapError):
            await populated_data_service.apply_patches(
                [
                    DataPatch(Range(0x2, 0x2), DATA_3, b"\x01" * 5),
                    DataPatch(Range(0x2, 0x2), DATA_2, b"\x01" * 5),
                ]
            )

    async def test_patches_overlapping_with_children(self, populated_data_service: DataService):
        with pytest.raises(PatchOverlapError):
            results = await populated_data_service.apply_patches(
                [
                    # Replace some data within DATA_2
                    DataPatch(Range(0x6, 0x8), DATA_2, b"\x01" * 4),
                ]
            )
        with pytest.raises(PatchOverlapError):
            results = await populated_data_service.apply_patches(
                [
                    # Insert some data within DATA_2
                    DataPatch(Range(0x6, 0x6), DATA_2, b"\x02" * 4),
                ]
            )

    async def test_patches_trailing_children(self, populated_data_service: DataService):
        results = await populated_data_service.apply_patches(
            [
                # Replace some data within DATA_0
                DataPatch(Range(0x00, 0x00), DATA_0, b"\x01" * 4),
            ]
        )

        data_1 = await populated_data_service.get_data(DATA_1)
        assert data_1 == b"\x00" * 0x8
        data_5 = await populated_data_service.get_data(DATA_5)
        assert data_5 == b"".join(
            [
                b"\x00" * 4,  # Original data
                b"\x00" * 4,  # Original data
            ]
        )
        data_3 = await populated_data_service.get_data(DATA_3)
        assert data_3 == b"".join([b"\x00" * 0x4])
        data_4 = await populated_data_service.get_data(DATA_4)
        assert data_4 == b"".join(
            [
                b"\x00" * 4,  # Original data
            ]
        )
        data_2 = await populated_data_service.get_data(DATA_2)
        assert data_2 == b"".join(
            [
                b"\x00" * 4,  # Original data  (DATA_3)
                b"\x00" * 4,  # Original data  (DATA_4)
            ]
        )
        data_0 = await populated_data_service.get_data(DATA_0)
        assert data_0 == b"".join(
            [
                b"\x01" * 4,  # Patch           (DATA_0)
                b"\x00" * 24,  # Original data   (DATA_1)
            ]
        )

    async def test_gather(self, populated_data_service: DataService):
        """
        Starting state:
        DATA_0 (0x0, 0x18)
         |
         +- DATA_1 (0x0, 0x8)
         +- DATA_2 (0x8, 0x10)
         |   |
         |   +- DATA_3 (0x0, 0x4)
         |   +- DATA_4 (0x4, 0x8)
         +- DATA_5 (0x10, 0x18)
        """
        data_3_model = await populated_data_service.get_by_id(DATA_3)
        assert data_3_model.root_id == DATA_2
        data_4_model = await populated_data_service.get_by_id(DATA_4)
        assert data_4_model.root_id == DATA_2

        await populated_data_service.gather_siblings(DATA_6, (DATA_3, DATA_4))
        """
        Expected state:
        DATA_0 (0x0, 0x18)
         |
         +- DATA_1 (0x0, 0x8)
         +- DATA_2 (0x8, 0x10)
         |   |
         |   +- DATA_6 (0x0, 0x8)
         |       |
         |       +- DATA_3 (0x0, 0x4)
         |       +- DATA_4 (0x4, 0x8)
         +- DATA_5 (0x10, 0x18)
        """
        data_6 = await populated_data_service.get_data(DATA_6)
        assert len(data_6) == 0x8

        data_6_model = await populated_data_service.get_by_id(DATA_6)
        assert data_6_model.root_id == DATA_2

        data_2_model = await populated_data_service.get_by_id(DATA_2)
        assert data_2_model.root_id == DATA_0

        data_3_model = await populated_data_service.get_by_id(DATA_3)
        assert data_3_model.root_id == DATA_6
        data_4_model = await populated_data_service.get_by_id(DATA_4)
        assert data_4_model.root_id == DATA_6

        # Gathering into DATA_7 should fail
        with pytest.raises(NonContiguousError):
            await populated_data_service.gather_siblings(DATA_7, (DATA_1, DATA_5))
        with pytest.raises(NotFoundError):
            await populated_data_service.get_by_id(DATA_7)

        await populated_data_service.gather_siblings(DATA_7, (DATA_2, DATA_5))
        """
        Expected state:
        DATA_0 (0x0, 0x18)
         |
         +- DATA_1 (0x0, 0x8)
         +- DATA_7 (0x8, 0x18)
             |
             +- DATA_2 (0x0, 0x8)
             |   |
             |   +- DATA_6 (0x0, 0x8)
             |       |
             |       +- DATA_3 (0x0, 0x4)
             |       +- DATA_4 (0x4, 0x8)
             +- DATA_5 (0x8, 0x10)
        """
        data_7 = await populated_data_service.get_data(DATA_7)
        assert len(data_7) == 0x10
        data_1_model = await populated_data_service.get_by_id(DATA_1)
        assert data_1_model.root_id == DATA_0
        data_7_model = await populated_data_service.get_by_id(DATA_7)
        assert data_7_model.root_id == DATA_0
        data_2_model = await populated_data_service.get_by_id(DATA_2)
        assert data_2_model.root_id == DATA_7
        assert data_2_model.range == Range(0, 0x8)
        data_6_model = await populated_data_service.get_by_id(DATA_6)
        assert data_6_model.root_id == DATA_2
        data_3_model = await populated_data_service.get_by_id(DATA_3)
        assert data_3_model.root_id == DATA_6
        data_4_model = await populated_data_service.get_by_id(DATA_4)
        assert data_4_model.root_id == DATA_6
        data_5_model = await populated_data_service.get_by_id(DATA_5)
        assert data_5_model.root_id == DATA_7
        assert data_5_model.range == Range(0x8, 0x10)

    async def test_delete(self, populated_data_service: DataService):
        """
        Starting state:
        DATA_0 (0x0, 0x18)
         |
         +- DATA_1 (0x0, 0x8)
         +- DATA_2 (0x8, 0x10)
         |   |
         |   +- DATA_3 (0x0, 0x4)
         |   +- DATA_4 (0x4, 0x8)
         +- DATA_5 (0x10, 0x18)
        """
        (
            data_0_model,
            data_1_model,
            data_2_model,
            data_3_model,
            data_4_model,
            data_5_model,
        ) = await populated_data_service.get_by_ids(
            [DATA_0, DATA_1, DATA_2, DATA_3, DATA_4, DATA_5]
        )
        assert data_0_model.root_id is None
        assert data_1_model.root_id == DATA_0
        assert data_2_model.root_id == DATA_0
        assert data_3_model.root_id == DATA_2
        assert data_4_model.root_id == DATA_2
        assert data_5_model.root_id == DATA_0

        await populated_data_service.delete_node(DATA_5)
        """
        Expected state:
        DATA_0 (0x0, 0x18)
         |
         +- DATA_1 (0x0, 0x8)
         +- DATA_2 (0x8, 0x10)
             |
             +- DATA_3 (0x0, 0x4)
             +- DATA_4 (0x4, 0x8)
        """
        with pytest.raises(NotFoundError):
            await populated_data_service.get_by_id(DATA_5)
        (
            data_0_model,
            data_1_model,
            data_2_model,
            data_3_model,
            data_4_model,
        ) = await populated_data_service.get_by_ids([DATA_0, DATA_1, DATA_2, DATA_3, DATA_4])
        assert data_0_model.root_id is None
        assert data_1_model.root_id == DATA_0
        assert data_2_model.root_id == DATA_0
        assert data_3_model.root_id == DATA_2
        assert data_4_model.root_id == DATA_2

        await populated_data_service.delete_node(DATA_2)
        """
        Expected state:
        DATA_0 (0x0, 0x18)
         |
         +- DATA_1 (0x0, 0x8)
         +- DATA_3 (0x8, 0xC)
         +- DATA_4 (0xC, 0x10)
        """
        with pytest.raises(NotFoundError):
            await populated_data_service.get_by_id(DATA_2)
        (
            data_0_model,
            data_1_model,
            data_3_model,
            data_4_model,
        ) = await populated_data_service.get_by_ids([DATA_0, DATA_1, DATA_3, DATA_4])
        print(data_0_model, data_1_model, data_3_model, data_4_model)
        assert data_0_model.root_id is None
        assert data_1_model.root_id == DATA_0, data_1_model
        assert data_3_model.root_id == DATA_0, data_3_model
        assert data_4_model.root_id == DATA_0, data_4_model
        data_3_range = await populated_data_service.get_data_range_within_root(data_3_model.id)
        assert data_3_range == Range(0x8, 0xC)
        data_4_range = await populated_data_service.get_data_range_within_root(data_4_model.id)
        assert data_4_range == Range(0xC, 0x10)

    async def test_merge(self, populated_data_service: DataService):
        """
        Starting state:
        DATA_0 (0x0, 0x18)
         |
         +- DATA_1 (0x0, 0x8)
         +- DATA_2 (0x8, 0x10)
         |   |
         |   +- DATA_3 (0x0, 0x4)
         |   +- DATA_4 (0x4, 0x8)
         +- DATA_5 (0x10, 0x18)
        """
        data_3_model, data_4_model = await populated_data_service.get_by_ids([DATA_3, DATA_4])
        assert data_3_model.root_id == data_4_model.root_id == DATA_2

        await populated_data_service.merge_siblings(DATA_6, (DATA_3, DATA_4))
        """
        Expected state:
        DATA_0 (0x0, 0x18)
         |
         +- DATA_1 (0x0, 0x8)
         +- DATA_2 (0x8, 0x10)
         |   |
         |   +- DATA_6 (0x0, 0x8)
         +- DATA_5 (0x10, 0x18)
        """
        data_6 = await populated_data_service.get_data(DATA_6)
        assert len(data_6) == 0x8
        data_6_model = await populated_data_service.get_by_id(DATA_6)
        assert data_6_model.root_id == DATA_2
        with pytest.raises(NotFoundError):
            await populated_data_service.get_by_id(DATA_3)
            await populated_data_service.get_by_id(DATA_4)

        with pytest.raises(NonContiguousError):
            await populated_data_service.merge_siblings(DATA_7, (DATA_1, DATA_5))
        with pytest.raises(NotFoundError):
            await populated_data_service.get_by_id(DATA_7)

        await populated_data_service.merge_siblings(DATA_7, (DATA_1, DATA_2, DATA_5))
        """
        Expected state:
        DATA_0 (0x0, 0x18)
         |
         +- DATA_7 (0x0, 0x18)
             |
             +- DATA_6 (0x0, 0x8)
        """
        data_7 = await populated_data_service.get_data(DATA_7)
        assert len(data_7) == 0x18
        data_7_model = await populated_data_service.get_by_id(DATA_7)
        assert data_7_model.root_id == DATA_0
        data_6_model = await populated_data_service.get_by_id(DATA_6)
        assert data_6_model.root_id == DATA_7
        for data_id in [DATA_1, DATA_2, DATA_3, DATA_4, DATA_5]:
            with pytest.raises(NotFoundError):
                await populated_data_service.get_by_id(data_id)

    async def test_delete_tree(self, populated_data_service: DataService):
        """
        Starting state:
        DATA_0 (0x0, 0x18)
         |
         +- DATA_1 (0x0, 0x8)
         +- DATA_2 (0x8, 0x10)
         |   |
         |   +- DATA_3 (0x0, 0x4)
         |   +- DATA_4 (0x4, 0x8)
         +- DATA_5 (0x10, 0x18)
        """
        data_2_model = await populated_data_service.get_by_id(DATA_2)
        assert data_2_model.root_id == DATA_0
        data_3_model, data_4_model = await populated_data_service.get_by_ids([DATA_3, DATA_4])
        assert data_3_model.root_id == data_4_model.root_id == DATA_2

        await populated_data_service.delete_tree(DATA_2)
        """
        Expected state:
        DATA_0 (0x0, 0x18)
         |
         +- DATA_1 (0x0, 0x8)
         +- DATA_5 (0x10, 0x18)
        """
        data_1_model, data_5_model = await populated_data_service.get_by_ids([DATA_1, DATA_5])
        assert data_1_model.root_id == data_5_model.root_id == DATA_0
        for data_id in [DATA_2, DATA_3, DATA_4]:
            with pytest.raises(NotFoundError):
                await populated_data_service.get_by_id(data_id)


class TestDataServiceInternalAttribute:
    """
    A separate class for the test below which still uses a internal attribute of DataService, rather than conforming
    to the DataServiceInterface. This test will fail on DataServiceInterface implementations which don't have this
    attribute. We put it in a separate class so that tests for other implementations can inherit from the other tests
    in TestDataService while avoiding this one.
    """

    async def test_patches(self, populated_data_service: DataService):
        results = await populated_data_service.apply_patches(
            [
                # Replace some data within DATA_5
                DataPatch(Range(0x00, 0x02), DATA_5, b"\x01" * 4),
                # Now DATA_5 has length 10.
                # Insert some data within DATA_5
                DataPatch(Range(0x04, 0x04), DATA_5, b"\x02" * 4),
                # Now DATA_5 has length 14.
                # Insert some data into DATA_2 between DATA_3 and DATA_4
                DataPatch(Range(0x4, 0x4), DATA_2, b"\x03" * 4),
                # Now DATA_2 has length 12.
                # Append some data to DATA_3
                DataPatch(Range(0x4, 0x4), DATA_3, b"\x04" * 4),
                # Now DATA_2 has length 16.
                # Now DATA_3 has length 8.
                # Prepend some data to DATA_4
                DataPatch(Range(0x0, 0x0), DATA_4, b"\x05" * 4),
                # Now DATA_2 has length 20.
                # Now DATA_4 has length 8.
            ]
        )

        data_1 = await populated_data_service.get_data(DATA_1)
        assert data_1 == b"\x00" * 0x8
        data_5 = await populated_data_service.get_data(DATA_5)
        assert data_5 == b"".join(
            [
                b"\x01" * 4,  # First patch
                b"\x00" * 2,  # Original data
                b"\x02" * 4,  # Second patch
                b"\x00" * 4,  # Original data
            ]
        )
        data_3 = await populated_data_service.get_data(DATA_3)
        assert data_3 == b"".join([b"\x00" * 0x4, b"\x04" * 4])
        data_4 = await populated_data_service.get_data(DATA_4)
        assert data_4 == b"".join(
            [
                b"\x05" * 4,  # Fifth patch
                b"\x00" * 4,  # Original data
            ]
        )
        data_2 = await populated_data_service.get_data(DATA_2)
        assert data_2 == b"".join(
            [
                b"\x00" * 4,  # Original data  (DATA_3)
                b"\x04" * 4,  # Fourth patch   (DATA_3)
                b"\x03" * 4,  # Third patch    (DATA_2)
                b"\x05" * 4,  # Fifth patch    (DATA_4)
                b"\x00" * 4,  # Original data  (DATA_4)
            ]
        )
        data_0 = await populated_data_service.get_data(DATA_0)
        assert data_0 == b"".join(
            [
                b"\x00" * 8,  # Original data  (DATA_1)
                b"\x00" * 4,  # Original data  (DATA_3)
                b"\x04" * 4,  # Fourth patch   (DATA_3)
                b"\x03" * 4,  # Third patch    (DATA_2)
                b"\x05" * 4,  # Fifth patch    (DATA_4)
                b"\x00" * 4,  # Original data  (DATA_4)
                b"\x01" * 4,  # First patch
                b"\x00" * 2,  # Original data
                b"\x02" * 4,  # Second patch
                b"\x00" * 4,  # Original data
            ]
        )
        # TODO: Rewrite this test so that it tests through the DataServiceInterface
        for node in populated_data_service._data_node_store.values():
            for start, child in node._children:
                assert start == child.model.range.start


@dataclass
class TranslateChildrenTestCase:
    label: str
    patch_infos: List[Tuple[Range, int, DataRangePosition, int]]
    expected_patched_children_starts: List[int]


TRANSLATE_CHILDREN_TEST_CASES = [
    TranslateChildrenTestCase(
        "unmapped range before all children",
        [
            (Range(0x0, 0x0), 0, DataRangePosition.UNMAPPED, 0x20),
        ],
        [0x20, 0x60, 0xA0, 0xE0],
    ),
    TranslateChildrenTestCase(
        "unmapped range after all children",
        [
            (Range(0x100, 0x100), 4, DataRangePosition.UNMAPPED, 0x20),
        ],
        [0x0, 0x40, 0x80, 0xC0],
    ),
    TranslateChildrenTestCase(
        "unmapped range between children",
        [
            (Range(0x80, 0x80), 2, DataRangePosition.UNMAPPED, 0x20),
        ],
        [0x00, 0x40, 0xA0, 0xE0],
    ),
]


@pytest.mark.parametrize("test_case", TRANSLATE_CHILDREN_TEST_CASES, ids=lambda tc: tc.label)
def test_unmapped_translate_children(test_case):
    factory = DataNodeFactory(0x100, overlaps_enabled=False)
    factory.insert(DataModel(DATA_0, Range(0x0, 0x40)))
    factory.insert(DataModel(DATA_1, Range(0x40, 0x80)))
    factory.insert(DataModel(DATA_2, Range(0x80, 0xC0)))
    factory.insert(DataModel(DATA_3, Range(0xC0, 0x100)))

    root_node = factory.create()

    for patch_range, patch_child_idx, patch_pos, _ in test_case.patch_infos:
        assert (patch_child_idx, patch_pos) == root_node.get_range_index(patch_range)

    root_node.translate_children(test_case.patch_infos)

    for i in range(0, 4):
        node_start = root_node.get_child(i).model.range.start
        expected_node_start = test_case.expected_patched_children_starts[i]
        assert (
            expected_node_start == node_start
        ), f"Expected {hex(expected_node_start)}, got {hex(node_start)} for node {i}"
