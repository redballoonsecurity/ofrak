from typing import Tuple, Union, Any, Iterable, Optional

from intervaltree import IntervalTree

from ofrak.service.data_service import DataNode
from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface

# The data is actually not typed in the IntervalTree documentation. However, given how IntervalTree
# is used in OFRAK, this serializer only expects to encounter data of this type.
OFRAKIntervalTreeDataType = Optional[DataNode]
IntervalTreeTupleType = Union[Tuple[int, int], Tuple[int, int, OFRAKIntervalTreeDataType]]
IntervalTreeTuplesType = Iterable[IntervalTreeTupleType]


class IntervalTreeSerializer(SerializerInterface):
    """
    Serialize and deserialize third-party object `IntervalTree` into `PJSONType`.

    Implementation: an `IntervalTree` is a binary lookup tree of intervals, each interval being
    an `Interval` object representing a 3-tuple (begin, end, data).
    As `IntervalTree` provides a `from_tuples` constructor, and has an `all_intervals` attribute,
    we can simply serialize it as its list of intervals (themselves serialized as tuples).
    """

    targets = (IntervalTree,)

    def obj_to_pjson(self, obj: IntervalTree, _type_hint: Any) -> PJSONType:
        return self._service.to_pjson(
            [(interval.begin, interval.end, interval.data) for interval in obj.all_intervals],
            IntervalTreeTuplesType,
        )

    def pjson_to_obj(self, pjson_obj: PJSONType, type_hint: Any) -> IntervalTree:
        return IntervalTree.from_tuples(self._service.from_pjson(pjson_obj, IntervalTreeTuplesType))
