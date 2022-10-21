from dataclasses import dataclass
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Tuple, Type, Set, Optional, Sequence, Union, Iterable

import pytest
from beartype.roar import BeartypeCallHintParamViolation
from hypothesis import given, settings, HealthCheck
from hypothesis.strategies import (
    builds,
    data,
    register_type_strategy,
    tuples,
    integers,
    composite,
    from_type,
    lists,
    one_of,
    just,
    floats,
)
from intervaltree import IntervalTree, Interval
from synthol.injector import DependencyInjector
from typing_inspect import get_args

from ofrak import ResourceTag
from ofrak.core.addressable import Addressable
from ofrak.core.elf.model import ElfHeader
from ofrak.core.filesystem import FilesystemRoot
from ofrak.core.magic import Magic
from ofrak.core.memory_region import MemoryRegion
from ofrak.model.component_model import ComponentConfig
from ofrak.model.data_model import DataModel
from ofrak.model.resource_model import ResourceAttributes, ResourceAttributeDependency
from ofrak.resource_view import ResourceView
from ofrak.service.component_locator_i import ComponentFilter
from ofrak.service.data_service import DataNode
from ofrak.service.serialization.pjson import PJSONSerializationService
from ofrak_type.architecture import InstructionSet, InstructionSetMode
from ofrak_type.range import Range


@composite
def integer_strategy(draw):
    """orjson doesn't support integers outside of the 64-bit range"""
    return draw(integers(min_value=-(2**63), max_value=2**63 - 1))


@composite
def positive_integer_strategy(draw):
    return draw(integers(min_value=0, max_value=2**63 - 1))


@composite
def range_strategy(draw, _type_hint):
    """Generating invalid Ranges triggers errors, so we generate valid ones"""
    int1 = draw(positive_integer_strategy())
    int2 = draw(positive_integer_strategy())
    return Range(min(int1, int2), max(int1, int2))


@composite
def iterable_strategy(draw, type_hint):
    """
    Hypothesis generates weird iterables like b'' so we restrict it to lists.

    That's basically how we're using the Iterable type hint in OFRAK.
    """
    contained_type = get_args(type_hint)[0]
    return draw(lists(from_type(contained_type)))


@composite
def os_stat_result_strategy(draw, _type_hint):
    """
    os.stat_result instances can be generated as tuples of size 10. They most likely won't be valid
    but it doesn't matter here.
    """
    return draw(tuples(*[integer_strategy()] * 10))


@composite
def resource_tag_strategy(draw, _type_hint):
    """
    Use a child (Addressable) and a grand-child (MemoryRegion) of ResourceView as
    instances of the type ResourceTag (a metaclass)
    """
    return draw(one_of(just(Addressable), just(MemoryRegion)))


@composite
def float_strategy(draw, _type_hint):
    return draw(floats(allow_nan=False, allow_infinity=False))


register_type_strategy(Range, range_strategy)
register_type_strategy(Iterable, iterable_strategy)  # type: ignore
register_type_strategy(os.stat_result, os_stat_result_strategy)
register_type_strategy(ResourceTag, resource_tag_strategy)
register_type_strategy(int, integer_strategy)
register_type_strategy(float, float_strategy)


class A:
    a1: Optional[int]
    a2: List[bytes]

    def __init__(self, a1: Optional[int], a2: List[bytes]):
        self.a1 = None
        self.a2 = a2

    def __eq__(self, other):
        return all((isinstance(other, A), self.a1 == other.a1, self.a2 == other.a2))


class B:
    a: A
    ta: Type[A]

    def __init__(self, a: A, ta: Type[A]):
        self.a = a
        self.ta = ta

    def __eq__(self, other):
        return all((isinstance(other, B), self.a == other.a, self.ta == other.ta))


@dataclass
class ExampleDataclass:
    int_attr: int
    none_attr: type(None)  # type: ignore
    bool_attr: bool
    str_attr: str
    bytes_attr: bytes
    range_attr: Range
    list_attr: List[bytes]
    heterogeneous_tuple_attr: Tuple[int, type(None)]  # type: ignore
    long_tuple_attr: Tuple[Range, ...]
    nested_list_and_dict: List[List[Dict[str, Range]]]


can_be_slow_settings = settings(
    deadline=None,
    suppress_health_check=(HealthCheck.too_slow, HealthCheck.data_too_large),
)


@pytest.mark.parametrize(
    "type_hint",
    [
        int,
        float,
        type(None),
        bytes,
        str,
        bool,
        Range,
        Tuple[int, ...],
        Tuple[int, str],
        Tuple[Range, ...],
        List[bytes],
        Set[int],
        Optional[List[str]],
        Optional[Dict[bytes, int]],
        Union[str, int],
        Union[List[int], Optional[int]],
        Union[Tuple[int], int],
        Union[Tuple[str, ...], str],
        Union[str, Tuple[str, ...]],
        A,
        B,
        Iterable[int],
        Iterable[str],
    ],
)
@given(data=data())
@settings(parent=can_be_slow_settings, max_examples=50)
def test_to_pjson_hypothesis(type_hint, data, _test_serialize_deserialize):
    obj = data.draw(from_type(type_hint))
    _test_serialize_deserialize(obj, type_hint)


@pytest.mark.parametrize(
    "type_hint",
    [
        List[List[bytes]],
        Set[List[str]],
        Dict[bytes, List[Dict[int, Range]]],
        ExampleDataclass,
    ],
)
@given(data=data())
@settings(parent=can_be_slow_settings, max_examples=10)
def test_to_pjson_hypothesis_slow_types(type_hint, data, _test_serialize_deserialize):
    """Types for which hypothesis will generate big objects and be slow."""
    obj = data.draw(from_type(type_hint))
    _test_serialize_deserialize(obj, type_hint)


class WeirdEnum(Enum):
    """An Enum using heterogeneous and weird types that should still be serializable even if the types used are not."""

    TYPE = type
    MAP = map(hash, [1])  # = <map at ...>


@pytest.mark.parametrize(
    "obj,type_hint",
    [
        (1, Any),
        ("test", Any),
        ([1, 2], Any),
        (InstructionSet.ARM, Enum),  # Enum using strings
        (InstructionSetMode.THUMB, Enum),  # Enum using ints
        (InstructionSetMode.THUMB, InstructionSetMode),
        (WeirdEnum, type),
        (WeirdEnum.TYPE, Enum),
        (WeirdEnum.MAP, Enum),
        (WeirdEnum.MAP, WeirdEnum),
        (ResourceAttributes, Type[ResourceAttributes]),
        (ResourceAttributes, type),
        (ElfHeader, Type[ElfHeader]),
        (ElfHeader, type),
        (FilesystemRoot, Type[FilesystemRoot]),
        (FilesystemRoot, type),
        (FilesystemRoot, ResourceTag),  # ResourceTag is a metaclass of FilesystemRoot
        ([1, 2], Sequence[int]),
        (
            ResourceAttributeDependency(b"id1", b"id2", ResourceAttributes),
            ResourceAttributeDependency,
        ),
        (ResourceAttributeDependency(b"id1", b"id2", Magic), ResourceAttributeDependency),
    ],
)
def test_to_pjson(obj: Any, type_hint: Any, _test_serialize_deserialize):
    _test_serialize_deserialize(obj, type_hint)


data_model = DataModel(b"123", Range(0, 10))

data_node = DataNode(data_model)


@pytest.mark.parametrize(
    "obj",
    [
        IntervalTree(),
        IntervalTree.from_tuples([(0, 10)]),
        IntervalTree.from_tuples([(0, 10, data_node)]),
        IntervalTree.from_tuples([(0, 10), (10, 20, data_node)]),
        IntervalTree([Interval(0, 10)]),
        IntervalTree([Interval(0, 10, data_node)]),
        IntervalTree([Interval(0, 10), Interval(10, 20, data_node)]),
    ],
)
def test_interval_tree_serialization(obj: IntervalTree, _test_serialize_deserialize):
    _test_serialize_deserialize(obj, IntervalTree)


@pytest.mark.parametrize(
    "json_obj,type_hint",
    [
        ([1, 2], List),
        ({1: 2}, Dict),
    ],
)
def test_from_pjson_ambiguous_type_hints(
    json_obj: Any, type_hint: Any, serializer: PJSONSerializationService
):
    with pytest.raises((TypeError, BeartypeCallHintParamViolation)):
        serializer.from_pjson(json_obj, type_hint)


@pytest.mark.parametrize(
    "json_obj,type_hint",
    [
        ("123", List[int]),
        ("123", List[str]),
        ("", List[str]),
        (0, List[int]),
        (0, Union[List[int], bytes]),
    ],
)
def test_from_pjson_invalid_types(
    json_obj: Any, type_hint: Any, serializer: PJSONSerializationService
):
    with pytest.raises((TypeError, BeartypeCallHintParamViolation)):
        serializer.from_pjson(json_obj, type_hint)


def _get_descendants(cls: Type, injector: DependencyInjector) -> List[Type]:
    """Get all the descendants of `cls`, including `cls`, using the already initialized `injector`."""
    return [provider._factory for provider in injector._providers[cls]]


def _get_strict_descendants(cls: Type) -> List[Type]:
    """Get all the descendants of `cls`, excluding `cls`."""
    injector = DependencyInjector()
    import ofrak

    injector.discover(ofrak)

    try:
        import ofrak_components

        injector.discover(ofrak_components)
    except ModuleNotFoundError:
        pass
    return [descendant for descendant in _get_descendants(cls, injector) if descendant != cls]


def _type_and_descendants(superclass_type) -> List[Tuple[Type, Type]]:
    return [(superclass_type, desc) for desc in _get_strict_descendants(superclass_type)]


@pytest.mark.parametrize(
    "superclass_type,descendant_type",
    _type_and_descendants(ResourceView)
    + _type_and_descendants(ResourceAttributes)
    + _type_and_descendants(ComponentFilter)
    + _type_and_descendants(ComponentConfig),
)
@given(data=data())
@settings(parent=can_be_slow_settings, max_examples=10)
def test_ofrak_classes(superclass_type, descendant_type, data, _test_serialize_deserialize):
    """
    Test the serialization of all the classes in the parametrization above, trying both with
    the descendant type as type hint, and the superclass type.
    """
    instance = data.draw(builds(descendant_type))
    _test_serialize_deserialize(instance, descendant_type)
    _test_serialize_deserialize(instance, superclass_type)
