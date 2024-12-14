import tempfile
from dataclasses import dataclass
from io import BytesIO
from typing import List, Tuple

import pytest

from ofrak import OFRAKContext
from ofrak.core.binary import GenericBinary, GenericText
from ofrak.core.elf.model import Elf
from ofrak.core.filesystem import FilesystemRoot
from ofrak.core.patch_maker.linkable_binary import LinkableBinary
from ofrak.core.program import Program
from ofrak.model.component_model import ComponentContext
from ofrak.model.resource_model import ResourceAttributes, ResourceContext
from ofrak.model.viewable_tag_model import AttributesType, ResourceViewContext
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_type.range import Range
from test_ofrak.unit.component import mock_component
from test_ofrak.unit.component.mock_component import (
    MockFailException,
    MockFile,
    MockFailFile,
)

# Ignore the type below until MyPy supports recursive type definitions :(
# https://github.com/python/mypy/issues/731
NestedList = List[Tuple[bytes, "NestedList"]]  # type: ignore


@pytest.fixture
def resource(ofrak_context: OFRAKContext):
    resource = ofrak_context.create_root_resource("yummy", b"\x00\x00\x00\x00")
    _ = resource.create_child(data_range=Range(0, 1))
    return resource


@pytest.fixture
def nested_resource_children() -> NestedList:
    return [
        (b"first", [(b"first_first", []), (b"first_second", []), (b"first_third", [])]),
        (b"second", []),
        (b"third", []),
        (b"fourth", []),
        (b"fifth", []),
    ]


def test_get_children_does_not_return_self_no_filter(resource: Resource):
    """
    Test that ``Resource.get_children`` does not return itself as a child
    when no resource filters are provided.

    :param resource:
    :return:
    """
    children = list(resource.get_children())
    assert 1 == len(children)


def test_get_children_does_not_return_self_filter_include_self_false(
    resource: Resource,
):
    """
    Test that ``Resource.get_children`` does not return itself as a child
    with a ``ResourceFilter`` that has ``include_self`` set to False.

    :param resource:
    :return:
    """
    children = list(resource.get_children(ResourceFilter(False)))
    assert 1 == len(children)


def test_get_children_returns_self_filter_include_self_true(resource: Resource):
    """
    Test that ``Resource.get_children`` returns itself as a child with a ``ResourceFilter``
    that has `include_self`` set to True.

    :param resource:
    :return:
    """
    children = list(resource.get_children(ResourceFilter(True)))
    assert 2 == len(children)
    assert resource.get_id() in [child.get_id() for child in children]


def recursively_add_children(parent: Resource, children: NestedList):
    for data, grandchildren in children:
        child = parent.create_child(data=data)
        recursively_add_children(child, grandchildren)


def recursively_validate_children(parent: Resource, children: NestedList):
    # Cast to list so it can be non-destructively iterated over several times
    resource_children = list(parent.get_children())
    assert len(resource_children) == len(children), (
        f"Resource {parent.get_id().hex()} has the wrong number of children. "
        f"Expected {len(children)}; got {len(resource_children)}."
    )
    for resource_child, (original_data, grandchildren) in zip(resource_children, children):
        data = resource_child.get_data()
        assert (
            data == original_data
        ), f"Child data {data.decode()} does not equal reference data {original_data.decode()}"
        recursively_validate_children(resource_child, grandchildren)


def test_get_children_order_preserved(
    ofrak_context: OFRAKContext, nested_resource_children: NestedList
):
    """
    Test that resource children are returned in the same order that they were added.

    :param ofrak_context:
    :param nested_resource_children:
    """
    resource = ofrak_context.create_root_resource("root", b"root data")
    recursively_add_children(resource, nested_resource_children)
    recursively_validate_children(resource, nested_resource_children)


def test_add_view(resource: Resource):
    """
    Test that ``Resource.add_view`` adds each the attributes in the view and the tag
    correctly.

    :param resource:
    :return:
    """

    @dataclass
    class DummyViewA(ResourceView):
        a: int

    @dataclass
    class DummyViewB(DummyViewA):
        b: int

    a = 0x1000
    b = 0x8

    assert not resource.has_tag(DummyViewA)
    assert not resource.has_tag(DummyViewB)
    assert not resource.has_attributes(AttributesType[DummyViewA])
    assert not resource.has_attributes(AttributesType[DummyViewB])

    resource.add_view(DummyViewB(a, b))

    assert resource.has_tag(DummyViewA)
    assert resource.has_tag(DummyViewB)
    assert resource.has_attributes(AttributesType[DummyViewA])
    assert resource.has_attributes(AttributesType[DummyViewB])

    view = resource.view_as(DummyViewB)
    assert view.a == a
    assert view.b == b


def test_save_applies_patches(resource: Resource):
    original_data = resource.get_data()
    resource.queue_patch(Range(2, 4), b"\xff")
    data_after_patch = resource.get_data()
    assert data_after_patch == original_data
    resource.save()
    data_after_save = resource.get_data()
    assert data_after_save != original_data
    assert len(data_after_save) == (len(original_data) - 1)
    assert data_after_save == original_data[:2] + b"\xff"

    # Check that patch is not double-applied
    resource.save()
    data_after_second_save = resource.get_data()
    assert data_after_save == data_after_second_save


def test_get_most_specific_tags(resource: Resource):
    resource.add_tag(GenericBinary, GenericText, FilesystemRoot, LinkableBinary, Program, Elf)

    expected_most_specific_tags = {GenericText, FilesystemRoot, Elf}
    assert set(resource.get_most_specific_tags()) == expected_most_specific_tags


@pytest.fixture(autouse=True)
def mock_ofrak_component(ofrak):
    ofrak.injector.discover(mock_component)


@pytest.mark.asyncio
def test_flush_to_disk_pack(ofrak_context: OFRAKContext):
    # This test works as long as LZMA fails to pack() and the default is to
    # pack recursively. The root resource is a LZMA archive in a LZMA archive,
    # which as of 2022-09-13 will fail to pack and therefore pack_recursively
    # won't work.

    root_resource = ofrak_context.create_root_resource("mock", b"\x00" * 0x100)
    root_resource.add_tag(MockFile)

    child = root_resource.create_child((MockFailFile,), data_range=Range(0x10, 0x20))
    child.add_tag(MockFailFile)

    with BytesIO() as buffer:
        # should fail because write_to runs pack_recursively and MockFailFile will fail on packing
        with pytest.raises(MockFailException):
            root_resource.write_to(buffer)

        # this should not fail because pack_recursively was suppressed
        root_resource.write_to(buffer, pack=False)

    with tempfile.NamedTemporaryFile() as t:
        # again, should fail because the packer is run automatically
        with pytest.raises(MockFailException):
            root_resource.flush_data_to_disk(t.name)

        root_resource.flush_data_to_disk(t.name, pack=False)


def test_is_modified(resource: Resource):
    """
    Test Resource.is_modified raises true if the local resource is "dirty".
    """
    assert resource.is_modified() is False

    resource.add_tag(Elf)

    assert resource.is_modified() is True


def test_summarize(resource: Resource):
    """
    Test that the resource string summary returns a string
    """
    summary = resource.summarize()
    assert isinstance(summary, str)


def test_summarize_tree(resource: Resource):
    summary = resource.summarize_tree()
    assert isinstance(summary, str)


def test_get_range_within_parent(resource: Resource):
    """
    Test that Resource.get_data_range_within_parent returns the correctly-mapped range.
    """
    child_range = Range(1, 3)
    child = resource.create_child(data_range=child_range)
    data_range_within_parent = child.get_data_range_within_parent()
    assert data_range_within_parent == child_range

    grandchild_range = Range(1, 2)
    grandchild = child.create_child(data_range=grandchild_range)
    data_range_within_child = grandchild.get_data_range_within_parent()
    assert data_range_within_child == grandchild_range


def test_get_range_within_parent_for_root(resource: Resource):
    """
    Resource.get_data_range_within_parent returns Range(0, 0) if the resource is not mapped.
    """
    assert resource.get_data_range_within_parent() == Range(0, 0)


def test_identify(resource: Resource):
    resource.identify()
    assert resource.has_tag(GenericBinary) is True
    assert resource.has_tag(Elf) is False


def test_get_tags(resource: Resource):
    tags = resource.get_tags()
    assert GenericBinary in tags
    assert Elf not in tags

    resource.add_tag(Elf)
    updated_tags = resource.get_tags()
    assert Elf in updated_tags


def test_repr(resource: Resource):
    result = resource.__repr__()
    assert result.startswith("Resource(resource_id=")
    assert "GenericBinary" in result


def test_attributes(resource: Resource):
    """
    Test Resource.{has_attributes, add_attributes, remove_attributes}
    """

    @dataclass(**ResourceAttributes.DATACLASS_PARAMS)
    class DummyAttributes(ResourceAttributes):
        name: str

    dummy_attributes = DummyAttributes("dummy")
    assert resource.has_attributes(DummyAttributes) is False

    resource.add_attributes(dummy_attributes)
    assert resource.has_attributes(DummyAttributes) is True

    resource.remove_attributes(DummyAttributes)
    assert resource.has_attributes(DummyAttributes) is False


def test_create_child_data_and_data_range(ofrak_context: OFRAKContext):
    """
    Assert that passing both data and data_range to `Resource.create_child` raises a ValueError.
    """
    resource = ofrak_context.create_root_resource(name="test_file", data=b"\xff" * 10)
    with pytest.raises(ValueError):
        resource.create_child(data=b"\x00", data_range=Range(0, 1))


def test_get_contexts(resource: Resource):
    assert isinstance(resource.get_resource_context(), ResourceContext)
    assert isinstance(resource.get_resource_view_context(), ResourceViewContext)
    assert isinstance(resource.get_component_context(), ComponentContext)

    # Outside the context of a component, resources don't have job run contexts
    assert resource.get_job_context() is None
