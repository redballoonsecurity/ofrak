import pytest
import os
from .. import components
from ofrak import OFRAKContext, Resource
from ofrak_type.error import NotFoundError
from ofrak.resource import MultipleResourcesFoundError
from ofrak.core import Elf, CodeRegion, Addressable
from ofrak.service.resource_service_i import ResourceFilter, ResourceAttributeValueFilter


@pytest.fixture
async def resource_hello_elf_dyn(ofrak_context: OFRAKContext) -> Resource:
    """
    An ELF file to test the get_descendants / get_ancestors functionality.
    """
    file_path = os.path.join(components.ASSETS_DIR, "elf", "hello_elf_dyn")
    return await ofrak_context.create_root_resource_from_file(file_path)


async def test_get_descendants_0(resource_hello_elf_dyn: Resource):
    """
    Test that get_descendants retrieves all five executable segments in the ELF file.
    """
    await resource_hello_elf_dyn.unpack()
    code_regions = await resource_hello_elf_dyn.get_descendants(
        r_filter=ResourceFilter(
            tags=(CodeRegion,),
        ),
    )
    assert len(list(code_regions)) == 5


async def test_get_descendants_1(resource_hello_elf_dyn: Resource):
    """
    Test that get_descendants does not retrieve CodeRegions that have not been analyzed yet.
    """
    await resource_hello_elf_dyn.unpack()
    code_regions = await resource_hello_elf_dyn.get_descendants(
        r_filter=ResourceFilter(
            tags=(CodeRegion,),
            attribute_filters=(ResourceAttributeValueFilter(Addressable.VirtualAddress, 0x1050),),
        ),
    )
    # The CodeRegions have not been analyzed and therefore do not have a virtual_address attribute.
    # Consequently, they are filtered out by the ResourceAttributeValueFilter.
    assert len(list(code_regions)) == 0


async def test_get_only_descendant_0(resource_hello_elf_dyn: Resource):
    """
    Test that get_only_descendant throws an error when it finds multiple descendants that match the filter.
    """
    await resource_hello_elf_dyn.unpack()
    with pytest.raises(MultipleResourcesFoundError):
        await resource_hello_elf_dyn.get_only_descendant(
            r_filter=ResourceFilter(
                tags=(CodeRegion,),
            ),
        )


async def test_get_only_descendant_1(resource_hello_elf_dyn: Resource):
    """
    Test that get_only_descendant throws an error when it does not find any descendants that match the filter. Note that the CodeRegion exists, but it has not been analyzed yet and therefore does not have the `virtual_address` attribute that is filtered for.
    """
    await resource_hello_elf_dyn.unpack()
    with pytest.raises(NotFoundError):
        # The CodeRegions have not been analyzed and therefore do not have a virtual_address attribute.
        # Consequently, they are filtered out by the ResourceAttributeValueFilter.
        await resource_hello_elf_dyn.get_only_descendant(
            r_filter=ResourceFilter(
                tags=(CodeRegion,),
                attribute_filters=(
                    ResourceAttributeValueFilter(Addressable.VirtualAddress, 0x1050),
                ),
            ),
        )


async def test_get_descendants_as_view_0(resource_hello_elf_dyn: Resource):
    """
    Test that get_descendants_as_view retrieves all five executable segments in the ELF file.
    """
    await resource_hello_elf_dyn.unpack()
    code_regions = list(
        await resource_hello_elf_dyn.get_descendants_as_view(
            v_type=CodeRegion,
            r_filter=ResourceFilter(
                tags=(CodeRegion,),
            ),
        )
    )
    assert len(code_regions) == 5 and all(isinstance(cr, CodeRegion) for cr in code_regions)


async def test_get_descendants_as_view_1(resource_hello_elf_dyn: Resource):
    """
    Test that get_descendants_as_view retrieves the one executable segment with the specified virtual address in the ELF file.
    """
    await resource_hello_elf_dyn.unpack()
    code_regions = list(
        await resource_hello_elf_dyn.get_descendants_as_view(
            v_type=CodeRegion,
            r_filter=ResourceFilter(
                tags=(CodeRegion,),
                attribute_filters=(
                    ResourceAttributeValueFilter(Addressable.VirtualAddress, 0x1050),
                ),
            ),
        )
    )
    assert len(code_regions) == 1 and all(isinstance(cr, CodeRegion) for cr in code_regions)


async def test_get_descendants_as_view_2(resource_hello_elf_dyn: Resource):
    """
    Test that get_descendants_as_view does not retrieve non-existing executable segments.
    """
    await resource_hello_elf_dyn.unpack()
    non_existing_segments = await resource_hello_elf_dyn.get_descendants_as_view(
        v_type=CodeRegion,
        r_filter=ResourceFilter(
            tags=(CodeRegion,),
            attribute_filters=(
                ResourceAttributeValueFilter(Addressable.VirtualAddress, 0xDEADBEEF),
            ),
        ),
    )
    assert len(list(non_existing_segments)) == 0


async def test_get_only_descendant_as_view_0(resource_hello_elf_dyn: Resource):
    """
    Test that get_only_descendant_as_view retrieves the one executable segment with the specified virtual address in the ELF file.
    """
    await resource_hello_elf_dyn.unpack()
    text_segment = await resource_hello_elf_dyn.get_only_descendant_as_view(
        v_type=CodeRegion,
        r_filter=ResourceFilter(
            tags=(CodeRegion,),
            attribute_filters=(ResourceAttributeValueFilter(Addressable.VirtualAddress, 0x1050),),
        ),
    )
    assert isinstance(text_segment, CodeRegion)


async def test_get_only_descendant_as_view_1(resource_hello_elf_dyn: Resource):
    """
    Test that get_only_descendant_as_view throws an error if it does not find a non-existing executable segments.
    """
    await resource_hello_elf_dyn.unpack()
    with pytest.raises(NotFoundError):
        await resource_hello_elf_dyn.get_only_descendant_as_view(
            v_type=CodeRegion,
            r_filter=ResourceFilter(
                tags=(CodeRegion,),
                attribute_filters=(
                    ResourceAttributeValueFilter(Addressable.VirtualAddress, 0xDEADBEEF),
                ),
            ),
        )


async def test_get_only_descendant_as_view_2(resource_hello_elf_dyn: Resource):
    """
    Test that get_only_descendant_as_view throws an error when it finds multiple descendants that match the filter.
    """
    await resource_hello_elf_dyn.unpack()
    with pytest.raises(MultipleResourcesFoundError):
        await resource_hello_elf_dyn.get_only_descendant_as_view(
            v_type=CodeRegion,
            r_filter=ResourceFilter(
                tags=(CodeRegion,),
            ),
        )


async def test_get_descendants_combined_1(resource_hello_elf_dyn: Resource):
    """
    Test that get_descendants_as_view implicitly performs analysis on its retrieved components, making them retrievable by get_descendants.
    """
    await resource_hello_elf_dyn.unpack()
    await resource_hello_elf_dyn.get_descendants_as_view(
        v_type=CodeRegion,
        r_filter=ResourceFilter(
            tags=(CodeRegion,),
        ),
    )
    code_regions = await resource_hello_elf_dyn.get_descendants(
        r_filter=ResourceFilter(
            tags=(CodeRegion,),
            attribute_filters=(ResourceAttributeValueFilter(Addressable.VirtualAddress, 0x1050),),
        ),
    )

    assert len(list(code_regions)) == 1


async def test_get_only_anscestor_as_view(resource_hello_elf_dyn: Resource):
    """
    Test that get_only_ancestor_as_view returns a resource of correct type
    """
    await resource_hello_elf_dyn.unpack()
    text_segment = await resource_hello_elf_dyn.get_only_descendant_as_view(
        v_type=CodeRegion,
        r_filter=ResourceFilter(
            tags=(CodeRegion,),
            attribute_filters=(ResourceAttributeValueFilter(Addressable.VirtualAddress, 0x1050),),
        ),
    )
    elf = await text_segment.resource.get_only_ancestor_as_view(
        v_type=Elf,
        r_filter=ResourceFilter(
            tags=(Elf,),
        ),
    )

    assert isinstance(elf, Elf)
