import os
import pytest
import subprocess

from ofrak_patch_maker.toolchain.llvm_12 import LLVM_12_0_1_Toolchain

ofrak_angr = pytest.importorskip("ofrak_angr")
ofrak_capstone = pytest.importorskip("ofrak_capstone")
from ofrak import OFRAKContext, Resource, ResourceAttributeValueFilter, ResourceFilter
from ofrak.core import (
    Allocatable,
    CodeRegion,
    ComplexBlock,
    Instruction,
    LiefAddSegmentConfig,
    LiefAddSegmentModifier,
    ElfProgramHeader,
)
from ofrak.core.patch_maker.modifiers import (
    PatchFromSourceModifier,
    PatchFromSourceModifierConfig,
    SourceBundle,
)
from ofrak_patch_maker.toolchain.model import (
    ToolchainConfig,
    BinFileType,
    CompilerOptimizationLevel,
    Segment,
)
from ofrak_patch_maker.toolchain.utils import get_file_format
from ofrak_type import Range
from ofrak_type.memory_permissions import MemoryPermissions

PAGE_ALIGN = 0x1000


@pytest.fixture(autouse=True)
def angr_components(ofrak_injector):
    ofrak_injector.discover(ofrak_angr)
    ofrak_injector.discover(ofrak_capstone)


async def test_patch_from_source_modifier(
    ofrak_context: OFRAKContext,
    large_elf_file,
    patch_file,
) -> None:
    async def add_and_return_segment(resource: Resource, vaddr: int, size: int) -> ElfProgramHeader:
        """Add a segment to `elf_resource`, of size `size` at virtual address `vaddr`,
        returning this new segment resource after unpacking."""

        config = LiefAddSegmentConfig(vaddr, PAGE_ALIGN, [0 for _ in range(size)], "rx")
        await resource.run(LiefAddSegmentModifier, config)
        await resource.unpack_recursively()

        # Get our newly added segment. First get all ElfProgramHeaders, then return the one
        # with our virtual address.
        file_segments = await resource.get_descendants_as_view(
            ElfProgramHeader, r_filter=ResourceFilter(tags=(ElfProgramHeader,))
        )
        segment = [seg for seg in file_segments if seg.p_vaddr == vaddr].pop()

        # Carve out a child of the new segment where we can store the code for our new function.
        code_region = CodeRegion(segment.p_vaddr, segment.p_filesz)
        code_region.resource = await resource.create_child_from_view(
            code_region, data_range=Range(segment.p_offset, segment.p_offset + segment.p_filesz)
        )
        resource.add_tag(Allocatable)
        await resource.save()

        return segment

    async def call_new_segment_instead(root_resource: Resource, new_segment: ElfProgramHeader):
        """Replace the original `call` instruction in main with a call to the start of `new_segment`."""
        main_cb = await root_resource.get_only_descendant_as_view(
            v_type=ComplexBlock,
            r_filter=ResourceFilter(
                attribute_filters=(ResourceAttributeValueFilter(ComplexBlock.Symbol, "main"),)
            ),
        )

        call_instruction = await main_cb.resource.get_only_descendant_as_view(
            v_type=Instruction,
            r_filter=ResourceFilter(
                attribute_filters=(ResourceAttributeValueFilter(Instruction.Mnemonic, "call"),)
            ),
        )

        await call_instruction.modify_assembly("call", f"0x{new_segment.p_vaddr:x}")

    async def apply_patch(resource: Resource, source_dir: str, new_segment: ElfProgramHeader):
        # The PatchMaker will need to know how to configure the build toolchain.
        tc_config = ToolchainConfig(
            file_format=BinFileType.ELF,
            force_inlines=True,
            relocatable=False,
            no_std_lib=True,
            no_jump_tables=True,
            no_bss_section=True,
            create_map_files=True,
            compiler_optimization_level=CompilerOptimizationLevel.SPACE,
            debug_info=False,
            check_overlap=False,
        )

        # Tell the PatchMaker about the segment we added in the binary...
        text_segment_patch = Segment(
            segment_name=".text",
            vm_address=new_segment.p_vaddr,
            offset=0,
            is_entry=False,
            length=new_segment.p_filesz,
            access_perms=MemoryPermissions.RX,
        )

        # ... And that we want to put the compiled C patch there.
        patch_source: str = os.path.join(source_dir, "patch.c")
        segment_dict = {
            patch_source: (text_segment_patch,),
        }

        # Tell PatcherFromSourceModifier about the source files, toolchain, and patch name.
        patch_from_source_config = PatchFromSourceModifierConfig(
            SourceBundle.slurp(source_dir),
            segment_dict,
            tc_config,
            LLVM_12_0_1_Toolchain,
            patch_name="test_patch",
        )

        # Run PatchFromSourceModifier, which will analyze the target binary, run PatchMaker on our
        # patch, create a Batch of Objects and Metadata (BOM) for the patch, create a BOM from the
        # target binary for all unresolved symbols in the patch, make a Final Executable and Metadata
        # (FEM), and then inject our patch into the binary.
        await resource.run(PatchFromSourceModifier, patch_from_source_config)

    resource = await ofrak_context.create_root_resource_from_file(large_elf_file)
    new_segment = await add_and_return_segment(resource, 0x440000, 0x2000)

    output_file_name = os.path.join(os.path.dirname(patch_file), "test_patch")

    source_dir = os.path.join(os.path.dirname(patch_file))

    await apply_patch(resource, source_dir, new_segment)
    await call_new_segment_instead(resource, new_segment)

    await resource.pack()
    await resource.flush_data_to_disk(output_file_name)

    assert os.path.exists(output_file_name)
    assert get_file_format(output_file_name) == BinFileType.ELF

    subprocess.run(["chmod", "+x", output_file_name])
    result = subprocess.run([output_file_name], capture_output=True)
    assert result.returncode == 36
