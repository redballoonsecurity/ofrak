import logging
import os
import tempfile
from typing import Optional

from ofrak_type import ArchInfo
from ofrak_type.architecture import InstructionSet
from ofrak_patch_maker.model import PatchRegionConfig
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.model import (
    ToolchainConfig,
    BinFileType,
    Segment,
    CompilerOptimizationLevel,
)
from ofrak_patch_maker.toolchain.utils import get_file_format
from ofrak_patch_maker.toolchain.version import ToolchainVersion
from ofrak_type.memory_permissions import MemoryPermissions


def run_bounds_check_test(toolchain: ToolchainVersion, proc: ArchInfo):
    """
    Example solution patch for bounds_check challenge.
    """
    source_dir = os.path.join(os.path.dirname(__file__), "example_3")
    source_path = os.path.join(source_dir, "bounds_check.c")
    build_dir = tempfile.mkdtemp()

    if proc.isa == InstructionSet.AVR:
        # avr-gcc does not support relocatable
        relocatable = False
    else:
        relocatable = True
    tc_config = ToolchainConfig(
        file_format=BinFileType.ELF,
        force_inlines=True,
        relocatable=relocatable,
        no_std_lib=True,
        no_jump_tables=True,
        no_bss_section=True,
        create_map_files=True,
        compiler_optimization_level=CompilerOptimizationLevel.FULL,
        debug_info=True,
    )

    logger = logging.getLogger("ToolchainTest")
    logger.setLevel("INFO")

    exec_path = os.path.join(build_dir, "fem")
    patch_maker = PatchMaker(
        program_attributes=proc,
        toolchain_config=tc_config,
        toolchain_version=toolchain,
        logger=logger,
        build_dir=build_dir,
    )

    bom = patch_maker.make_bom(
        name="bc",
        source_list=[source_path],
        object_list=[],
        header_dirs=[],
    )

    text_segment = Segment(
        segment_name=".text",
        vm_address=0x6FE173D0,
        offset=0,
        is_entry=False,
        length=64,
        access_perms=MemoryPermissions.RX,
    )
    manual_map = {source_path: (text_segment,)}

    # Grab the resulting object paths and re-map them to the segments we chose for each source file.
    segment_dict = {}
    for src_file in manual_map.keys():
        object_path = bom.object_map[src_file].path
        segment_dict[object_path] = manual_map[src_file]

    # Generate a PatchRegionConfig from your segment Dict.
    # This data structure informs ld script generation which regions to create for every segment.
    p = PatchRegionConfig(bom.name + "_patch", segment_dict)
    fem = patch_maker.make_fem([(bom, p)], exec_path)

    assert os.path.exists(exec_path)
    assert get_file_format(exec_path) == tc_config.file_format


def run_hello_world_test(
    toolchain: ToolchainVersion, proc: ArchInfo, userspace_dynamic_linker: Optional[str] = None
):
    """
    Make sure we can run the toolchain components without falling over.
    """
    source_dir = os.path.join(os.path.dirname(__file__), "example_1")
    source_path = os.path.join(source_dir, "hello_world.c")
    build_dir = tempfile.mkdtemp()

    if toolchain in [ToolchainVersion.GNU_AVR_5]:
        relocatable = False
        base_symbols = {"__mulhi3": 0x1234}  # Dummy address to fix missing symbol
    else:
        relocatable = True
        base_symbols = None
    tc_config = ToolchainConfig(
        file_format=BinFileType.ELF,
        force_inlines=True,
        relocatable=relocatable,
        no_std_lib=True,
        no_jump_tables=True,
        no_bss_section=False,
        create_map_files=True,
        compiler_optimization_level=CompilerOptimizationLevel.FULL,
        debug_info=True,
        userspace_dynamic_linker=userspace_dynamic_linker,
    )

    logger = logging.getLogger("ToolchainTest")
    logger.setLevel("INFO")

    patch_maker = PatchMaker(
        program_attributes=proc,
        toolchain_config=tc_config,
        toolchain_version=toolchain,
        logger=logger,
        build_dir=build_dir,
        base_symbols=base_symbols,
    )

    bom = patch_maker.make_bom(
        name="example_3",
        source_list=[source_path],
        object_list=[],
        header_dirs=[source_dir],
    )

    all_segments = {}
    current_vm_address = 0x10000
    for o in bom.object_map.values():
        seg_list = []
        for s in o.segment_map.values():
            seg_list.append(
                Segment(
                    segment_name=s.segment_name,
                    vm_address=current_vm_address,
                    offset=s.offset,
                    is_entry=s.is_entry,
                    length=s.length,
                    access_perms=s.access_perms,
                )
            )
            current_vm_address += s.length

            if toolchain in [ToolchainVersion.GNU_X86_64_LINUX_EABI_10_3_0]:
                if current_vm_address % 16 > 0:
                    current_vm_address += 16 - current_vm_address % 16
            else:
                if current_vm_address % 4 > 0:
                    current_vm_address += 4 - current_vm_address % 4

        all_segments.update({o.path: tuple(seg_list)})

    bss = patch_maker.create_unsafe_bss_segment(current_vm_address, 0x8000)

    allocator_config = PatchRegionConfig(bom.name + "_patch", all_segments)

    # Skip the config step for now
    exec_path = os.path.join(build_dir, "fem")
    fem = patch_maker.make_fem([(bom, allocator_config)], exec_path, unsafe_bss_segment=bss)

    assert os.path.exists(exec_path)
    assert get_file_format(exec_path) == tc_config.file_format
