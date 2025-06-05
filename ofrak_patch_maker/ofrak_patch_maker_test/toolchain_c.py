from dataclasses import replace
import logging
import os
import tempfile

from ofrak_patch_maker.model import PatchRegionConfig
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.gnu_avr import GNU_AVR_5_Toolchain
from ofrak_patch_maker.toolchain.gnu_bcc_sparc import GNU_BCC_SPARC_Toolchain
from ofrak_patch_maker.toolchain.gnu_vbcc_m68k import VBCC_0_9_GNU_Hybrid_Toolchain
from ofrak_patch_maker.toolchain.gnu_x64 import GNU_X86_64_LINUX_EABI_10_3_0_Toolchain
from ofrak_patch_maker.toolchain.model import (
    ToolchainConfig,
    BinFileType,
    Segment,
    CompilerOptimizationLevel,
)
from ofrak_patch_maker.toolchain.utils import get_file_format
from ofrak_patch_maker_test import ToolchainUnderTest
from ofrak_type.memory_permissions import MemoryPermissions


def run_bounds_check_test(toolchain_under_test: ToolchainUnderTest):
    """
    Example solution patch for bounds_check challenge.
    """
    source_dir = os.path.join(os.path.dirname(__file__), "example_3")
    source_path = os.path.join(source_dir, "bounds_check.c")
    build_dir = tempfile.mkdtemp()

    tc_config = ToolchainConfig(
        file_format=BinFileType.ELF,
        force_inlines=True,
        relocatable=False,
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
        toolchain=toolchain_under_test.toolchain(toolchain_under_test.proc, tc_config),
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
        # This size is somewhat arbitrary, and can be increased to make tests
        # pass if necessary
        length=0x100,
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


def run_hello_world_test(toolchain_under_test: ToolchainUnderTest):
    """
    Make sure we can run the toolchain components without falling over.
    """
    source_dir = os.path.join(os.path.dirname(__file__), "example_1")
    source_path = os.path.join(source_dir, "hello_world.c")
    build_dir = tempfile.mkdtemp()

    if toolchain_under_test.toolchain == GNU_AVR_5_Toolchain:
        base_symbols = {"__mulhi3": 0x1234}  # Dummy address to fix missing symbol
    elif toolchain_under_test.toolchain == GNU_BCC_SPARC_Toolchain:
        base_symbols = {".umul": 0x1234}  # Dummy address to fix missing symbol
    else:
        base_symbols = None
    tc_config = ToolchainConfig(
        file_format=BinFileType.ELF,
        force_inlines=True,
        relocatable=False,
        no_std_lib=True,
        no_jump_tables=True,
        no_bss_section=False,
        create_map_files=True,
        compiler_optimization_level=CompilerOptimizationLevel.FULL,
        debug_info=True,
        userspace_dynamic_linker=toolchain_under_test.userspace_dynamic_linker,
    )

    logger = logging.getLogger("ToolchainTest")
    logger.setLevel("INFO")

    toolchain = toolchain_under_test.toolchain(toolchain_under_test.proc, tc_config)
    patch_maker = PatchMaker(
        toolchain=toolchain,
        logger=logger,
        build_dir=build_dir,
        base_symbols=base_symbols,
    )

    bom = patch_maker.make_bom(
        name="example_1",
        source_list=[source_path],
        object_list=[],
        header_dirs=[source_dir],
    )

    all_segments = {}
    current_vm_address = 0x10000
    for o in bom.object_map.values():
        seg_list = []
        for s in o.segment_map.values():
            if s.segment_name == ".bss.legacy":
                # test legacy allocation of .bss
                seg_list.append(replace(s, vm_address=Segment.BSS_LEGACY_VADDR))
                # Set the unsafe .bss size to exactly this length, the other .bss section
                # will be allocated the normal way
                unsafe_bss_size = s.length
            else:
                seg_list.append(replace(s, vm_address=current_vm_address))
                current_vm_address += s.length

                if toolchain_under_test.toolchain in [GNU_X86_64_LINUX_EABI_10_3_0_Toolchain]:
                    if current_vm_address % 16 > 0:
                        current_vm_address += 16 - current_vm_address % 16
                else:
                    if current_vm_address % 4 > 0:
                        current_vm_address += 4 - current_vm_address % 4

        all_segments.update({o.path: tuple(seg_list)})

    # TODO: can we get VBCC/GNU hybrid toolchain to emit separate .bss sections for testing?
    if toolchain_under_test.toolchain == VBCC_0_9_GNU_Hybrid_Toolchain:
        unsafe_bss_size = 8000
    else:
        current_vm_address += 16 - current_vm_address % 16  # align unsafe .bss segment

    bss = patch_maker.create_unsafe_bss_segment(current_vm_address, unsafe_bss_size)

    allocator_config = PatchRegionConfig(bom.name + "_patch", all_segments)

    # Skip the config step for now
    exec_path = os.path.join(build_dir, "fem")
    fem = patch_maker.make_fem([(bom, allocator_config)], exec_path, unsafe_bss_segment=bss)

    assert os.path.exists(exec_path)
    assert get_file_format(exec_path) == tc_config.file_format


def run_relocatable_test(toolchain_under_test: ToolchainUnderTest, build_dir):
    """
    Use patchmaker to link on a relocatable binary
    """
    source_dir = os.path.join(os.path.dirname(__file__), "example_5")
    source_path = os.path.join(source_dir, "patch.c")

    base_symbols = {
        "debug_printf": 0x2000,
        "debug_string": 0x4000,
    }
    tc_config = ToolchainConfig(
        file_format=BinFileType.ELF,
        force_inlines=True,
        relocatable=True,
        no_std_lib=True,
        no_jump_tables=True,
        no_bss_section=True,
        create_map_files=True,
        compiler_optimization_level=CompilerOptimizationLevel.FULL,
        debug_info=True,
        userspace_dynamic_linker=toolchain_under_test.userspace_dynamic_linker,
    )

    logger = logging.getLogger("ToolchainTest")
    logger.setLevel("INFO")

    toolchain = toolchain_under_test.toolchain(toolchain_under_test.proc, tc_config)
    patch_maker = PatchMaker(
        toolchain=toolchain,
        logger=logger,
        build_dir=build_dir,
        base_symbols=base_symbols,
    )

    bom = patch_maker.make_bom(
        name="example_5",
        source_list=[source_path],
        object_list=[],
        header_dirs=[source_dir],
    )

    all_segments = {}
    current_vm_address = 0x10000
    for o in bom.object_map.values():
        seg_list = []
        for s in o.segment_map.values():
            seg_list.append(replace(s, vm_address=current_vm_address))
            current_vm_address += s.length

            if toolchain_under_test.toolchain in [GNU_X86_64_LINUX_EABI_10_3_0_Toolchain]:
                if current_vm_address % 16 > 0:
                    current_vm_address += 16 - current_vm_address % 16
            else:
                if current_vm_address % 4 > 0:
                    current_vm_address += 4 - current_vm_address % 4
        # Linking a PIE object requires a .got segment
        seg_list.append(
            Segment(
                ".got",
                0x9000,
                0,
                is_entry=False,
                length=0x1000,
                access_perms=MemoryPermissions.R,
            )
        )
        all_segments.update({o.path: tuple(seg_list)})

    allocator_config = PatchRegionConfig(bom.name + "_patch", all_segments)

    # Skip the config step for now
    exec_path = os.path.join(build_dir, "fem")
    fem = patch_maker.make_fem([(bom, allocator_config)], exec_path)

    assert os.path.exists(exec_path)
    assert get_file_format(exec_path) == tc_config.file_format
