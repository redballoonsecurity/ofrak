import logging
import os
from ofrak import tempfile
from ofrak_patch_maker.model import PatchRegionConfig
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.model import (
    ToolchainConfig,
    BinFileType,
    Segment,
    CompilerOptimizationLevel,
)
from ofrak_patch_maker.toolchain.utils import get_file_format
from ofrak_patch_maker_test import ToolchainUnderTest
from ofrak_type.memory_permissions import MemoryPermissions


def run_challenge_3_reloc_toy_example_test(toolchain_under_test: ToolchainUnderTest):
    """
    Example solution patch for bounds_check challenge.
    """
    source_dir = os.path.join(os.path.dirname(__file__), "example_4")
    build_dir = tempfile.mkdtemp()

    # The GNU assembler generates 0-length .data section, no matter what. We must handle it.
    null_data = Segment(
        segment_name=".data",
        vm_address=0,
        offset=0,
        is_entry=False,
        length=0,
        access_perms=MemoryPermissions.RW,
    )

    text_segments = list()
    text_segment_b02 = Segment(
        segment_name=".text",
        vm_address=0xB02,
        offset=0,
        is_entry=False,
        length=0x1000,
        access_perms=MemoryPermissions.RX,
    )
    text_segments.append(text_segment_b02)
    text_segment_cc4 = Segment(
        segment_name=".text",
        vm_address=0xCC4,
        offset=0,
        is_entry=False,
        length=0x1000,
        access_perms=MemoryPermissions.RX,
    )
    text_segments.append(text_segment_cc4)
    text_segment_d18 = Segment(
        segment_name=".text",
        vm_address=0xD16,
        offset=0,
        is_entry=False,
        length=0x1000,
        access_perms=MemoryPermissions.RX,
    )
    text_segments.append(text_segment_d18)
    text_segment_11f4 = Segment(
        segment_name=".text",
        vm_address=0x11F0,
        offset=0,
        is_entry=False,
        length=0x1000,
        access_perms=MemoryPermissions.RX,
    )
    text_segments.append(text_segment_11f4)
    text_segment_1310 = Segment(
        segment_name=".text",
        vm_address=0x1308,
        offset=0,
        is_entry=False,
        length=0x1000,
        access_perms=MemoryPermissions.RX,
    )
    text_segments.append(text_segment_1310)
    text_segment_1380 = Segment(
        segment_name=".text",
        vm_address=0x1378,
        offset=0,
        is_entry=False,
        length=0x1000,
        access_perms=MemoryPermissions.RX,
    )
    text_segments.append(text_segment_1380)

    # If we know a particular immediate value is changing, currently the developer
    # must modify the assembly source in the patch to use a symbol.
    # Since the developer/operator must know, a-priori where that code will need
    # to jump we can provide the symbol here.
    #
    # If we don't want the person to modify source. Toolchain functionality must be added
    # to programmatically search and replace the immediate values (provided in a list)
    # with symbols like reloc_0x13D4_0x13C0 for easy look-up after the fact.
    #
    # The manual approach here is probably better because today because of the complexity required
    # to handle a situation where two identical instructions, like `B 0x13D4`, must branch to
    # two distinct locations (like 0x1340 and 0x13C0), after the fact.
    #
    # We can also approach this problem with some source annotation and analysis via asm comments,
    # which are technically source, but are not parsed by the assembler.

    # Arguably, we could come up with a better way to test these toolchains and construct this
    # `manual_map` in a more intelligent manner... just trying to keep source clutter/duplication
    # down for now.
    source_files = [f for f in os.listdir(source_dir) if toolchain_under_test.extension in f]
    try:
        assert len(source_files) <= len(text_segments)
    except AssertionError:
        raise AssertionError(
            f"Bad test parameters!\n"
            f"Only {len(text_segments)} text segments available for "
            f"{len(source_files)} source files: {source_files}"
        )
    manual_map = dict()
    for i, source_file in enumerate(source_files):
        manual_map.update({os.path.join(source_dir, source_file): (text_segments[i], null_data)})

    tc_config = ToolchainConfig(
        file_format=BinFileType.ELF,
        force_inlines=True,
        relocatable=False,  # important if you want to branch to absolutes!
        no_std_lib=True,
        no_jump_tables=True,
        no_bss_section=True,
        create_map_files=True,
        compiler_optimization_level=CompilerOptimizationLevel.FULL,
        debug_info=True,
        check_overlap=False,  # Note this disables the linker checking for you clobbering yourself.
    )

    logger = logging.getLogger("ToolchainTest")
    logger.setLevel("INFO")

    exec_path = os.path.join(build_dir, "fem")
    patch_maker = PatchMaker(
        toolchain=toolchain_under_test.toolchain(toolchain_under_test.proc, tc_config),
        logger=logger,
        build_dir=build_dir,
        base_symbols={"reloc_0x13ce_0x13d6": 0x13D6},
    )
    bom = patch_maker.make_bom(
        name="program_c_micropatch",
        source_list=list(manual_map.keys()),
        object_list=[],
        header_dirs=[],
    )

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


def run_monkey_patch_test(toolchain_under_test: ToolchainUnderTest):
    """
    Example showing how to manually generate an executable with assembly at client-specified locs.
    """
    source_dir = os.path.join(os.path.dirname(__file__), "example_2")
    source_files = [
        os.path.join(source_dir, x)
        for x in os.listdir(source_dir)
        if toolchain_under_test.extension in x
    ]
    build_dir = tempfile.mkdtemp()

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
    )

    logger = logging.getLogger("ToolchainTest")
    logger.setLevel("INFO")

    exec_path = os.path.join(build_dir, "fem")
    patch_maker = PatchMaker(
        toolchain=toolchain_under_test.toolchain(toolchain_under_test.proc, tc_config),
        logger=logger,
        build_dir=build_dir,
    )

    # The GNU assembler generates 0-length .data section no matter what.
    # The linker requires that even 0-length sections be mapped to a memory region,
    # even a nonsensical one.
    null_data = Segment(
        segment_name=".data",
        vm_address=0,
        offset=0,
        is_entry=False,
        length=0,
        access_perms=MemoryPermissions.RW,
    )

    # When we're "monkey patching" we can't rely on `allocate_bom`
    text0 = Segment(
        segment_name=".text",
        vm_address=0x1000,
        offset=0,
        is_entry=False,
        length=0x80,
        access_perms=MemoryPermissions.RX,
    )

    text1 = Segment(
        segment_name=".text",
        vm_address=0x2000,
        offset=0,
        is_entry=False,
        length=0x80,
        access_perms=MemoryPermissions.RX,
    )

    text2 = Segment(
        segment_name=".text",
        vm_address=0x3000,
        offset=0,
        is_entry=False,
        length=0x80,
        access_perms=MemoryPermissions.RX,
    )

    # Let's map these source files to the segments we hope to drop them in.
    # Use absolute paths because that's how the PatchMaker and Toolchain work with file paths...
    manual_map = {
        os.path.abspath(source_files[0]): (
            text0,
            null_data,
        ),
        os.path.abspath(source_files[1]): (
            text1,
            null_data,
        ),
        os.path.abspath(source_files[2]): (
            text2,
            null_data,
        ),
    }

    # Compile
    bom_name = "new_bom"
    bom = patch_maker.make_bom(
        name=bom_name,
        source_list=list(manual_map.keys()),
        object_list=[],
        header_dirs=[],
    )

    # Grab the resulting object paths and re-map them to the segments we chose for each source file.
    segment_dict = {}
    for src_file in manual_map.keys():
        object_path = bom.object_map[src_file].path
        segment_dict[object_path] = manual_map[src_file]

    # Generate a PatchRegionConfig from your segment Dict.
    # This data structure informs ld script generation which regions to create for every segment.
    p = PatchRegionConfig(bom.name + "_patch", segment_dict)
    fem = patch_maker.make_fem([(bom, p)], exec_path)

    # Run pytest with -sk to check out the .ld script you generated!
    # `SegmentInjectorModifier` will ignore 0-length sections!

    assert os.path.exists(exec_path)
    assert get_file_format(exec_path) == tc_config.file_format
