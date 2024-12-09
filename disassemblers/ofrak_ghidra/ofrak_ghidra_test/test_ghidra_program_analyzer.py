import os.path
import os.path
import tempfile
from typing import Dict, Type

import pytest

from ofrak import OFRAKContext
from ofrak.core import (
    Program,
    ProgramAttributes,
    NamedProgramSection,
    MemoryRegion,
    CodeRegion,
    Elf,
    SegmentInjectorModifier,
    SegmentInjectorModifierConfig,
)
from ofrak.resource import Resource
from ofrak_ghidra.ghidra_model import GhidraProject, GhidraCustomLoadProject
from ofrak_patch_maker.model import PatchRegionConfig
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.abstract import Toolchain
from ofrak_patch_maker.toolchain.gnu_aarch64 import GNU_AARCH64_LINUX_10_Toolchain
from ofrak_patch_maker.toolchain.gnu_arm import GNU_ARM_NONE_EABI_10_2_1_Toolchain
from ofrak_patch_maker.toolchain.gnu_ppc import GNU_PPC_LINUX_10_Toolchain
from ofrak_patch_maker.toolchain.gnu_vbcc_m68k import VBCC_0_9_GNU_Hybrid_Toolchain
from ofrak_patch_maker.toolchain.gnu_x64 import GNU_X86_64_LINUX_EABI_10_3_0_Toolchain
from ofrak_patch_maker.toolchain.model import (
    ToolchainConfig,
    CompilerOptimizationLevel,
    BinFileType,
    Segment,
)
from ofrak_type import BitWidth, Endianness, InstructionSet, MemoryPermissions, Range


async def test_ghidra_project_analyzer(hello_world_elf_resource: Resource):
    """
    Test that the
    [GhidraProject][ofrak_ghidra.components.ghidra_analyzer.GhidraProject] object can
    be successfully generated
    """
    hello_world_elf_resource.add_tag(Elf)
    await hello_world_elf_resource.save()
    await hello_world_elf_resource.identify()
    ghidra_project = await hello_world_elf_resource.view_as(GhidraProject)
    assert isinstance(ghidra_project, GhidraProject)


@pytest.mark.parametrize(
    "arch_info",
    [
        ProgramAttributes(
            InstructionSet.PPC,
            None,
            BitWidth.BIT_32,
            Endianness.BIG_ENDIAN,
            None,
        ),
        ProgramAttributes(
            InstructionSet.ARM,
            None,
            BitWidth.BIT_32,
            Endianness.LITTLE_ENDIAN,
            None,
        ),
        ProgramAttributes(
            InstructionSet.M68K,
            None,
            BitWidth.BIT_32,
            Endianness.BIG_ENDIAN,
            None,
        ),
        ProgramAttributes(
            InstructionSet.X86,
            None,
            BitWidth.BIT_64,
            Endianness.LITTLE_ENDIAN,
            None,
        ),
        ProgramAttributes(
            InstructionSet.AARCH64,
            None,
            BitWidth.BIT_64,
            Endianness.BIG_ENDIAN,
            None,
        ),
    ],
    ids=lambda arch_info: f"{arch_info.isa.name}-{arch_info.bit_width.value}-{arch_info.endianness.value}",
)
async def test_ghidra_custom_loader(ofrak_context: OFRAKContext, arch_info: ProgramAttributes):
    file_data = b"\xed" * 0x10000

    prog = await ofrak_context.create_root_resource("test_custom_load", data=file_data)

    prog.add_tag(Program)
    prog.add_attributes(arch_info)
    await prog.save()

    await prog.create_child_from_view(
        NamedProgramSection(0x0, 0x1000, "FIRST_SECTION"), data_range=Range.from_size(0x0, 0x1000)
    )
    await prog.create_child_from_view(
        MemoryRegion(0x1000, 0x1000), data_range=Range.from_size(0x1000, 0x1000)
    )
    cr_child = await prog.create_child_from_view(
        CodeRegion(0x2000, 0x1000), data_range=Range.from_size(0x2000, 0x1000)
    )

    await _make_dummy_program(prog, arch_info)

    await prog.identify()
    assert prog.has_tag(GhidraCustomLoadProject)

    ghidra_project = await prog.view_as(GhidraProject)
    assert isinstance(ghidra_project, GhidraProject)

    await cr_child.unpack()
    children = list(await cr_child.get_children())
    assert 2 == len(children)


async def _make_dummy_program(resource: Resource, arch_info):
    src = """
    int foo(int x, int y);
    
    int main(int argc, char** argv){
        int x = 5;
        int y = 3;
        for (int i = 0; i < x; i++){
            y *= argc;
        }
        
        return foo(x, y);
    }
    
    int foo(int x, int y){
        switch (x){
            case 1:
                return y + 2;
            case 2:
                return y * 2;
            case 3:
                return y * y;
            default:
                return x + y;
        
        }
    }
    """

    arch_map: Dict[InstructionSet, Type[Toolchain]] = {
        InstructionSet.PPC: GNU_PPC_LINUX_10_Toolchain,
        InstructionSet.ARM: GNU_ARM_NONE_EABI_10_2_1_Toolchain,
        InstructionSet.M68K: VBCC_0_9_GNU_Hybrid_Toolchain,
        InstructionSet.AARCH64: GNU_AARCH64_LINUX_10_Toolchain,
        InstructionSet.X86: GNU_X86_64_LINUX_EABI_10_3_0_Toolchain,
    }

    tc = arch_map[arch_info.isa](
        arch_info,
        toolchain_config=ToolchainConfig(
            file_format=BinFileType.ELF,
            force_inlines=True,
            relocatable=True,
            no_std_lib=True,
            no_jump_tables=True,
            no_bss_section=True,
            compiler_optimization_level=CompilerOptimizationLevel.NONE,
            compiler_target=None,
            compiler_cpu=None,
            assembler_target=None,
            assembler_cpu=None,
        ),
    )
    build_dir = tempfile.mkdtemp()
    pm = PatchMaker(tc, build_dir=build_dir)

    src_path = os.path.join(build_dir, "src.c")
    with open(src_path, "w") as f:
        f.write(src)

    bom = pm.make_bom("name", [src_path], [], [])

    patch_config = PatchRegionConfig(
        "name",
        {
            list(bom.object_map.values())[0].path: (
                Segment(".text", 0x2000, 0x0, True, 0x800, MemoryPermissions.RX),
            ),
        },
    )

    exec_path = os.path.join(build_dir, "exec")

    fem = pm.make_fem([(bom, patch_config)], exec_path)

    await resource.run(
        SegmentInjectorModifier,
        SegmentInjectorModifierConfig.from_fem(fem),
    )
