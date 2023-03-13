import pytest
import tempfile

from dataclasses import dataclass
from immutabledict import immutabledict
from ofrak_patch_maker.toolchain.llvm_12 import LLVM_12_0_1_Toolchain
from ofrak.core.architecture import ProgramAttributes
from ofrak_type.architecture import (
    InstructionSet,
)
from ofrak_patch_maker.model import AssembledObject
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.model import (
    CompilerOptimizationLevel,
    BinFileType,
    Segment,
    ToolchainConfig,
)
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness
from ofrak_type.memory_permissions import MemoryPermissions
from ofrak_type.symbol_type import LinkableSymbolType

PARAMS = [
    {"rel_symbol": {}, "expected_value": 0},
    {"rel_symbol": {"foo": (0, LinkableSymbolType.UNDEF)}, "expected_value": 0},
    {"rel_symbol": {"bar": (0, LinkableSymbolType.UNDEF)}, "expected_value": 1},
]


@dataclass
class TestCase:
    assembled_object: AssembledObject
    expected_value: int


@pytest.fixture
def patch_maker():
    # Set up PatchMaker
    proc = ProgramAttributes(
        isa=InstructionSet.X86,
        sub_isa=None,
        bit_width=BitWidth.BIT_64,
        endianness=Endianness.LITTLE_ENDIAN,
        processor=None,
    )

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

    toolchain = LLVM_12_0_1_Toolchain(proc, tc_config)

    patch_maker = PatchMaker(
        toolchain=toolchain,
        build_dir=tempfile.mkdtemp(),
    )

    return patch_maker


@pytest.fixture
def target_object_map():
    object_map = {}
    obj = AssembledObject(
        path="/tmp/stub_bom_files/stub_foo.as.o",
        file_format=BinFileType.ELF,
        segment_map=immutabledict(
            {
                ".text": Segment(
                    segment_name=".text",
                    vm_address=0,
                    offset=64,
                    is_entry=False,
                    length=0,
                    access_perms=MemoryPermissions.RX,
                ),
                ".data": Segment(
                    segment_name=".data",
                    vm_address=0,
                    offset=64,
                    is_entry=False,
                    length=0,
                    access_perms=MemoryPermissions.RW,
                ),
            }
        ),
        symbols=immutabledict(
            {
                ".text": (0, LinkableSymbolType.UNDEF),
                ".data": (0, LinkableSymbolType.UNDEF),
                ".bss": (0, LinkableSymbolType.UNDEF),
                "foo": (0, LinkableSymbolType.FUNC),
            }
        ),
        rel_symbols=immutabledict({}),
        bss_size_required=0,
    )
    object_map.update({"/tmp/stub_bom_files/stub_foo.as.o": obj})

    return object_map


@pytest.fixture(params=PARAMS)
def symbol_test_case(request):
    return TestCase(
        AssembledObject(
            path=f"/tmp/patch_bom_files/patch.c.o",
            file_format=BinFileType.ELF,
            segment_map=immutabledict(
                {
                    ".text": Segment(
                        segment_name=".text",
                        vm_address=0,
                        offset=64,
                        is_entry=False,
                        length=0,
                        access_perms=MemoryPermissions.RX,
                    ),
                }
            ),
            symbols=immutabledict(
                {"patch.c": (0, LinkableSymbolType.UNDEF), "baz": (0, LinkableSymbolType.FUNC)}
            ),
            rel_symbols=immutabledict(request.param["rel_symbol"]),
            bss_size_required=0,
        ),
        request.param["expected_value"],
    )


@pytest.mark.parametrize("symbol_test_case", PARAMS, indirect=["symbol_test_case"])
def test_symbol_resolution(patch_maker, target_object_map, symbol_test_case):
    target_object_map.update({"/tmp/patch_bom_files/patch.c.o": symbol_test_case.assembled_object})
    bss_size_required, unresolved_sym_set = patch_maker._resolve_symbols_within_BOM(
        target_object_map
    )

    assert len(unresolved_sym_set) == symbol_test_case.expected_value
