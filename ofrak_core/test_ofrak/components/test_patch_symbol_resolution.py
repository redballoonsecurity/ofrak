import pytest
import tempfile312 as tempfile

from dataclasses import dataclass
from immutabledict import immutabledict
from typing import Dict, List, Set

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


@dataclass
class TestSymbols:
    label: str
    objects: List[Dict[str, List[str]]]
    expected_unresolved_symbols: Set[str]


@dataclass
class TestCase:
    object_map: Dict[str, AssembledObject]
    expected_unresolved_symbols: Set[str]


PARAMS = [
    TestSymbols(
        "Symbol defined in one AssembledObject but not referenced in another",
        [{"symbols_defined": ["foo", "bar"]}, {"symbols_referenced": []}],
        set(),
    ),
    TestSymbols(
        "Undefined symbol referenced in an AssembledObject",
        [{"symbols_defined": []}, {"symbols_referenced": ["undefined_in_bom"]}],
        {"undefined_in_bom"},
    ),
    TestSymbols(
        "Symbol defined in one AssembledObject and referenced in another",
        [{"symbols_defined": ["defined_in_bom"]}, {"symbols_referenced": ["defined_in_bom"]}],
        set(),
    ),
    TestSymbols("label", [{"symbols_defined": [], "symbols_referenced": []}], set()),
    # symbol defined and used within a single AssembledObject
    TestSymbols(
        "Symbol defined and used within a single AssembledObject",
        [
            {"symbols_defined": ["defined_in_self"], "symbols_referenced": ["defined_in_self"]},
        ],
        set(),
    ),
    TestSymbols(
        "Symbol defined but not referenced within a single AssembledObject",
        [{"symbols_defined": ["defined_in_self"], "symbols_referenced": []}],
        set(),
    ),
    TestSymbols(
        "Symbol defined in one AssembledObject and multiple other AssembledObjects reference it",
        [
            {"symbols_defined": ["defined_in_bom"]},
            {"symbols_referenced": ["defined_in_bom"]},
            {"symbols_referenced": ["defined_in_bom"]},
        ],
        set(),
    ),
    TestSymbols(
        "Symbol defined in multiple AssembledObjects and referenced in another",
        [
            {"symbols_defined": ["defined_twice_in_bom"]},
            {"symbols_defined": ["defined_twice_in_bom"]},
            {"symbols_referenced": ["defined_twice_in_bom"]},
        ],
        set(),
    ),
    TestSymbols(
        "Symbol defined in one AssembledObject, referenced in another, and multiple not using or defining",
        [
            {"symbols_defined": ["defined_in_bom"]},
            {"symbols_referenced": ["defined_in_bom"]},
            {},
            {},
        ],
        set(),
    ),
    # not defined, multiple references
    TestSymbols(
        "Symbol not defined, referenced in multiple AssembledObjects",
        [
            {"symbols_referenced": ["undefined_in_bom"]},
            {"symbols_referenced": ["undefined_in_bom"]},
        ],
        {"undefined_in_bom"},
    ),
]


@pytest.fixture
def patch_maker() -> PatchMaker:
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


@pytest.fixture(params=PARAMS)
def symbol_test_case(request) -> TestCase:
    object_map = {}
    for idx, obj in enumerate(request.param.objects):
        defined_symbols = obj.get("symbols_defined", [])
        referenced_symbols = obj.get("symbols_referenced", [])
        object_map.update(
            {
                str(idx): AssembledObject(
                    path=f"/tmp/patch_bom_files/patch_{str(idx)}.c.o",
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
                    strong_symbols=immutabledict(
                        {
                            symbol: (0, LinkableSymbolType.FUNC)
                            for symbol in defined_symbols
                            if symbol != []
                        }
                    ),
                    unresolved_symbols=immutabledict(
                        {
                            symbol: (0, LinkableSymbolType.FUNC)
                            for symbol in referenced_symbols
                            if symbol != []
                        }
                    ),
                    bss_size_required=0,
                ),
            }
        )

    return TestCase(
        object_map=object_map, expected_unresolved_symbols=request.param.expected_unresolved_symbols
    )


@pytest.mark.parametrize(
    "symbol_test_case", PARAMS, indirect=["symbol_test_case"], ids=lambda tc: tc.label
)
def test_symbol_resolution(patch_maker, symbol_test_case):
    bss_size_required, unresolved_sym_set = patch_maker._resolve_symbols_within_BOM(
        symbol_test_case.object_map
    )

    assert unresolved_sym_set == symbol_test_case.expected_unresolved_symbols
