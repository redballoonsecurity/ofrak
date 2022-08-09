from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ofrak_type.memory_permissions import MemoryPermissions


class ToolchainException(Exception):
    pass


class BinFileType(Enum):
    """
    Enums for file types
    """

    ELF = "elf"
    COFF = "coff"
    PE = "pe"
    MACH_O = "mach-o"


@dataclass
class Segment:
    """
    Describes a program segment.

    :var segment_name: e.g. `.text`
    :var vm_address: where the segment is located
    :var offset: offset from `vm_address`
    :var is_entry: If the `Segment` contains the patch "entry point symbol"
    :var length: size of the segment in bytes
    :var access_perms: `rw`, `ro`, `rwx`, etc.
    """

    segment_name: str
    vm_address: int
    offset: int
    is_entry: bool
    length: int
    access_perms: MemoryPermissions


class CompilerOptimizationLevel(Enum):
    """
    Some compilers implement different optimization options. This `Enum` enables us to handle
    those distinctly.
    """

    NONE = "none"
    SOME = "some"
    SPACE = "space"
    FULL = "full"


class CStandardVersion(Enum):
    C89 = "c89"
    C99 = "c99"
    C11 = "c11"
    GNU89 = "gnu89"
    GNU99 = "gnu99"
    GNU11 = "gnu11"


class LinkerOptimizationLevel(Enum):
    """
    !!! todo

        Experiment with this
    """

    NONE = "none"


@dataclass(frozen=True)
class ToolchainConfig:
    """
    A `dataclass` that describes all of the parameters toolchains may be configured with.

    As further [Toolchain][ofrak_patch_maker.toolchain.abstract.Toolchain] support is added,
    not all of these may be relevant to all toolchains.

    It is expected the functionality described by the parameter will be achieved to the best effort.

    :var file_format: Usually ELF
    :var force_inlines: forces inlines when specified in the function signature
    :var relocatable: Enables PC-relative data references, branches, etc. (via `pic`/`pie`)
    :var no_std_lib: Excludes the host system root from include paths
    :var no_jump_tables: Prevents the generation of jump tables
    :var no_bss_section: Forces usage of `.data`/`.rodata` instead of `.bss`
    :var compiler_optimization_level: `NONE`, `SOME`, `SPACE`, or `FULL` (implementation dependent)
    :var compiler_target: Forces specific triple (CPU/ARCH) target-- should match `file_format`
    :var assembler_target: Forces specific assembler CPU/ARCH target
    :var create_map_files: Creates `.map` files from link step (Default: `True`)
    :var debug_info: Should most closely mirror GNU `-g` functionality (Default: `True`)
    :var check_overlap: Enables the Toolchain Linker to assert memory boundaries (Default: `True`)
    :var userspace_dynamic_linker: Signals compilation for userspace and libc usage.
    :var isysroot: Specifies the root directory for header files
    :var c_standard: Specifies the version of C to use, e.g. C89, C99, etc
    :var separate_data_sections: Whether to put each data object in a separate section in .o file
    :var hard_float: Compile with support for hardware floating point operations (Default: `False`)
    """

    file_format: BinFileType
    force_inlines: bool
    relocatable: bool
    no_std_lib: bool
    no_jump_tables: bool
    no_bss_section: bool
    compiler_optimization_level: CompilerOptimizationLevel
    compiler_target: Optional[str] = None
    compiler_cpu: Optional[str] = None
    assembler_target: Optional[str] = None
    assembler_cpu: Optional[str] = None
    create_map_files: bool = True
    debug_info: bool = True
    check_overlap: bool = True
    userspace_dynamic_linker: Optional[str] = None
    isysroot: Optional[str] = None
    c_standard: Optional[CStandardVersion] = CStandardVersion.C99
    separate_data_sections: Optional[bool] = False
    hard_float: Optional[bool] = False
