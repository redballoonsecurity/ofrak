from ofrak_type.bit_width import BitWidth

from ofrak.core.architecture import ProgramAttributes
from ofrak_type.endianness import Endianness
from ofrak_type.architecture import InstructionSet

ARM32_ARCH = ProgramAttributes(
    InstructionSet.ARM,
    None,
    BitWidth.BIT_32,
    Endianness.LITTLE_ENDIAN,
    None,
)

X64_ARCH = ProgramAttributes(
    InstructionSet.X86,
    None,
    BitWidth.BIT_64,
    Endianness.LITTLE_ENDIAN,
    None,
)

PPC_ARCH = ProgramAttributes(
    InstructionSet.PPC,
    None,
    BitWidth.BIT_32,
    Endianness.BIG_ENDIAN,
    None,
)
