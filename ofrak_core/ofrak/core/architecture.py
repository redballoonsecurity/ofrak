from dataclasses import dataclass
from typing import Optional

from ofrak import ResourceAttributes
from ofrak_type.architecture import InstructionSet, SubInstructionSet, ProcessorType
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ProgramAttributes(ResourceAttributes):
    """
    Analyzer output containing architecture attributes of a program.

    :ivar isa: Instruction set architecture
    :ivar sub_isa: Sub instruction set
    :ivar bit_width: Bits per word
    :ivar endianness: Endianness as `Endianness.BIG_ENDIAN` or `Endianness.LITTLE_ENDIAN`
    :ivar processor: Processor type
    """

    isa: InstructionSet
    sub_isa: Optional[SubInstructionSet]
    bit_width: BitWidth
    endianness: Endianness
    processor: Optional[ProcessorType]
