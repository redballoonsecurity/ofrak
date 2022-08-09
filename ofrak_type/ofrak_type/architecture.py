from enum import Enum


class InstructionSet(Enum):
    """
    Enumeration of the possible supported instruction sets.

    :ivar ARM: ARM
    :ivar AARCH64: ARM 64-bit
    :ivar X86: Intel x86
    :ivar MIPS: MIPS
    :ivar MSP430: MSP430
    :ivar PPS: PowerPC
    :ivar M68K: Motorola 68K
    :ivar AVR: Atmel AVR
    """

    ARM = "arm"
    AARCH64 = "aarch64"
    X86 = "x86"
    MIPS = "mips"
    MSP430 = "msp430"
    PPC = "ppc"
    M68K = "68000"
    AVR = "avr"


class SubInstructionSet(Enum):
    """
    ARM sub instruction set. Different sub ISAs correspond to different
    [ARM versions](https://en.wikipedia.org/wiki/AArch64).
    """

    ARMv4T = "ARMV4T"
    ARMv5T = "ARMV5T"
    ARMv5TE = "ARMV5TE"
    ARMv6 = "ARMV6"
    ARMv6J = "ARMV6J"
    ARMv6K = "ARMV6K"
    ARMv6KZ = "ARMV6KZ"
    ARMv6T2 = "ARMV6T2"
    ARMv6Z = "ARMV6Z"
    ARMv6ZK = "ARMV6ZK"
    ARMv7 = "ARMV7"
    ARMv7A = "ARMV7-A"
    ARMv7VE = "ARMV7VE"
    ARMv8A = "ARMV8-A"
    ARMv81A = "ARMV8.1-A"
    ARMv82A = "ARMV8.2-A"
    ARMv83A = "ARMV8.3-A"
    ARMv84A = "ARMV8.4-A"
    ARMv85A = "ARMV8.5-A"
    ARMv86A = "ARMV8.6-A"
    ARMv7R = "ARMV7-R"
    ARMv8R = "ARMV8-R"
    ARMv6M = "ARMV6-M"
    ARMv6SM = "ARMV6S-M"
    ARMv7M = "ARMV7-M"
    ARMv7EM = "ARMV7E-M"
    ARMv8MBASE = "ARMV8-M.BASE"
    ARMv8MMAIN = "ARMV8-M.MAIN"
    ARMv81MMAIN = "ARMV8.1-M.MAIN"
    ARMv9A = "ARMV9-A"
    IWMMXT = "IWMMXT"
    IWMMXT2 = "IWMMXT2"
    # AVR
    AVR2 = "avr2"
    AVR25 = "avr25"
    AVR3 = "avr3"
    AVR31 = "avr31"
    AVR35 = "avr35"
    AVR4 = "avr4"
    AVR5 = "avr5"
    AVR51 = "avr51"
    AVR6 = "avr6"
    AVRXMEGA2 = "avrxmega2"
    # AVRXMEGA3 = "avrxmega3"  # Not supported in 5.4.0
    AVRXMEGA4 = "avrxmega4"
    AVRXMEGA5 = "avrxmega5"
    AVRXMEGA6 = "avrxmega6"
    AVRXMEGA7 = "avrxmega7"
    AVRTINY = "avrtiny"
    AVR1 = "avr1"  # assembler only


class InstructionSetMode(Enum):
    """
    Instruction set mode. Useful for architectures which have multiple encodings it can switch
    between on the fly. In particular the Thumb mode for ARM and VLE more for PPC are represented.

    :ivar NONE: None
    :ivar THUMB: Thumb (ARM)
    :ivar VLE: VLE (PPC)
    """

    NONE = 0
    THUMB = 1
    VLE = 2


class ProcessorType(Enum):
    """
    Enumeration of specific processor types.

    :ivar ARM926EJ_S:
    :ivar GENERIC_A53_V8:
    :ivar GENERIC_A9_V6:
    :ivar GENERIC_A9_V7:
    :ivar GENERIC_A9_V7_THUMB:
    :ivar MSP430:
    :ivar MIPS_LITTLE:
    :ivar MIPS_RM5721_BIG:
    :ivar PPC_405:
    :ivar PPC_MPC855T:
    :ivar PPC_VLE:
    :ivar PI_ARM6:
    :ivar PIXHAWK:
    :ivar SPARTAN:
    :ivar X186_16:
    :ivar X186_32:
    :ivar X64:
    :ivar XSCALE:
    :ivar COLDFIRE4E:
    :ivar CORTEX_A53:
    :ivar AVR:
    """

    ARM926EJ_S = "arm926ej-s"
    GENERIC_A53_V8 = "generic_a53_v8"
    GENERIC_A9_V6 = "generic_a9_v6"
    GENERIC_A9_V7 = "generic_a9_v7"
    GENERIC_A9_V7_THUMB = "generic_a9_v7_thumb"
    MSP430 = "msp340"
    MIPS_LITTLE = "mips"
    MIPS_RM5721_BIG = "mips_rm5721_big"
    PPC_405 = "ppc_405"
    PPC_MPC855T = "ppc_mpc855t"
    PPC_VLE = "ppc_vle"
    PI_ARM6 = "pi_arm6"
    PIXHAWK = "pixhawk"
    SPARTAN = "spartan"
    X186_16 = "x186_16"
    X186_32 = "x186_32"
    I386 = "i386"
    X64 = "x86_64"
    XSCALE = "xscale"
    COLDFIRE4E = "cfv4e"
    CORTEX_A53 = "cortex-a53"
    AVR = "avr"
