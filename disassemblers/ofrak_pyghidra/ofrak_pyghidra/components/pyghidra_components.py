import pyghidra
from ofrak.core import *
from tempfile import TemporaryDirectory
import os


class PyGhidraUnpacker(Unpacker[None]):
    id = b"PyGhidraUnpacker"

    targets = (Elf,)
    children = (ComplexBlock, BasicBlock, Instruction)
    
    async def unpack(self, resource: Resource, config=None):
        with TemporaryDirectory() as tempdir:
            program_file = os.path.join(tempdir, "program")
            await resource.flush_data_to_disk(program_file)
            with pyghidra.open_program(program_file) as flat_api:
                func = flat_api.getFunctionAt(0)
                if func is None:
                    func = flat_api.getFunctionAfter(0)

                    if func is None:
                        raise()
