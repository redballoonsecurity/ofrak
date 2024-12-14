import pytest

from ofrak.core import *
from test_ofrak.components.hello_world_elf import hello_elf


@pytest.fixture(scope="session")
def hello_world_elf() -> bytes:
    return hello_elf()


def test_run_script_modifier(ofrak_context, hello_world_elf):
    root_1 = ofrak_context.create_root_resource("root_1", hello_world_elf, (Elf,))
    root_2 = ofrak_context.create_root_resource("root_2", hello_world_elf, (Elf,))

    r = root_1.unpack()
    root_2.run(RunScriptModifier, RunScriptModifierConfig(SCRIPT, "part_1"))

    assert len(list(root_1.get_children())) == len(list(root_2.get_children()))

    elf = root_1.view_as(Elf)
    header = elf.get_header()
    original_machine = header.e_machine
    header.resource.run(ElfHeaderModifier, ElfHeaderModifierConfig(e_machine=0x20))

    root_2.run(
        RunScriptModifier, RunScriptModifierConfig(SCRIPT, "part_2", extra_args={"e_machine": 0x20})
    )

    elf_2 = root_2.view_as(Elf)
    header_2 = elf_2.get_header()
    assert header_2.e_machine == header.e_machine
    assert original_machine != header.e_machine


SCRIPT = """
from ofrak import *
from ofrak.core import *

def part_1(ofrak_context: OFRAKContext, root_resource: Optional[Resource] = None):
    root_resource.unpack()

def part_2(ofrak_context: OFRAKContext, root_resource: Optional[Resource] = None, e_machine: int = 0):
    elf = root_resource.view_as(Elf)
    header = elf.get_header()
    header.resource.run(ElfHeaderModifier, ElfHeaderModifierConfig(e_machine=e_machine))
    
"""
