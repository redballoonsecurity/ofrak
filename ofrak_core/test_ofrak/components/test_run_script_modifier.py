import pytest

from ofrak.core import *
from test_ofrak.components.hello_world_elf import hello_elf


@pytest.fixture(scope="session")
def hello_world_elf() -> bytes:
    return hello_elf()


async def test_run_script_modifier(ofrak_context, hello_world_elf):
    root_1 = await ofrak_context.create_root_resource("root_1", hello_world_elf, (Elf,))
    root_2 = await ofrak_context.create_root_resource("root_2", hello_world_elf, (Elf,))

    r = await root_1.unpack()
    await root_2.run(RunScriptModifier, RunScriptModifierConfig(SCRIPT, "part_1"))

    assert len(list(await root_1.get_children())) == len(list(await root_2.get_children()))

    elf = await root_1.view_as(Elf)
    header = await elf.get_header()
    original_machine = header.e_machine
    await header.resource.run(ElfHeaderModifier, ElfHeaderModifierConfig(e_machine=0x20))

    await root_2.run(RunScriptModifier, RunScriptModifierConfig(SCRIPT, "part_2"))

    elf_2 = await root_2.view_as(Elf)
    header_2 = await elf_2.get_header()
    assert header_2.e_machine == header.e_machine
    assert original_machine != header.e_machine


SCRIPT = """
from ofrak import *
from ofrak.core import *

async def part_1(ofrak_context: OFRAKContext, root_resource: Optional[Resource] = None):
    await root_resource.unpack()

async def part_2(ofrak_context: OFRAKContext, root_resource: Optional[Resource] = None):
    elf = await root_resource.view_as(Elf)
    header = await elf.get_header()
    await header.resource.run(ElfHeaderModifier, ElfHeaderModifierConfig(e_machine=0x20))
    
"""
