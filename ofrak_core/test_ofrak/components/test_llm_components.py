import asyncio
import os

import pytest

import ofrak_ghidra
import test_ofrak
from ofrak import OFRAKContext
from ofrak.core import Elf
from ofrak.core.llm import (
    LlmAnalyzer,
    LlmAnalyzerConfig,
    LlmProgramAnalyzer,
    LlmAttributes,
    LlmFunctionAnalyzer,
)


@pytest.fixture()
@pytest.mark.asyncio
async def ollama():
    async def run_task():
        proc = None
        try:
            proc = await asyncio.subprocess.create_subprocess_exec("ollama", "serve")
            await proc.communicate()
        except asyncio.CancelledError:
            if proc is not None:
                proc.kill()

    task = asyncio.create_task(run_task())
    await asyncio.sleep(5)
    yield
    task.cancel()


@pytest.fixture()
@pytest.mark.asyncio
async def model(ollama) -> str:
    # Smallest chat model currently available on ollama
    model_name = "qwen2.5:0.5b"
    proc = await asyncio.subprocess.create_subprocess_exec("ollama", "pull", model_name)
    await proc.communicate()
    yield model_name


@pytest.fixture(autouse=True)
def ghidra_components(ofrak_injector):
    ofrak_injector.discover(ofrak_ghidra)


async def test_llm_component(ofrak_context: OFRAKContext, model: str):
    root_path = os.path.join(test_ofrak.components.ASSETS_DIR, "elf", "busybox_elf_exec_noscop")
    root = await ofrak_context.create_root_resource_from_file(root_path)
    await root.unpack()
    await root.auto_run(all_analyzers=True)
    await root.run(
        LlmAnalyzer,
        LlmAnalyzerConfig(
            "http://localhost:11434/api/chat",
            model,
        ),
    )
    attributes = root.get_attributes(LlmAttributes)
    assert attributes.description, f"LlmAnalyzer did not generate valid description attributes."


async def test_llm_function_component(ofrak_context: OFRAKContext, model: str):
    root_path = os.path.join(test_ofrak.components.ASSETS_DIR, "elf", "hello_elf_dyn")
    root = await ofrak_context.create_root_resource_from_file(root_path)
    await root.unpack_recursively()
    elf = await root.view_as(Elf)
    main = await elf.get_function_complex_block("main")
    await main.resource.run(
        LlmFunctionAnalyzer,
        LlmAnalyzerConfig(
            "http://localhost:11434/api/chat",
            model,
        ),
    )
    attributes = main.resource.get_attributes(LlmAttributes)
    assert (
        attributes.description
    ), f"LlmFunctoinAnalyzer did not generate valid description attributes."


async def test_llm_program_component(ofrak_context: OFRAKContext, model: str):
    root_path = os.path.join(test_ofrak.components.ASSETS_DIR, "elf", "hello_elf_dyn")
    root = await ofrak_context.create_root_resource_from_file(root_path)
    await root.unpack_recursively()
    await root.run(
        LlmProgramAnalyzer,
        LlmAnalyzerConfig(
            "http://localhost:11434/api/chat",
            model,
        ),
    )
    attributes = root.get_attributes(LlmAttributes)
    assert (
        attributes.description
    ), f"LlmProgramAnalyzer did not generate valid description attributes."
