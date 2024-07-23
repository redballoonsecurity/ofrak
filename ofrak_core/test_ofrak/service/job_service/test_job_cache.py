import asyncio
import logging
import pytest
from gzip import GzipFile as _GzipFile
from io import BytesIO

from ofrak import OFRAK
from ofrak.resource import Resource


@pytest.fixture
def test_file(tmpdir):
    d = tmpdir.mkdir("gzip")
    fh = d.join("hello.gz")
    result = BytesIO()
    with _GzipFile(fileobj=result, mode="w") as gzip_file:
        gzip_file.write(b"hello world")
    fh.write_binary(result.getvalue())

    return fh.realpath()


def test_job_cache(ofrak_context, test_file, caplog):
    """
    Test job server can handle start and stop. Should cause a warning to be printed about running the identifiers twice.
    """

    ofrak = OFRAK(logging_level=logging.INFO)
    caplog.set_level(logging.WARNING)

    async def step1(binary: bytes) -> Resource:
        resource = await ofrak_context.create_root_resource_from_file(test_file)
        await resource.unpack()
        return resource

    resource = asyncio.get_event_loop().run_until_complete(step1(b"Hello world\n"))
    assert ofrak_context.job_service._num_runners == 0
    assert len(ofrak_context.job_service._active_component_tasks) == 0

    async def step2(resource):
        await resource.unpack()

    asyncio.get_event_loop().run_until_complete(step2(resource))
    assert ofrak_context.job_service._num_runners == 0
    assert len(ofrak_context.job_service._active_component_tasks) == 0
    # Note - this could be the only test that hits AbstractComponent._log_component_has_run_warning
    print([(r.filename, r.getMessage()) for r in caplog.get_records("call")], flush=True)
    assert any(
        "GzipUnpacker has already been run" in r.getMessage() for r in caplog.get_records("call")
    )
