import json
import os
from pathlib import Path, PosixPath
from ofrak.ofrak_context import OFRAKContext
from ofrak.resource import Resource
import pytest
import re

from multiprocessing import Process
from typing import List, Tuple

from aiohttp.test_utils import TestClient

from ofrak import Analyzer, Unpacker, Modifier, Packer
from ofrak.core import File
from ofrak.core.entropy import DataSummaryAnalyzer
from ofrak.gui.server import AiohttpOFRAKServer, start_server
from ofrak.model.component_filters import ComponentOrMetaFilter, ComponentTypeFilter
from ofrak.service.serialization.pjson import (
    PJSONSerializationService,
)
from test_ofrak.components.hello_world_elf import hello_elf


@pytest.fixture(scope="session")
def hello_world_elf() -> bytes:
    return hello_elf()


@pytest.fixture()
async def test_project_dir(ofrak_client: TestClient, tmpdir):
    test_project_dir = Path(tmpdir).resolve().as_posix()
    await ofrak_client.post("/set_projects_path", json={"path": test_project_dir})
    yield test_project_dir


@pytest.fixture()
async def large_test_file(ofrak_context: OFRAKContext, tmp_path: PosixPath) -> Resource:
    large_file = tmp_path / "large_file.txt"
    for i in range(256):
        large_file.write_bytes(int.to_bytes(i, 1, "big") * 1024 * 1024)
    yield await ofrak_context.create_root_resource_from_file(large_file.resolve().as_posix())


@pytest.fixture(scope="session")
def firmware_zip() -> bytes:
    assets_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../components/assets/binwalk_assets")
    )
    asset_path = os.path.join(assets_dir, "firmware.zip")
    with open(asset_path, "rb") as f:
        return f.read()


# Create test server that will be spun up for each test
@pytest.fixture
async def ofrak_server(ofrak, ofrak_context):
    ofrak = ofrak

    ofrak.injector.bind_factory(PJSONSerializationService)

    ofrak.injector.bind_factory(
        AiohttpOFRAKServer,
        ofrak_context=ofrak_context,
        host="127.0.0.1",
        port=8080,
    )
    ofrak_server = await ofrak.injector.get_instance(AiohttpOFRAKServer)
    return ofrak_server


@pytest.fixture
async def ofrak_client(ofrak_server, aiohttp_client):
    return await aiohttp_client(ofrak_server._app)


@pytest.fixture
async def test_resource(ofrak_context, hello_world_elf):
    return await ofrak_context.create_root_resource(hello_world_elf, hello_world_elf, (File,))


def dicts_are_similar(d1, d2, attributes_to_skip=None):
    if attributes_to_skip is None:
        attributes_to_skip = {"id", "data_id"}
    for key, value in d1.items():
        if key in attributes_to_skip:
            continue
        if isinstance(value, list) and set(value) != set(d2[key]):
            return False
        elif value != d2[key]:
            return False
    return True


def join_and_normalize(list_of_strs: List[str]) -> str:
    in_str = "\n".join(list_of_strs)
    return re.sub(r"RuntimeError\(\s*.*\s*\)", "RuntimeError(err)", in_str, flags=re.M)


# Test server methods and top-level functions.
# Does not effect coverage because it runs in a subprocess. Could use in future to test end-to-end.
async def test_server_main(ofrak_client: TestClient, ofrak_context):
    args = {"ofrak_context": ofrak_context, "host": "127.0.0.1", "port": 8080}
    proc = Process(target=start_server, kwargs=args)
    proc.start()
    resp = await ofrak_client.get("/")
    assert resp.status == 200
    proc.join(timeout=5)


async def test_error(ofrak_client: TestClient):
    resp = await ofrak_client.get("/1234/")
    assert resp.status == 500


# Test calls to each of the routes set on the server, this should hit each of the callbacks
async def test_get_index(ofrak_client: TestClient):
    resp = await ofrak_client.get("/")
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "text/html"


async def test_create_root_resource(
    ofrak_client: TestClient, ofrak_server, hello_world_elf, test_resource
):
    resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["id"] is not None

    serialized_resource = ofrak_server._serialize_resource(test_resource)
    json_result = json.loads(json.dumps(serialized_resource))
    assert body["tags"] == json_result["tags"]


async def test_create_chunked_root_resource(
    ofrak_client: TestClient, ofrak_server, large_test_file
):
    test_file_data = await large_test_file.get_data()
    chunk_size = int(len(test_file_data) / 10)
    init_resp = await ofrak_client.post(
        "/init_chunked_root_resource",
        params={"name": "test_file_data", "size": len(test_file_data)},
    )
    id = await init_resp.json()
    for start in range(0, len(test_file_data), chunk_size):
        end = min(start + chunk_size, len(test_file_data))
        res = await ofrak_client.post(
            "/root_resource_chunk",
            params={"id": id, "start": start, "end": end},
            data=test_file_data[start:end],
        )
    create_resp = await ofrak_client.post(
        "/create_chunked_root_resource", params={"name": "test_file_data", "id": id}
    )
    assert create_resp.status == 200
    length_resp = await ofrak_client.get(f"/{id}/get_data_length")
    length_resp_body = await length_resp.json()
    assert length_resp_body == len(test_file_data)


async def test_get_root_resources(
    ofrak_client: TestClient, ofrak_context, ofrak_server, hello_world_elf
):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    get_resp = await ofrak_client.get("/get_root_resources")
    assert get_resp.status == 200
    body = await get_resp.json()
    assert body[0]["id"] is not None

    result = await ofrak_context.resource_service.get_root_resources()
    serialized_result = list(map(ofrak_server._serialize_resource_model, result))
    # Need to replace tuples with lists as per proper json structure
    json_result = json.loads(json.dumps(serialized_result))
    assert body[0]["attributes"] == json_result[0]["attributes"]


async def test_get_resource(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await ofrak_client.get(f"/{body['id']}/")
    assert resp.status == 200

    # TODO: How test directly? Package up in request and send to ofrak_server?


async def test_get_data(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.get(f"/{create_body['id']}/get_data")
    assert resp.status == 200
    resp_body = await resp.read()
    assert resp_body == hello_world_elf
    resp = await ofrak_client.get(f"/{create_body['id']}/get_data", params={"range": "[16,80]"})
    assert resp.status == 200
    resp_body = await resp.read()
    assert resp_body == hello_world_elf[0x10:0x50]


async def test_get_data_length(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.get(f"/{create_body['id']}/get_data_length")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body == len(hello_world_elf)


async def test_unpack(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/unpack")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["created"] is not None


async def test_get_children(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    root = await create_resp.json()
    root_id = root["id"]
    await ofrak_client.post(f"/{root_id}/unpack")
    children_resp = await ofrak_client.post(f"/batch/get_children", json=[root_id])
    assert children_resp.status == 200
    children_body = await children_resp.json()
    assert root_id in children_body
    assert len(children_body[root_id]) > 1


async def test_get_descendants(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    root = await create_resp.json()
    root_id = root["id"]
    await ofrak_client.post(f"/{root_id}/unpack")
    children_resp = await ofrak_client.post(f"/batch/get_children", json=[root_id])
    children = await children_resp.json()
    children_ids = [
        cid_v for child in children[root_id] for cid_k, cid_v, in child.items() if cid_k == "id"
    ]
    descendants_resp = await ofrak_client.get(f"/{root_id}/get_descendants")
    assert descendants_resp.status == 200
    descendants = await descendants_resp.json()
    descendant_ids = [
        did_v for descendant in descendants for did_k, did_v in descendant.items() if did_k == "id"
    ]
    for child in children_ids:
        assert child in descendant_ids
    assert len(descendants) > 1


async def test_get_data_range(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    root = await create_resp.json()
    root_id = root["id"]
    await ofrak_client.post(f"/{root_id}/unpack")
    children_resp = await ofrak_client.get(f"/{root_id}/get_child_data_ranges")
    child_ranges = await children_resp.json()
    assert [0, 16] in child_ranges.values()

    batch_range_resp = await ofrak_client.post(
        f"/batch/get_data_range_within_parent", json=list(child_ranges.keys())
    )
    batch_ranges = await batch_range_resp.json()
    assert all(
        batch_ranges[child_id] == child_range for child_id, child_range in child_ranges.items()
    )


# Cannot find manual example to compare against
async def test_get_root(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await ofrak_client.get(f"/{body['id']}/get_root")
    assert resp.status == 200


async def test_unpack_recursively(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/unpack_recursively")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["created"] is not None


# Cannot find manual example to compare against
async def test_pack(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await ofrak_client.post(f"/{body['id']}/pack")
    assert resp.status == 200


# Cannot find manual example to compare against
async def test_pack_recursively(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await ofrak_client.post(f"/{body['id']}/pack_recursively")
    assert resp.status == 200


async def test_analyze(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/analyze")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body is not None


async def test_identify(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/identify")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]


async def test_identify_recursively(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/identify_recursively")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]


async def test_data_summary(ofrak_client: TestClient, ofrak_server, hello_world_elf, test_resource):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/data_summary")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]

    # use ofrak_context to create root resource, then run DataSummaryAnalyzer on it
    result = await test_resource.run(DataSummaryAnalyzer)
    serialized_result = await ofrak_server._serialize_component_result(result)
    # Need to replace tuples with lists as per proper json structure
    json_result = json.loads(json.dumps(serialized_result))
    assert resp_body["modified"][0]["attributes"] == json_result["modified"][0]["attributes"]


async def test_get_parent(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    unpack_resp = await ofrak_client.post(f"/{create_body['id']}/unpack")
    unpack_body = await unpack_resp.json()
    resp = await ofrak_client.get(f"/{unpack_body['created'][0]['id']}/get_parent")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["id"] == create_body["id"]


async def test_get_ancestors(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    unpack_resp = await ofrak_client.post(f"/{create_body['id']}/unpack")
    unpack_body = await unpack_resp.json()
    resp = await ofrak_client.get(f"/{unpack_body['created'][0]['id']}/get_ancestors")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body[0]["id"] == create_body["id"]


async def test_queue_patch(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    unpack_resp = await ofrak_client.post(f"/{create_body['id']}/unpack")
    resp = await ofrak_client.post(f"/{create_body['id']}/queue_patch", data=hello_world_elf)
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["id"] == create_body["id"]


async def test_create_mapped_child(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    root = await create_resp.json()
    root_id = root["id"]
    await ofrak_client.post(f"/{root_id}/unpack")
    children_resp = await ofrak_client.post(f"/batch/get_children", json=[root_id])
    children_body = await children_resp.json()
    eldest_child_id = children_body[root_id][0]["id"]

    resp = await ofrak_client.post(f"/{eldest_child_id}/create_mapped_child", json=[0, 1])
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["parent_id"] == eldest_child_id


# find_and_replace doesn't appear to send back any information in the response
async def test_find_and_replace(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await ofrak_client.post(
        f"/{body['id']}/find_and_replace",
        json=[
            "ofrak.core.strings.StringFindReplaceConfig",
            {
                "to_find": "hello",
                "replace_with": "Hello",
                "null_terminate": False,
                "allow_overflow": False,
            },
        ],
    )
    assert resp.status == 200


# Returns (comment range count, comment count)
# comment range count = # of unique Optional[Range]s comments are mapped to
# comment count = total # of comments across all Optional[Range]s
def get_comment_count(resp_body_json) -> Tuple[int, int]:
    attributes = resp_body_json["modified"][0]["attributes"]
    comment_range_count = 0
    comment_count = 0

    for attr_array in attributes:
        if attr_array[0] == "ofrak.core.comments.CommentsAttributes":
            comment_data = attr_array[1][1]["comments"]
            for kv_pair in comment_data:
                comment_range_count += 1
                comment_count += len(kv_pair[1])

    return (comment_range_count, comment_count)


async def test_add_comment(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    # Try creating comments on invalid ranges
    resp = await client.post(
        f"/{create_body['id']}/add_comment",
        json=[[0, len(hello_world_elf) + 1], "test comment out of bounds"],
    )
    assert resp.status != 200
    resp = await client.post(
        f"/{create_body['id']}/add_comment",
        json=[[-1, len(hello_world_elf)], "test comment out of bounds"],
    )
    assert resp.status != 200
    # Create comment without range
    resp = await client.post(f"/{create_body['id']}/add_comment", json=[None, "test comment 0"])
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]
    # Create comment with range
    resp = await client.post(f"/{create_body['id']}/add_comment", json=[[0, 1], "test comment 1"])
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]
    # Create multiple comments on the same range
    resp = await client.post(
        f"/{create_body['id']}/add_comment", json=[[0, len(hello_world_elf)], "test comment 2"]
    )
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]
    resp = await client.post(
        f"/{create_body['id']}/add_comment", json=[[0, len(hello_world_elf)], "test comment 3"]
    )
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]
    # Check comment counts
    comment_range_count, comment_count = get_comment_count(resp_body)
    assert comment_range_count == 3
    assert comment_count == 4


# Test deleting comments using both the old and new format
async def test_delete_comment(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    # Comments to delete
    await client.post(f"/{create_body['id']}/add_comment", json=[None, "test comment 0"])
    await client.post(f"/{create_body['id']}/add_comment", json=[None, "test comment 1"])
    await client.post(
        f"/{create_body['id']}/add_comment", json=[[0, len(hello_world_elf)], "test comment 0"]
    )
    resp = await client.post(
        f"/{create_body['id']}/add_comment", json=[[0, len(hello_world_elf)], "test comment 1"]
    )
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]
    comment_range_count, comment_count = get_comment_count(resp_body)
    assert comment_range_count == 2
    assert comment_count == 4
    # Test deleting specific comments from range
    resp = await client.post(f"/{create_body['id']}/delete_comment", json=[None, "test comment 1"])
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]
    comment_range_count, comment_count = get_comment_count(resp_body)
    assert comment_range_count == 2
    assert comment_count == 3
    # Test deleting last comment from range
    resp = await client.post(f"/{create_body['id']}/delete_comment", json=[None, "test comment 0"])
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]
    comment_range_count, comment_count = get_comment_count(resp_body)
    assert comment_range_count == 1
    assert comment_count == 2
    # Test deleting entire range
    resp = await client.post(f"/{create_body['id']}/delete_comment", json=[0, len(hello_world_elf)])
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]
    assert (0, 0) == get_comment_count(resp_body)  # All comments should be gone


async def test_search_for_vaddr(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    await ofrak_client.post(f"/{create_body['id']}/unpack_recursively")
    resp = await ofrak_client.post(f"/{create_body['id']}/search_for_vaddr", json=[0, None])
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body[0] is not None


async def test_get_all_tags(ofrak_client: TestClient):
    resp = await ofrak_client.get(f"/get_all_tags")
    assert resp.status == 200
    resp_body = await resp.json()
    assert "ofrak.core.basic_block.BasicBlock" in resp_body


async def test_add_tag(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resource_id = create_body["id"]
    resp = await ofrak_client.post(
        f"/{resource_id}/add_tag",
        json="ofrak.core.apk.Apk",
    )
    assert resp.status == 200


async def test_update_script(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    root = await create_resp.json()
    root_id = root["id"]

    # Perform some actions that should hit add_action, add_variable, and all their subcalls
    await ofrak_client.post(f"/{root_id}/unpack")
    children_resp = await ofrak_client.post(f"/batch/get_children", json=[root_id])
    children_body = await children_resp.json()
    eldest_child_id = children_body[root_id][0]["id"]
    await ofrak_client.post(f"/{eldest_child_id}/analyze")

    # Get final script and compare it
    resp = await ofrak_client.get(
        f"/{root_id}/get_script",
    )
    resp_body = await resp.json()
    expected_list = [
        "from ofrak import *",
        "from ofrak.core import *",
        "from ofrak.gui.script_builder import get_child_by_range",
        "",
        "",
        "async def main(ofrak_context: OFRAKContext, root_resource: Optional[Resource] = None):",
        "    if root_resource is None:",
        "        root_resource = await ofrak_context.create_root_resource_from_file(",
        '            "hello_world_elf"',
        "        )",
        "",
        "    await root_resource.unpack()",
        "",
        "    elfbasicheader_0x0 = await get_child_by_range(root_resource, Range(0, 16))",
        "",
        "    await elfbasicheader_0x0.auto_run(all_analyzers=True)",
        "",
        "",
        'if __name__ == "__main__":',
        "    ofrak = OFRAK()",
        "    if False:",
        "        import ofrak_angr",
        "        import ofrak_capstone",
        "",
        "        ofrak.discover(ofrak_capstone)",
        "        ofrak.discover(ofrak_angr)",
        "",
        "    if False:",
        "        import ofrak_binary_ninja",
        "        import ofrak_capstone",
        "",
        "        ofrak.discover(ofrak_capstone)",
        "        ofrak.discover(ofrak_binary_ninja)",
        "",
        "    if False:",
        "        import ofrak_ghidra",
        "",
        "        ofrak.discover(ofrak_ghidra)",
        "",
        "    ofrak.run(main)",
        "",
    ]

    expected_str = join_and_normalize(expected_list)
    actual_str = join_and_normalize(resp_body)
    assert actual_str == expected_str


async def test_selectable_attr_err(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    root = await create_resp.json()
    root_id = root["id"]

    # Carving the root resource twice will result in 2 children with identical attributes, which
    # leads to a SelectableAttributesError when you attempt to unpack the children
    await ofrak_client.post(f"/{root_id}/create_mapped_child", json=[0, 8181])

    await ofrak_client.post(f"/{root_id}/create_mapped_child", json=[0, 8181])
    children_resp = await ofrak_client.post(f"/batch/get_children", json=[root_id])
    children_body = await children_resp.json()

    child_one = children_body[root_id][0]
    child_two = children_body[root_id][1]
    await ofrak_client.post(f"/{child_one['id']}/unpack")
    await ofrak_client.post(f"/{child_two['id']}/unpack")

    # Verify script is as expected
    resp = await ofrak_client.get(
        f"/{root_id}/get_script",
    )
    resp_body = await resp.json()
    normalized_expected_list = [
        "from ofrak import *",
        "from ofrak.core import *",
        "from ofrak.gui.script_builder import get_child_by_range",
        "",
        "",
        "async def main(ofrak_context: OFRAKContext, root_resource: Optional[Resource] = None):",
        "    if root_resource is None:",
        "        root_resource = await ofrak_context.create_root_resource_from_file(",
        '            "hello_world_elf"',
        "        )",
        "",
        "    await root_resource.create_child(",
        "        tags=(GenericBinary,), data_range=Range(0x0, 0x1FF5)",
        "    )",
        "",
        "    await root_resource.create_child(",
        "        tags=(GenericBinary,), data_range=Range(0x0, 0x1FF5)",
        "    )",
        "",
        "    # Resource with parent root_resource is missing, could not find selectable attributes.",
        "    raise RuntimeError(err)",
        "    root_resource_MISSING_RESOURCE_0 = None",
        "",
        "    await root_resource_MISSING_RESOURCE_0.unpack()",
        "",
        "    # Resource with parent root_resource is missing, could not find selectable attributes.",
        "    raise RuntimeError(err)",
        "    root_resource_MISSING_RESOURCE_1 = None",
        "",
        "    await root_resource_MISSING_RESOURCE_1.unpack()",
        "",
        "",
        'if __name__ == "__main__":',
        "    ofrak = OFRAK()",
        "    if False:",
        "        import ofrak_angr",
        "        import ofrak_capstone",
        "",
        "        ofrak.discover(ofrak_capstone)",
        "        ofrak.discover(ofrak_angr)",
        "",
        "    if False:",
        "        import ofrak_binary_ninja",
        "        import ofrak_capstone",
        "",
        "        ofrak.discover(ofrak_capstone)",
        "        ofrak.discover(ofrak_binary_ninja)",
        "",
        "    if False:",
        "        import ofrak_ghidra",
        "",
        "        ofrak.discover(ofrak_ghidra)",
        "",
        "    ofrak.run(main)",
        "",
    ]

    actual_str = join_and_normalize(resp_body)
    assert actual_str == "\n".join(normalized_expected_list)


async def test_clear_action_queue(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    root = await create_resp.json()
    root_id = root["id"]

    # StringFindReplace will fail because replacement string is longer than original
    await ofrak_client.post(
        f"/{root_id}/find_and_replace",
        json=[
            "ofrak.core.strings.StringFindReplaceConfig",
            {
                "to_find": "cat",
                "replace_with": "meow",
                "null_terminate": True,
                "allow_overflow": False,
            },
        ],
    )

    # Force script to update to ensure nothing is missed in the queue
    await ofrak_client.post(f"/{root_id}/unpack")

    # Verify string modify action was dequeued and not in the script
    resp = await ofrak_client.get(
        f"/{root_id}/get_script",
    )
    resp_body = await resp.json()
    expected_list = [
        "from ofrak import *",
        "from ofrak.core import *",
        "from ofrak.gui.script_builder import get_child_by_range",
        "",
        "",
        "async def main(ofrak_context: OFRAKContext):",
        "    root_resource = await ofrak_context.create_root_resource_from_file(",
        '        "hello_world_elf"',
        "    )",
        "",
        "    await root_resource.unpack()",
        "",
        "",
        'if __name__ == "__main__":',
        "    ofrak = OFRAK()",
        "    if False:",
        "        import ofrak_angr",
        "        import ofrak_capstone",
        "",
        "        ofrak.discover(ofrak_capstone)",
        "        ofrak.discover(ofrak_angr)",
        "",
        "    if False:",
        "        import ofrak_binary_ninja",
        "        import ofrak_capstone",
        "",
        "        ofrak.discover(ofrak_capstone)",
        "        ofrak.discover(ofrak_binary_ninja)",
        "",
        "    if False:",
        "        import ofrak_ghidra",
        "",
        "        ofrak.discover(ofrak_ghidra)",
        "",
        "    ofrak.run(main)",
        "",
    ]


async def test_get_components(ofrak_client: TestClient, hello_world_elf, ofrak_context):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resource_id = create_body["id"]
    resp = await ofrak_client.post(
        f"/{resource_id}/get_components",
        json={
            "show_all_components": True,
            "target_filter": None,
            "analyzers": True,
            "modifiers": True,
            "packers": True,
            "unpackers": True,
        },
    )
    components = set(await resp.json())
    expected_components = ofrak_context.component_locator.get_components_matching_filter(
        ComponentOrMetaFilter(
            ComponentTypeFilter(Analyzer),
            ComponentTypeFilter(Unpacker),
            ComponentTypeFilter(Modifier),
            ComponentTypeFilter(Packer),
        )
    )
    assert components == {
        type(comp).__name__ for comp in expected_components if "Angr" not in type(comp).__name__
    }


async def test_get_config(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resource_id = create_body["id"]
    components_resp = await ofrak_client.post(
        f"/{resource_id}/get_components",
        json={
            "show_all_components": True,
            "target_filter": None,
            "analyzers": True,
            "modifiers": True,
            "packers": True,
            "unpackers": True,
        },
    )
    components = await components_resp.json()
    configs = []
    for component in components:
        configs_resp = await ofrak_client.get(
            f"/{resource_id}/get_config_for_component",
            params={"component": component},
        )
        configs.append(await configs_resp.json())
    assert len(configs) == len(components)
    config_resp = await ofrak_client.get(
        f"/{resource_id}/get_config_for_component",
        params={"component": "UpdateLinkableSymbolsModifier"},
    )
    config = await config_resp.json()
    assert config == {
        "name": "UpdateLinkableSymbolsModifierConfig",
        "type": "ofrak.core.patch_maker.linkable_binary.UpdateLinkableSymbolsModifierConfig",
        "args": None,
        "enum": None,
        "fields": [
            {
                "name": "updated_symbols",
                "type": "typing.List",
                "args": [
                    {
                        "name": None,
                        "type": "ofrak.core.patch_maker.linkable_symbol.LinkableSymbol",
                        "args": None,
                        "fields": [
                            {
                                "name": "virtual_address",
                                "type": "builtins.int",
                                "args": None,
                                "fields": None,
                                "enum": None,
                                "default": None,
                            },
                            {
                                "name": "name",
                                "type": "builtins.str",
                                "args": None,
                                "fields": None,
                                "enum": None,
                                "default": None,
                            },
                            {
                                "name": "symbol_type",
                                "type": "ofrak_type.symbol_type.LinkableSymbolType",
                                "args": None,
                                "fields": None,
                                "enum": {"FUNC": 0, "RW_DATA": 1, "RO_DATA": 2, "UNDEF": -1},
                                "default": None,
                            },
                            {
                                "name": "mode",
                                "type": "ofrak_type.architecture.InstructionSetMode",
                                "args": None,
                                "fields": None,
                                "enum": {"NONE": 0, "THUMB": 1, "VLE": 2},
                                "default": 0,
                            },
                        ],
                        "enum": None,
                        "default": None,
                    }
                ],
                "fields": None,
                "enum": None,
                "default": None,
            }
        ],
    }


async def test_search_string(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resource_id = create_body["id"]
    resp = await ofrak_client.post(
        f"/{resource_id}/search_for_string",
        json={"search_query": "he[l]{2}o", "caseIgnore": False, "regex": True},
    )
    resp_body = await resp.json()
    assert resp.status == 200
    assert resp_body == ["00000001"]
    resp = await ofrak_client.post(
        f"/{resource_id}/search_for_string",
        json={"search_query": "hello", "caseIgnore": False, "regex": False},
    )
    resp_body = await resp.json()
    assert resp.status == 200
    assert resp_body == ["00000001"]
    resp = await ofrak_client.post(
        f"/{resource_id}/search_for_string",
        json={"search_query": "he[l]{2}o", "caseIgnore": False, "regex": False},
    )
    resp_body = await resp.json()
    assert resp.status == 200
    assert resp_body == []
    resp = await ofrak_client.post(
        f"/{resource_id}/search_for_string",
        json={"search_query": "He[l]{2}o", "caseIgnore": True, "regex": True},
    )
    resp_body = await resp.json()
    assert resp.status == 200
    assert resp_body == ["00000001"]
    resp = await ofrak_client.post(
        f"/{resource_id}/search_for_string",
        json={"search_query": "HE[l]{2}O", "caseIgnore": False, "regex": True},
    )
    resp_body = await resp.json()
    assert resp.status == 200
    assert resp_body == []
    resp = await ofrak_client.post(
        f"/{resource_id}/search_for_string",
        json={"search_query": "he[l]{2}o", "caseIgnore": True, "regex": False},
    )
    resp_body = await resp.json()
    assert resp.status == 200
    assert resp_body == []


async def test_search_bytes(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resource_id = create_body["id"]
    resp = await ofrak_client.post(
        f"/{resource_id}/search_for_bytes",
        json={"search_query": "68 65 6c 6c 6f", "regex": False},
    )
    resp_body = await resp.json()
    assert resp.status == 200
    assert resp_body == ["00000001"]
    resp = await ofrak_client.post(
        f"/{resource_id}/search_for_bytes",
        json={"search_query": "68 65 6c 3c 6f", "regex": False},
    )
    resp_body = await resp.json()
    assert resp.status == 200
    assert resp_body == []


async def test_get_tags_and_num_components(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resource_id = create_body["id"]
    resp = await ofrak_client.post(
        f"/{resource_id}/get_tags_and_num_components",
        json={
            "target": "File",
            "analyzers": True,
            "modifiers": True,
            "packers": True,
            "unpackers": True,
        },
    )
    resp_body = await resp.json()
    assert (
        resp.status == 200
    )  # The result of the components differs based on the number of components in OFRAK, so checking the exact output will break everytime a component is added.


async def test_run_component(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resource_id = create_body["id"]
    resp = await ofrak_client.post(
        f"/{resource_id}/run_component",
        params={"component": "StringFindReplaceModifier"},
        json=[
            "ofrak.core.strings.StringFindReplaceConfig",
            {
                "allow_overflow": False,
                "null_terminate": False,
                "to_find": "ELF",
                "replace_with": "ORC",
            },
        ],
    )
    assert resp.status == 200
    resp_body = await resp.json()
    expected_list = {
        "created": [],
        "modified": [
            {
                "id": "00000001",
                "data_id": "00000001",
                "parent_id": None,
                "tags": ["ofrak.core.filesystem.File", "ofrak.core.filesystem.FilesystemEntry"],
                "attributes": [
                    [],
                ],
                "caption": "File",
            }
        ],
        "deleted": [],
    }
    expected_str = join_and_normalize(expected_list)
    actual_str = join_and_normalize(resp_body)
    assert actual_str == expected_str


async def test_add_flush_to_disk_to_script(ofrak_client: TestClient, firmware_zip):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "firmware_zip"}, data=firmware_zip
    )
    root = await create_resp.json()
    root_id = root["id"]

    await ofrak_client.post(f"/{root_id}/unpack")
    child_resp = await ofrak_client.post(f"/batch/get_children", json=[root_id])
    child_body = await child_resp.json()
    only_child_id = child_body[root_id][0]["id"]
    await ofrak_client.post(f"/{only_child_id}/unpack")
    grandchildren_resp = await ofrak_client.post(f"/batch/get_children", json=[only_child_id])
    grandchildren_body = await grandchildren_resp.json()
    eldest_grandchild_id = grandchildren_body[only_child_id][0]["id"]
    await ofrak_client.post(
        f"/{eldest_grandchild_id}/add_flush_to_disk_to_script", json="DIR655B1_FW203NAB02.bin"
    )

    resp = await ofrak_client.get(
        f"/{root_id}/get_script",
    )
    resp_body = await resp.json()
    expected_list = [
        "from ofrak import *",
        "from ofrak.core import *",
        "from ofrak.gui.script_builder import get_child_by_range",
        "",
        "",
        "async def main(ofrak_context: OFRAKContext, root_resource: Optional[Resource] = None):",
        "    if root_resource is None:",
        "        root_resource = await ofrak_context.create_root_resource_from_file(",
        '            "firmware_zip"',
        "        )",
        "",
        "    await root_resource.unpack()",
        "",
        "    folder_dir655_revB_FW_203NA = await root_resource.get_only_child(",
        "        r_filter=ResourceFilter(",
        "            tags={Folder},",
        "            attribute_filters=[",
        "                ResourceAttributeValueFilter(",
        "                    attribute=AttributesType[FilesystemEntry].Name,",
        '                    value="dir655_revB_FW_203NA",',
        "                )",
        "            ],",
        "        )",
        "    )",
        "",
        "    await folder_dir655_revB_FW_203NA.unpack()",
        "",
        "    file_DIR655B1_FW203NAB02_bin = await folder_dir655_revB_FW_203NA.get_only_child(",
        "        r_filter=ResourceFilter(",
        "            tags={File},",
        "            attribute_filters=[",
        "                ResourceAttributeValueFilter(",
        "                    attribute=AttributesType[FilesystemEntry].Name,",
        '                    value="DIR655B1_FW203NAB02.bin",',
        "                )",
        "            ],",
        "        )",
        "    )",
        "",
        '    await file_DIR655B1_FW203NAB02_bin.flush_data_to_disk("DIR655B1_FW203NAB02.bin")',
        "",
        "",
        'if __name__ == "__main__":',
        "    ofrak = OFRAK()",
        "    if False:",
        "        import ofrak_angr",
        "        import ofrak_capstone",
        "",
        "        ofrak.discover(ofrak_capstone)",
        "        ofrak.discover(ofrak_angr)",
        "",
        "    if False:",
        "        import ofrak_binary_ninja",
        "        import ofrak_capstone",
        "",
        "        ofrak.discover(ofrak_capstone)",
        "        ofrak.discover(ofrak_binary_ninja)",
        "",
        "    if False:",
        "        import ofrak_ghidra",
        "",
        "        ofrak.discover(ofrak_ghidra)",
        "",
        "    ofrak.run(main)",
        "",
    ]

    expected_str = join_and_normalize(expected_list)
    actual_str = join_and_normalize(resp_body)
    assert actual_str == expected_str


async def test_search_data(ofrak_client: TestClient, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resource_id = create_body["id"]
    resp = await ofrak_client.post(
        f"/{resource_id}/search_data",
        json={
            "search_query": "H[a-z]llo",
            "searchType": "String",
            "regex": True,
            "caseIgnore": False,
        },
    )
    resp_body1 = await resp.json()
    assert resp.status == 200
    assert resp_body1 == [[1496, 5]]
    resp = await ofrak_client.post(
        f"/{resource_id}/search_data",
        json={"search_query": "hello", "searchType": "String", "regex": False, "caseIgnore": True},
    )
    resp_body1 = await resp.json()
    assert resp.status == 200
    assert len(resp_body1) >= len([[1496, 5]])
    assert [1496, 5] in resp_body1
    resp = await ofrak_client.post(
        f"/{resource_id}/search_data",
        json={
            "search_query": "hel[a-z]o",
            "searchType": "String",
            "regex": True,
            "caseIgnore": True,
        },
    )
    resp_body1 = await resp.json()
    assert resp.status == 200
    assert len(resp_body1) >= len([[1496, 5]])
    assert [1496, 5] in resp_body1
    resp = await ofrak_client.post(
        f"/{resource_id}/search_data",
        json={
            "search_query": "hel[a-z]o",
            "searchType": "String",
            "regex": False,
            "caseIgnore": True,
        },
    )
    resp_body1 = await resp.json()
    assert resp.status == 200
    assert resp_body1 == []
    resp = await ofrak_client.post(
        f"/{resource_id}/search_data",
        json={"search_query": "hello", "searchType": "String", "regex": False, "caseIgnore": False},
    )
    resp_body1 = await resp.json()
    assert resp.status == 200
    assert [1496, 5] not in resp_body1
    resp = await ofrak_client.post(
        f"/{resource_id}/search_data",
        json={"search_query": "Hello", "searchType": "String", "regex": False, "caseIgnore": False},
    )
    resp_body1 = await resp.json()
    assert resp.status == 200
    assert resp_body1 == [[1496, 5]]
    resp = await ofrak_client.post(
        f"/{resource_id}/search_data",
        json={
            "search_query": "48656c6c6f",
            "searchType": "Bytes",
        },  # binascii.hexlify("Hello".encode("utf-8")).decode('ascii')
    )
    resp_body2 = await resp.json()
    assert resp.status == 200
    assert resp_body1 == resp_body2


async def test_create_new_project(ofrak_client: TestClient, test_project_dir):
    resp = await ofrak_client.post(
        "/create_new_project",
        json={"name": "test"},
    )
    assert resp.status == 200


async def test_get_project_by_id(ofrak_client: TestClient, test_project_dir):
    resp = await ofrak_client.post(
        "/create_new_project",
        json={"name": "test"},
    )
    assert resp.status == 200
    resp_body = await resp.json()
    id = resp_body["id"]

    resp = await ofrak_client.get("/get_project_by_id", params={"id": id})
    assert resp.status == 200
    body = await resp.json()
    assert list(body.keys()) == [
        "name",
        "project_id",
        "session_id",
        "resource_ids",
        "scripts",
        "binaries",
    ]


async def test_get_all_projects(ofrak_client: TestClient, test_project_dir):
    resp = await ofrak_client.post(
        "/create_new_project",
        json={"name": "test1"},
    )
    assert resp.status == 200
    resp_body = await resp.json()
    id1 = resp_body["id"]

    resp = await ofrak_client.post(
        "/create_new_project",
        json={"name": "test2"},
    )
    assert resp.status == 200
    resp_body = await resp.json()
    id2 = resp_body["id"]

    resp = await ofrak_client.get("/get_all_projects")
    assert resp.status == 200
    body = await resp.json()
    assert len(body) == 2
    assert "test1" in [project["name"] for project in body]
    assert "test2" in [project["name"] for project in body]
    assert id1 in [project["session_id"] for project in body]
    assert id2 in [project["session_id"] for project in body]


async def test_reset_project(ofrak_client: TestClient, test_project_dir):
    resp = await ofrak_client.post(
        "/create_new_project",
        json={"name": "test"},
    )
    assert resp.status == 200
    resp_body = await resp.json()
    id = resp_body["id"]
    resp = await ofrak_client.post(
        "/reset_project",
        json={"id": id},
    )
    assert resp.status == 200


async def test_add_binary_to_project(ofrak_client: TestClient, test_project_dir, hello_world_elf):
    resp = await ofrak_client.post(
        "/create_new_project",
        json={"name": "test"},
    )
    assert resp.status == 200
    resp_body = await resp.json()
    id = resp_body["id"]
    resp = await ofrak_client.post(
        "/add_binary_to_project",
        params={"id": id, "name": "hello_world_elf"},
        data=hello_world_elf,
    )
    assert resp.status == 200


async def test_add_script_to_project(ofrak_client: TestClient, test_project_dir):
    script = b"async def main(ofrak_context: OFRAKContext, root_resource: Optional[Resource] = None):\n\tawait root_resource.unpack()"
    resp = await ofrak_client.post(
        "/create_new_project",
        json={"name": "test"},
    )
    assert resp.status == 200
    resp_body = await resp.json()
    id = resp_body["id"]
    resp = await ofrak_client.post(
        "/add_script_to_project", params={"id": id, "name": "unpack.py"}, data=script
    )
    assert resp.status == 200


async def test_get_projects_path(ofrak_client: TestClient, test_project_dir):
    resp = await ofrak_client.get("/get_projects_path")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body == test_project_dir


async def test_save_project_data(ofrak_client: TestClient, test_project_dir, hello_world_elf):
    script = b"async def main(ofrak_context: OFRAKContext, root_resource: Optional[Resource] = None):\n\tawait root_resource.unpack()"
    resp = await ofrak_client.post(
        "/create_new_project",
        json={"name": "test"},
    )
    assert resp.status == 200
    resp_body = await resp.json()
    id = resp_body["id"]
    resp = await ofrak_client.post(
        "/add_script_to_project", params={"id": id, "name": "unpack.py"}, data=script
    )
    assert resp.status == 200
    resp = await ofrak_client.post(
        "/add_binary_to_project",
        params={"id": id, "name": "hello_world_elf"},
        data=hello_world_elf,
    )
    assert resp.status == 200
    resp = await ofrak_client.get("/get_project_by_id", params={"id": id})
    assert resp.status == 200
    project = await resp.json()
    resp = await ofrak_client.post("/save_project_data", json=project)
    assert resp.status == 200
    resp = await ofrak_client.post("/reset_project", json={"id": id})
    assert resp.status == 200
    resp = await ofrak_client.get("/get_all_projects")
    assert resp.status == 200
    resp_body = await resp.json()
    resp = await ofrak_client.post(
        "/add_binary_to_project",
        params={"id": id, "name": "hello_world_elf"},
        data=hello_world_elf,
    )
    assert resp.status == 200
    assert len(resp_body) == 1
    assert resp_body[0]["scripts"] == [{"name": "unpack.py"}]
    assert resp_body[0]["binaries"] == {
        "hello_world_elf": {"init_script": None, "associated_scripts": []}
    }
    assert resp.status == 200


async def test_delete_from_project(ofrak_client: TestClient, test_project_dir, hello_world_elf):
    script = b"async def main(ofrak_context: OFRAKContext, root_resource: Optional[Resource] = None):\n\tawait root_resource.unpack()"
    resp = await ofrak_client.post(
        "/create_new_project",
        json={"name": "test"},
    )
    assert resp.status == 200
    resp_body = await resp.json()
    id = resp_body["id"]
    resp = await ofrak_client.post(
        "/add_script_to_project", params={"id": id, "name": "unpack.py"}, data=script
    )
    assert resp.status == 200
    resp = await ofrak_client.post(
        "/add_binary_to_project",
        params={"id": id, "name": "hello_world_elf"},
        data=hello_world_elf,
    )
    assert resp.status == 200
    resp = await ofrak_client.get("/get_project_by_id", params={"id": id})
    assert resp.status == 200
    project = await resp.json()
    resp = await ofrak_client.post("/save_project_data", json=project)
    assert resp.status == 200
    resp = await ofrak_client.post("/reset_project", json={"id": id})
    assert resp.status == 200
    resp = await ofrak_client.get("/get_all_projects")
    assert resp.status == 200
    resp_body = await resp.json()
    assert len(resp_body) == 1
    assert resp_body[0]["scripts"] == [{"name": "unpack.py"}]
    assert resp_body[0]["binaries"] == {
        "hello_world_elf": {"init_script": None, "associated_scripts": []}
    }
    resp = await ofrak_client.post(
        "/delete_script_from_project",
        json={"id": id, "script": "unpack.py"},
    )
    assert resp.status == 200
    resp = await ofrak_client.post(
        "/delete_binary_from_project",
        json={"id": id, "binary": "hello_world_elf"},
    )
    assert resp.status == 200
    resp = await ofrak_client.get("/get_project_by_id", params={"id": id})
    assert resp.status == 200
    project = await resp.json()
    resp = await ofrak_client.post("/save_project_data", json=project)
    resp = await ofrak_client.post("/reset_project", json={"id": id})
    resp = await ofrak_client.get("/get_all_projects")
    resp_body = await resp.json()
    assert resp_body[0]["scripts"] == []
    assert resp_body[0]["binaries"] == {}


async def test_get_project_script(ofrak_client: TestClient, test_project_dir):
    script = b"async def main(ofrak_context: OFRAKContext, root_resource: Optional[Resource] = None):\n\tawait root_resource.unpack()"
    resp = await ofrak_client.post(
        "/create_new_project",
        json={"name": "test"},
    )
    assert resp.status == 200
    resp_body = await resp.json()
    id = resp_body["id"]
    resp = await ofrak_client.post(
        "/add_script_to_project", params={"id": id, "name": "unpack.py"}, data=script
    )
    assert resp.status == 200
    resp = await ofrak_client.get(
        "/get_project_script",
        params={"project": id, "script": "unpack.py"},
    )
    assert resp.status == 200
    resp_body = await resp.text()
    assert resp_body == script.decode()


async def test_git_clone_project(ofrak_client: TestClient, test_project_dir):
    git_url = "https://github.com/redballoonsecurity/ofrak-project-example.git"
    resp = await ofrak_client.post("/clone_project_from_git", json={"url": git_url})
    assert resp.status == 200
    resp_body = await resp.json(content_type=None)
    id = resp_body["id"]
    resp = await ofrak_client.get("/get_project_by_id", params={"id": id})
    assert resp.status == 200
    resp_body = await resp.json(content_type=None)
    assert resp_body["scripts"] == [
        {"name": "unpack-and-comment.py"},
        {"name": "unpack.py"},
        {"name": "modify.py"},
    ]
    assert resp_body["binaries"] == {
        "example_program": {
            "init_script": "modify.py",
            "associated_scripts": ["unpack-and-comment.py", "unpack.py", "modify.py"],
        }
    }


async def test_open_project(ofrak_client: TestClient, test_project_dir):
    git_url = "https://github.com/whyitfor/ofrak-project-example.git"
    resp = await ofrak_client.post("/clone_project_from_git", json={"url": git_url})
    assert resp.status == 200
    resp_body = await resp.json(content_type=None)
    id = resp_body["id"]
    resp = await ofrak_client.post(
        "/open_project",
        json={"id": id, "binary": "example_program", "script": "unpack-and-comment.py"},
    )
    assert resp.status == 200
    resp_body = await resp.json(content_type=None)
    assert resp_body["id"] == "00000001"


async def test_get_project_by_resource_id(ofrak_client: TestClient, test_project_dir):
    git_url = "https://github.com/whyitfor/ofrak-project-example.git"
    resp = await ofrak_client.post("/clone_project_from_git", json={"url": git_url})
    assert resp.status == 200
    resp_body = await resp.json()
    id = resp_body["id"]
    resp = await ofrak_client.post(
        "/open_project",
        json={"id": id, "binary": "example_program", "script": "unpack-and-comment.py"},
    )
    assert resp.status == 200
    resp_body = await resp.json()
    resource_id = resp_body["id"]
    project_resp = await ofrak_client.get(f"/{resource_id}/get_project_by_resource_id")
    project = await project_resp.json()
    assert project["session_id"] == id
