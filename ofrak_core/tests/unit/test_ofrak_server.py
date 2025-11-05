"""
Test the OFRAK HTTP server API endpoints and GUI backend functionality.
"""
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
async def test_resource(ofrak_context, hello_elf):
    return await ofrak_context.create_root_resource("hello_elf", hello_elf, (File,))


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
    """
    Tests the OFRAK server can be started and responds to requests.

    This test verifies that:
    - The server process can be launched successfully
    - The server responds to HTTP requests on the configured port
    - The index route returns a successful status code
    """
    args = {"ofrak_context": ofrak_context, "host": "127.0.0.1", "port": 8080}
    proc = Process(target=start_server, kwargs=args)
    proc.start()
    resp = await ofrak_client.get("/")
    assert resp.status == 200
    proc.join(timeout=5)


async def test_error(ofrak_client: TestClient):
    """
    Test error handling for invalid routes.

    This test verifies that:
    - Requests to invalid routes return appropriate error status codes
    - The server handles malformed requests gracefully
    """
    resp = await ofrak_client.get("/1234/")
    assert resp.status == 500


# Test calls to each of the routes set on the server, this should hit each of the callbacks
async def test_get_index(ofrak_client: TestClient):
    """
    Test the index route returns the HTML interface.

    This test verifies that:
    - The index route is accessible
    - The response is a successful HTML document
    - The content type is correctly set to text/html
    """
    resp = await ofrak_client.get("/")
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "text/html"


async def test_create_root_resource(
    ofrak_client: TestClient, ofrak_server, hello_elf, test_resource
):
    """
    Test creating a root resource from binary data.

    This test verifies that:
    - A root resource can be created via HTTP POST with binary data
    - The response contains a valid resource ID
    - The created resource has the expected tags
    - The serialized resource matches the expected structure
    """
    resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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
    """
    Test creating a large root resource using chunked upload.

    This test verifies that:
    - A root resource can be initialized for chunked upload
    - Large binary data can be uploaded in multiple chunks
    - The chunked upload completes successfully
    - The final resource has the correct data length
    """
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


async def test_get_root_resources(ofrak_client: TestClient, ofrak_context, ofrak_server, hello_elf):
    """
    Test retrieving all root resources.

    This test verifies that:
    - Root resources can be retrieved via the API
    - The response includes resource IDs and attributes
    - The serialized attributes match the expected format
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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


async def test_get_resource(ofrak_client: TestClient, hello_elf):
    """
    Test retrieving a specific resource by ID.

    This test verifies that:
    - A resource can be retrieved by its ID via the API
    - The response is successful
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    body = await create_resp.json()
    resp = await ofrak_client.get(f"/{body['id']}/")
    assert resp.status == 200

    # TODO: How test directly? Package up in request and send to ofrak_server?


async def test_get_data(ofrak_client: TestClient, hello_elf):
    """
    Test retrieving resource data with and without range parameters.

    This test verifies that:
    - Full resource data can be retrieved
    - A specific range of data can be retrieved with range parameters
    - The returned data matches the original binary data
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.get(f"/{create_body['id']}/get_data")
    assert resp.status == 200
    resp_body = await resp.read()
    assert resp_body == hello_elf
    resp = await ofrak_client.get(f"/{create_body['id']}/get_data", params={"range": "[16,80]"})
    assert resp.status == 200
    resp_body = await resp.read()
    assert resp_body == hello_elf[0x10:0x50]


async def test_get_data_length(ofrak_client: TestClient, hello_elf):
    """
    Test retrieving the length of resource data.

    This test verifies that:
    - The data length endpoint returned length matches the actual binary data length
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.get(f"/{create_body['id']}/get_data_length")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body == len(hello_elf)


async def test_unpack(ofrak_client: TestClient, hello_elf):
    """
    Test unpacking a resource.

    This test verifies that:
    - A resource can be unpacked via the API
    - The unpack operation creates child resources
    - The response includes the created resources
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/unpack")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["created"] is not None


async def test_get_children(ofrak_client: TestClient, hello_elf):
    """
    Test retrieving child resources in batch.

    This test verifies that:
    - Child resources can be retrieved for multiple parent resources
    - The batch get_children endpoint returns all children
    - The response structure maps parent IDs to their children
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    root = await create_resp.json()
    root_id = root["id"]
    await ofrak_client.post(f"/{root_id}/unpack")
    children_resp = await ofrak_client.post(f"/batch/get_children", json=[root_id])
    assert children_resp.status == 200
    children_body = await children_resp.json()
    assert root_id in children_body
    assert len(children_body[root_id]) > 1


async def test_get_descendants(ofrak_client: TestClient, hello_elf):
    """
    Test retrieving all descendant resources recursively.

    This test verifies that:
    - All descendants of a resource can be retrieved
    - The descendants include all direct children
    - The response includes all nested resources
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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


async def test_get_data_range(ofrak_client: TestClient, hello_elf):
    """
    Test retrieving data ranges for child resources.

    This test verifies that:
    - Data ranges can be retrieved for all child resources
    - The batch get_data_range endpoint works correctly
    - The returned ranges match expected values
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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
async def test_get_root(ofrak_client: TestClient, hello_elf):
    """
    Test retrieving the root resource for a given resource.

    This test verifies that:
    - The get_root endpoint is accessible
    - The root resource can be retrieved for any resource ID
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    body = await create_resp.json()
    resp = await ofrak_client.get(f"/{body['id']}/get_root")
    assert resp.status == 200


async def test_unpack_recursively(ofrak_client: TestClient, hello_elf):
    """
    Test recursively unpacking a resource and all its children.

    This test verifies that:
    - A resource can be unpacked recursively via the API
    - All nested resources are unpacked
    - The response includes all created resources
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/unpack_recursively")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["created"] is not None


# Cannot find manual example to compare against
async def test_pack(ofrak_client: TestClient, hello_elf):
    """
    Test packing a resource.

    This test verifies that:
    - A resource can be packed via the API
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    body = await create_resp.json()
    resp = await ofrak_client.post(f"/{body['id']}/pack")
    assert resp.status == 200


# Cannot find manual example to compare against
async def test_pack_recursively(ofrak_client: TestClient, hello_elf):
    """
    Test recursively packing a resource and all its children.

    This test verifies that:
    - A resource can be packed recursively via the API
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    body = await create_resp.json()
    resp = await ofrak_client.post(f"/{body['id']}/pack_recursively")
    assert resp.status == 200


async def test_analyze(ofrak_client: TestClient, hello_elf):
    """
    Test analyzing a resource to extract attributes.

    This test verifies that:
    - A resource can be analyzed via the API
    - The analyze operation returns results
    - Analysis attributes are populated
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/analyze")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body is not None


async def test_identify(ofrak_client: TestClient, hello_elf):
    """
    Test identifying a resource to determine its type.

    This test verifies that:
    - A resource can be identified via the API
    - The identify operation modifies the resource
    - The resource ID in the response matches the original
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/identify")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]


async def test_identify_recursively(ofrak_client: TestClient, hello_elf):
    """
    Test recursively identifying a resource and all its children.

    This test verifies that:
    - A resource can be identified recursively via the API
    - The identify operation modifies the resource
    - The resource ID in the response matches the original
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/identify_recursively")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]


async def test_data_summary(
    ofrak_client: TestClient, ofrak_server, hello_elf, test_resource: Resource
):
    """
    Test retrieving a data summary including entropy and magnitude samples.

    This test verifies that:
    - A data summary can be retrieved via the API
    - The response includes entropy and magnitude samples
    - The API results match direct analyzer invocation
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/data_summary")
    assert resp.status == 200
    resp_body = await resp.json()

    # Compare result from accessing directly
    data_summary_analyzer = test_resource._job_service._component_locator.get_by_id(
        DataSummaryAnalyzer.get_id()
    )
    data_summary = await data_summary_analyzer.get_data_summary(test_resource)
    assert resp_body == {
        "entropy_samples": list(data_summary.entropy_samples),
        "magnitude_samples": list(data_summary.magnitude_samples),
    }


async def test_get_parent(ofrak_client: TestClient, hello_elf):
    """
    Test retrieving the parent resource of a child.

    This test verifies that:
    - The parent resource can be retrieved for a child resource
    - The returned parent ID matches the expected parent
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    unpack_resp = await ofrak_client.post(f"/{create_body['id']}/unpack")
    unpack_body = await unpack_resp.json()
    resp = await ofrak_client.get(f"/{unpack_body['created'][0]['id']}/get_parent")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["id"] == create_body["id"]


async def test_get_ancestors(ofrak_client: TestClient, hello_elf):
    """
    Test retrieving all ancestor resources.

    This test verifies that:
    - All ancestors can be retrieved for a resource
    - The list includes the direct parent
    - Ancestor IDs are correctly returned
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    unpack_resp = await ofrak_client.post(f"/{create_body['id']}/unpack")
    unpack_body = await unpack_resp.json()
    resp = await ofrak_client.get(f"/{unpack_body['created'][0]['id']}/get_ancestors")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body[0]["id"] == create_body["id"]


async def test_queue_patch(ofrak_client: TestClient, hello_elf):
    """
    Test queueing a patch operation on a resource.

    This test verifies that:
    - A patch can be queued for a resource via the API
    - The patch operation returns the modified resource
    - The resource ID remains consistent
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    unpack_resp = await ofrak_client.post(f"/{create_body['id']}/unpack")
    resp = await ofrak_client.post(f"/{create_body['id']}/queue_patch", data=hello_elf)
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["id"] == create_body["id"]


async def test_create_mapped_child(ofrak_client: TestClient, hello_elf):
    """
    Test creating a mapped child resource with a specific data range.

    This test verifies that:
    - A mapped child can be created from a parent resource
    - The child is mapped to the correct data range
    - The parent-child relationship is established correctly
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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
async def test_find_and_replace(ofrak_client: TestClient, hello_elf):
    """
    Test the find and replace string modification functionality.

    This test verifies that:
    - String find and replace can be performed on a resource
    - The operation completes successfully
    - The API accepts properly formatted configuration
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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


async def test_add_comment(ofrak_server, aiohttp_client, hello_elf):
    """
    Test adding comments to resources with various range configurations.

    This test verifies that:
    - Comments can be added without a range
    - Comments can be added with specific byte ranges
    - Multiple comments can be added to the same range
    - Invalid ranges are rejected
    - Comment counts are tracked correctly
    """
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_elf
    )
    create_body = await create_resp.json()
    # Try creating comments on invalid ranges
    resp = await client.post(
        f"/{create_body['id']}/add_comment",
        json=[[0, len(hello_elf) + 1], "test comment out of bounds"],
    )
    assert resp.status != 200
    resp = await client.post(
        f"/{create_body['id']}/add_comment",
        json=[[-1, len(hello_elf)], "test comment out of bounds"],
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
        f"/{create_body['id']}/add_comment", json=[[0, len(hello_elf)], "test comment 2"]
    )
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]
    resp = await client.post(
        f"/{create_body['id']}/add_comment", json=[[0, len(hello_elf)], "test comment 3"]
    )
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]
    # Check comment counts
    comment_range_count, comment_count = get_comment_count(resp_body)
    assert comment_range_count == 3
    assert comment_count == 4


# Test deleting comments using both the old and new format
async def test_delete_comment(ofrak_server, aiohttp_client, hello_elf):
    """
    Test deleting comments from resources.

    This test verifies that:
    - Specific comments can be deleted from a range
    - The last comment in a range can be deleted
    - Entire comment ranges can be deleted
    - Comment counts are updated correctly after deletion
    """
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_elf
    )
    create_body = await create_resp.json()
    # Comments to delete
    await client.post(f"/{create_body['id']}/add_comment", json=[None, "test comment 0"])
    await client.post(f"/{create_body['id']}/add_comment", json=[None, "test comment 1"])
    await client.post(
        f"/{create_body['id']}/add_comment", json=[[0, len(hello_elf)], "test comment 0"]
    )
    resp = await client.post(
        f"/{create_body['id']}/add_comment", json=[[0, len(hello_elf)], "test comment 1"]
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
    resp = await client.post(f"/{create_body['id']}/delete_comment", json=[0, len(hello_elf)])
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]
    assert (0, 0) == get_comment_count(resp_body)  # All comments should be gone


async def test_search_for_vaddr(ofrak_client: TestClient, hello_elf):
    """
    Test searching for resources by virtual address.

    This test verifies that:
    - Resources can be searched by virtual address
    - The search returns matching resources
    - Virtual address queries work correctly
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    await ofrak_client.post(f"/{create_body['id']}/unpack_recursively")
    resp = await ofrak_client.post(f"/{create_body['id']}/search_for_vaddr", json=[0, None])
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body[0] is not None


async def test_get_all_tags(ofrak_client: TestClient):
    """
    Test retrieving all available OFRAK tags.

    This test verifies that:
    - All system tags can be retrieved
    - The response includes known tags like BasicBlock
    """
    resp = await ofrak_client.get(f"/get_all_tags")
    assert resp.status == 200
    resp_body = await resp.json()
    assert "ofrak.core.basic_block.BasicBlock" in resp_body


async def test_add_tag(ofrak_client: TestClient, hello_elf):
    """
    Test adding a tag to a resource.

    This test verifies that:
    - Tags can be added to resources via the API
    - The added tag appears in the resource's tag list
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    resource_id = create_body["id"]
    resp = await ofrak_client.post(
        f"/{resource_id}/add_tag",
        json="ofrak.core.apk.Apk",
    )
    assert resp.status == 200
    # Check tag is added
    add_tag_resp = await ofrak_client.get(f"/{resource_id}/")
    assert "ofrak.core.apk.Apk" in (await add_tag_resp.json())["tags"]


async def test_remove_tag(ofrak_client: TestClient, hello_elf):
    """
    Test removing a tag from a resource.

    This test verifies that:
    - Tags can be removed from resources via the API
    - The removed tag no longer appears in the resource's tag list
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    resource_id = create_body["id"]
    # First add a tag
    await ofrak_client.post(
        f"/{resource_id}/add_tag",
        json="ofrak.core.apk.Apk",
    )
    # Check tag is added
    add_tag_resp = await ofrak_client.get(f"/{resource_id}/")
    assert "ofrak.core.apk.Apk" in (await add_tag_resp.json())["tags"]

    # Then remove it
    resp = await ofrak_client.post(
        f"/{resource_id}/remove_tag",
        json="ofrak.core.apk.Apk",
    )
    assert resp.status == 200
    # Check tag is removed
    rem_tag_resp = await ofrak_client.get(f"/{resource_id}/")
    assert "ofrak.core.apk.Apk" not in (await rem_tag_resp.json())["tags"]


async def test_get_view_schema(ofrak_client: TestClient):
    """
    Test retrieving the schema for a resource view type.

    This test verifies that:
    - View schemas can be retrieved via the API
    - The schema includes name, type, and fields information
    - The schema matches the expected view type
    """
    resp = await ofrak_client.post(
        "/get_view_schema",
        json="ofrak.core.filesystem.File",
    )
    assert resp.status == 200
    resp_body = await resp.json()
    assert "name" in resp_body
    assert "type" in resp_body
    assert "fields" in resp_body
    assert resp_body["name"] == "File"


async def test_add_view_to_resource(ofrak_client: TestClient, hello_elf):
    """
    Test adding a view with attributes to a resource.

    This test verifies that:
    - Views can be added to resources with specified fields
    - The added attributes appear in the resource
    - Field values are correctly set
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    resource_id = create_body["id"]
    resp = await ofrak_client.post(
        f"/{resource_id}/add_view_to_resource",
        json={
            "view_type": "ofrak.core.filesystem.File",
            "fields": {"name": "test_file", "stat": None, "xattrs": None},
        },
    )
    assert resp.status == 200
    add_attribute_resp = await ofrak_client.get(f"/{resource_id}/")
    add_attribute_dict = {
        attr[0]: attr[1][1] for attr in (await add_attribute_resp.json())["attributes"]
    }
    assert (
        "ofrak.model._auto_attributes.AttributesType[FilesystemEntry]" in add_attribute_dict.keys()
    )
    fields = add_attribute_dict["ofrak.model._auto_attributes.AttributesType[FilesystemEntry]"]
    assert fields["name"] == "test_file"
    assert fields["stat"] == None
    assert fields["xattrs"] == None


async def test_remove_component(ofrak_client: TestClient, hello_elf):
    """
    Test removing a component from a resource.

    This test verifies that:
    - Components can be run on resources
    - Component attributes are added after running
    - Components can be removed via the API
    - Component attributes are removed after component removal
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    resource_id = create_body["id"]
    # First run a component to add it
    await ofrak_client.post(f"/{resource_id}/run_component?component=Md5Analyzer")
    # Check component is added
    add_component_resp = await ofrak_client.get(f"/{resource_id}/")
    add_attribute_names = [attr[0] for attr in (await add_component_resp.json())["attributes"]]
    assert "ofrak.core.checksum.Md5Attributes" in add_attribute_names

    # Then try to remove a component
    resp = await ofrak_client.post(
        f"/{resource_id}/remove_component",
        params={"component": "Md5Analyzer"},
    )
    assert resp.status == 200
    resp_body = await resp.json()
    assert "success" in resp_body
    # Check component is removed
    rem_component_resp = await ofrak_client.get(f"/{resource_id}/")
    rem_attribute_names = [attr[0] for attr in (await rem_component_resp.json())["attributes"]]
    assert "ofrak.core.checksum.Md5Attributes" not in rem_attribute_names


async def test_update_script(ofrak_client: TestClient, hello_elf):
    """
    Test automatic script generation from GUI actions.

    This test verifies that:
    - Actions performed in the GUI are tracked
    - A Python script can be generated from tracked actions
    - The generated script includes all operations performed
    - The script structure matches expected format
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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
        '        root_resource = await ofrak_context.create_root_resource_from_file("hello_elf")',
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
        "    if False:  # older Ghidra backend with Java server",
        "        import ofrak_ghidra",
        "",
        "        ofrak.discover(ofrak_ghidra)",
        "",
        "    if False:  # newer PyGhidra backend",
        "        import ofrak_pyghidra",
        "",
        "        ofrak.discover(ofrak_pyghidra)",
        "",
        "    ofrak.run(main)",
        "",
    ]

    expected_str = join_and_normalize(expected_list)
    actual_str = join_and_normalize(resp_body)
    assert actual_str == expected_str


async def test_selectable_attr_err(ofrak_client: TestClient, hello_elf):
    """
    Test script generation when selectable attribute errors occur.

    This test verifies that:
    - Duplicate children with identical attributes can be created
    - Script generation handles selectable attribute errors gracefully
    - Error comments are included in the generated script
    - Resource placeholders are created for missing resources
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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
        '        root_resource = await ofrak_context.create_root_resource_from_file("hello_elf")',
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
        "    if False:  # older Ghidra backend with Java server",
        "        import ofrak_ghidra",
        "",
        "        ofrak.discover(ofrak_ghidra)",
        "",
        "    if False:  # newer PyGhidra backend",
        "        import ofrak_pyghidra",
        "",
        "        ofrak.discover(ofrak_pyghidra)",
        "",
        "    ofrak.run(main)",
        "",
    ]

    actual_str = join_and_normalize(resp_body)
    assert actual_str == "\n".join(normalized_expected_list)


async def test_clear_action_queue(ofrak_client: TestClient, hello_elf):
    """
    Test that failed actions are removed from the script generation queue.

    This test verifies that:
    - Failed operations are tracked
    - Failed actions are removed from the action queue
    - The generated script does not include failed operations
    - Subsequent successful operations are still recorded
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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
        '        "hello_elf"',
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
        "    if False:  # older Ghidra backend with Java server",
        "        import ofrak_ghidra",
        "",
        "        ofrak.discover(ofrak_ghidra)",
        "",
        "    if False:  # newer PyGhidra backend",
        "        import ofrak_pyghidra",
        "",
        "        ofrak.discover(ofrak_pyghidra)",
        "",
        "    ofrak.run(main)",
        "",
    ]


async def test_get_components(ofrak_client: TestClient, hello_elf, ofrak_context):
    """
    Test retrieving available components for a resource.

    This test verifies that:
    - Components can be retrieved via the API
    - Filtering by component types works correctly
    - The returned components match the expected component set
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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


async def test_get_components_with_docstrings(ofrak_client: TestClient, hello_elf):
    """
    Test retrieving component information including docstrings.

    This test verifies that:
    - Components can be retrieved with documentation
    - The response format includes docstring information
    - Documentation is provided for each component
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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
            "include_docstrings": True,
        },
    )
    assert resp.status == 200
    components_with_docs = await resp.json()
    # Should return a dict with component names as keys and docstring info as values
    assert isinstance(components_with_docs, dict)
    # Check that at least one component has docstring information
    if components_with_docs:
        component_name = next(iter(components_with_docs))
        assert isinstance(components_with_docs[component_name], str)


async def test_get_config(ofrak_client: TestClient, hello_elf):
    """
    Test retrieving configuration schemas for components.

    This test verifies that:
    - Configuration schemas can be retrieved for components
    - All components return valid configuration information
    - The optional field is included in config responses
    - Complex nested configurations are properly serialized
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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
    # Verify the response includes the optional field
    assert "optional" in config
    assert config == {
        "name": "UpdateLinkableSymbolsModifierConfig",
        "type": "ofrak.core.patch_maker.linkable_binary.UpdateLinkableSymbolsModifierConfig",
        "optional": False,  # This component has a required config
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


async def test_run_component_no_config(ofrak_client: TestClient, hello_elf):
    """
    Test running a component without providing optional configuration.

    This test verifies that:
    - Components with optional config can run without providing config
    - The component executes successfully with default configuration
    - The response includes created, modified, and deleted resources
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    resource_id = create_body["id"]

    # Try to run a component that has an optional config without providing config
    resp = await ofrak_client.post(
        f"/{resource_id}/run_component",
        params={"component": "DataSummaryAnalyzer"},
        # No JSON body provided - testing optional config handling
    )
    assert resp.status == 200
    resp_body = await resp.json()
    # Just check that the response has the expected structure
    assert "created" in resp_body
    assert "modified" in resp_body
    assert "deleted" in resp_body


async def test_search_string(ofrak_client, hello_elf):
    """
    Test string searching with various options including regex and case sensitivity.

    This test verifies that:
    - Regex pattern matching works correctly
    - Literal string searching works correctly
    - Case-sensitive and case-insensitive search work as expected
    - Search returns correct resource IDs
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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


async def test_search_bytes(ofrak_client, hello_elf):
    """
    Test byte pattern searching.

    This test verifies that:
    - Hexadecimal byte patterns can be searched
    - Matching byte patterns return correct resource IDs
    - Non-matching patterns return empty results
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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


async def test_get_tags_and_num_components(ofrak_client: TestClient, hello_elf):
    """
    Test retrieving tag information and component counts for a target type.

    This test verifies that:
    - Tag and component count information can be retrieved
    - The API returns data for the specified target type
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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


async def test_run_component(ofrak_client: TestClient, hello_elf):
    """
    Test running a component with configuration.

    This test verifies that:
    - Components can be run with provided configuration
    - The component modifies the resource as expected
    - The response includes created, modified, and deleted resources
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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
    expected_result = {
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
    # Just check that the response has the expected structure
    assert "created" in resp_body
    assert "modified" in resp_body
    assert "deleted" in resp_body
    assert len(resp_body["modified"]) > 0


async def test_add_flush_to_disk_to_script(ofrak_client: TestClient, firmware_zip):
    """
    Test adding flush_to_disk actions to the generated script.

    This test verifies that:
    - Flush to disk operations can be added to the script
    - The generated script includes the flush_data_to_disk call
    - Resource navigation in the script uses proper filtering
    """
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
        "    if False:  # older Ghidra backend with Java server",
        "        import ofrak_ghidra",
        "",
        "        ofrak.discover(ofrak_ghidra)",
        "",
        "    if False:  # newer PyGhidra backend",
        "        import ofrak_pyghidra",
        "",
        "        ofrak.discover(ofrak_pyghidra)",
        "",
        "    ofrak.run(main)",
        "",
    ]

    expected_str = join_and_normalize(expected_list)
    actual_str = join_and_normalize(resp_body)
    assert actual_str == expected_str


async def test_search_data(ofrak_client: TestClient, hello_elf):
    """
    Test comprehensive data searching with strings and bytes.

    This test verifies that:
    - Data can be searched as strings with regex patterns
    - Data can be searched with case sensitivity options
    - Data can be searched as hexadecimal byte patterns
    - Search results return correct offset and length tuples
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
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
    """
    Test creating a new project.

    This test verifies that:
    - New projects can be created via the API
    """
    resp = await ofrak_client.post(
        "/create_new_project",
        json={"name": "test"},
    )
    assert resp.status == 200


async def test_get_project_by_id(ofrak_client: TestClient, test_project_dir):
    """
    Test retrieving a project by its ID.

    This test verifies that:
    - Projects can be retrieved by ID
    - The response includes all expected project fields
    - Project metadata is correctly structured
    """
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
    """
    Test retrieving all projects.

    This test verifies that:
    - All projects can be listed via the API
    - Multiple projects are included in the response
    - Project names and IDs are correctly returned
    """
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
    """
    Test resetting a project to its initial state.

    This test verifies that:
    - Projects can be reset via the API
    """
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


async def test_add_binary_to_project(ofrak_client: TestClient, test_project_dir, hello_elf):
    """
    Test adding a binary file to a project.

    This test verifies that:
    - Binary files can be added to projects
    """
    resp = await ofrak_client.post(
        "/create_new_project",
        json={"name": "test"},
    )
    assert resp.status == 200
    resp_body = await resp.json()
    id = resp_body["id"]
    resp = await ofrak_client.post(
        "/add_binary_to_project",
        params={"id": id, "name": "hello_elf"},
        data=hello_elf,
    )
    assert resp.status == 200


async def test_add_script_to_project(ofrak_client: TestClient, test_project_dir):
    """
    Test adding a script to a project.

    This test verifies that:
    - Python scripts can be added to projects
    """
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
    """
    Test retrieving the projects directory path.

    This test verifies that:
    - The projects directory path can be retrieved
    - The returned path matches the configured directory
    """
    resp = await ofrak_client.get("/get_projects_path")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body == test_project_dir


async def test_save_project_data(ofrak_client: TestClient, test_project_dir, hello_elf):
    """
    Test saving project data including scripts and binaries.

    This test verifies that:
    - Project data can be saved persistently
    - Scripts and binaries are preserved after reset
    - The saved project can be retrieved with correct contents
    """
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
        params={"id": id, "name": "hello_elf"},
        data=hello_elf,
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
        params={"id": id, "name": "hello_elf"},
        data=hello_elf,
    )
    assert resp.status == 200
    assert len(resp_body) == 1
    assert resp_body[0]["scripts"] == [{"name": "unpack.py"}]
    assert resp_body[0]["binaries"] == {
        "hello_elf": {"init_script": None, "associated_scripts": []}
    }
    assert resp.status == 200


async def test_delete_from_project(ofrak_client: TestClient, test_project_dir, hello_elf):
    """
    Test deleting scripts and binaries from a project.

    This test verifies that:
    - Scripts can be deleted from projects
    - Binaries can be deleted from projects
    - Deletions are persisted after saving
    - The project correctly reflects removed items
    """
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
        params={"id": id, "name": "hello_elf"},
        data=hello_elf,
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
        "hello_elf": {"init_script": None, "associated_scripts": []}
    }
    resp = await ofrak_client.post(
        "/delete_script_from_project",
        json={"id": id, "script": "unpack.py"},
    )
    assert resp.status == 200
    resp = await ofrak_client.post(
        "/delete_binary_from_project",
        json={"id": id, "binary": "hello_elf"},
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
    """
    Test retrieving a script from a project.

    This test verifies that:
    - Scripts can be retrieved by name from a project
    - The script content matches what was uploaded
    """
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
    """
    Test cloning a project from a git repository.

    This test verifies that:
    - Projects can be cloned from git URLs
    - Cloned projects include all scripts and binaries
    - Project metadata is correctly populated
    """
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
    """
    Test opening a project with a specific binary and script.

    This test verifies that:
    - Projects can be opened with a specified binary
    - An initialization script can be specified
    - Resources are created with the correct IDs
    """
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
    """
    Test retrieving a project using a resource ID.

    This test verifies that:
    - Projects can be looked up by resource ID
    - The project session ID matches the expected value
    """
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


async def test_get_all_program_attributes(ofrak_client: TestClient):
    """
    Test retrieving all available program architecture attributes.

    This test verifies that:
    - The get_all_program_attributes endpoint is accessible
    - All program attribute categories are returned
    - ISA (Instruction Set Architecture) options are included
    - Sub-ISA options are included
    - Bit width options are included
    - Endianness options are included
    - Processor type options are included
    - Specific known values exist for each category (ARM, ARMv4T, etc.)

    Requirements Mapping:
    - REQ2.2
    """
    resp = await ofrak_client.get(f"/get_all_program_attributes")
    assert resp.status == 200
    resp_body = await resp.json()
    # convert from list to dict form:
    resp_body_dict = {}
    for key, values in resp_body:
        resp_body_dict[key] = values
    assert "isa" in resp_body_dict
    assert "sub_isa" in resp_body_dict
    assert "bit_width" in resp_body_dict
    assert "endianness" in resp_body_dict
    assert "processor" in resp_body_dict
    assert "ofrak_type.architecture.InstructionSet.ARM" in resp_body_dict["isa"]
    assert "ofrak_type.architecture.SubInstructionSet.ARMv4T" in resp_body_dict["sub_isa"]
    assert "ofrak_type.bit_width.BitWidth.BIT_16" in resp_body_dict["bit_width"]
    assert "ofrak_type.endianness.Endianness.LITTLE_ENDIAN" in resp_body_dict["endianness"]
    assert "ofrak_type.architecture.ProcessorType.ARM926EJ_S" in resp_body_dict["processor"]


async def test_add_program_attributes(ofrak_client: TestClient, hello_elf):
    """
    Test adding program architecture attributes to a resource.

    This test verifies that:
    - Program attributes can be added to a resource via the API
    - All required attribute fields can be specified (ISA, bit width, endianness)
    - Optional fields (sub_isa, processor) can be set to specific values
    - Optional fields can be set to None
    - Multiple program attribute updates can be applied to the same resource
    - The add_program_attributes endpoint handles both complete and minimal configurations

    Requirements Mapping:
    - REQ2.2
    """
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_elf"}, data=hello_elf
    )
    create_body = await create_resp.json()
    resource_id = create_body["id"]
    json_program_attributes = [
        "ofrak.core.architecture.ProgramAttributes",
        {
            "isa": "ofrak_type.architecture.InstructionSet.ARM",
            "sub_isa": "ofrak_type.architecture.SubInstructionSet.ARMv6",
            "bit_width": "ofrak_type.bit_width.BitWidth.BIT_32",
            "endianness": "ofrak_type.endianness.Endianness.LITTLE_ENDIAN",
            "processor": "ofrak_type.architecture.ProcessorType.GENERIC_A9_V7",
        },
    ]
    resp = await ofrak_client.post(
        f"/{resource_id}/add_program_attributes",
        json=json_program_attributes,
    )
    assert resp.status == 200

    # also test having sub_isa and processor as null, as they are optional
    json_program_attributes_optional = [
        "ofrak.core.architecture.ProgramAttributes",
        {
            "isa": "ofrak_type.architecture.InstructionSet.ARM",
            "sub_isa": None,
            "bit_width": "ofrak_type.bit_width.BitWidth.BIT_32",
            "endianness": "ofrak_type.endianness.Endianness.LITTLE_ENDIAN",
            "processor": None,
        },
    ]
    resp = await ofrak_client.post(
        f"/{resource_id}/add_program_attributes",
        json=json_program_attributes_optional,
    )
    assert resp.status == 200
