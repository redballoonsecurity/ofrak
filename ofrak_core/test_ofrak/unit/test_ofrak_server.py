import json
import pytest

from multiprocessing import Process

from ofrak.core import File
from ofrak.core.entropy import DataSummaryAnalyzer
from ofrak.gui.server import AiohttpOFRAKServer, start_server
from ofrak.service.serialization.pjson import (
    PJSONSerializationService,
)
from test_ofrak.components.hello_world_elf import hello_elf


@pytest.fixture(scope="session")
def hello_world_elf() -> bytes:
    return hello_elf()


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


# Test server methods and top-level functions.
# Does not effect coverage because it runs in a subprocess. Could use in future to test end-to-end.
async def test_server_main(ofrak_client, ofrak_context):
    args = {"ofrak_context": ofrak_context, "host": "127.0.0.1", "port": 8080}
    proc = Process(target=start_server, kwargs=args)
    proc.start()
    resp = await ofrak_client.get("/")
    assert resp.status == 200
    proc.join(timeout=5)


async def test_error(ofrak_client):
    resp = await ofrak_client.get("/1234/")
    assert resp.status == 500


# Test calls to each of the routes set on the server, this should hit each of the callbacks
async def test_get_index(ofrak_client):
    resp = await ofrak_client.get("/")
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "text/html"


async def test_create_root_resource(ofrak_client, ofrak_server, hello_world_elf, test_resource):
    resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["id"] is not None

    serialized_resource = ofrak_server._serialize_resource(test_resource)
    json_result = json.loads(json.dumps(serialized_resource))
    assert body["tags"] == json_result["tags"]


async def test_get_root_resources(ofrak_client, ofrak_context, ofrak_server, hello_world_elf):
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


async def test_get_resource(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await ofrak_client.get(f"/{body['id']}/")
    assert resp.status == 200

    # TODO: How test directly? Package up in request and send to ofrak_server?


async def test_get_data(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.get(f"/{create_body['id']}/get_data")
    assert resp.status == 200
    resp_body = await resp.read()
    assert resp_body == hello_world_elf


async def test_unpack(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/unpack")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["created"] is not None


async def test_get_children(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    unpack_resp = await ofrak_client.post(f"/{create_body['id']}/unpack")
    children_resp = await ofrak_client.get(f"/{create_body['id']}/get_children")
    assert children_resp.status == 200
    children_body = await children_resp.json()
    assert children_body[0]["id"] is not None


async def test_get_data_range(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    unpack_resp = await ofrak_client.post(f"/{create_body['id']}/unpack")
    children_resp = await ofrak_client.get(f"/{create_body['id']}/get_children")
    children_body = await children_resp.json()
    get_data_resp = await ofrak_client.get(
        f"/{children_body[0]['id']}/get_data_range_within_parent"
    )
    get_data_resp_body = await get_data_resp.json()
    assert get_data_resp_body == [0, 16]


# Cannot find manual example to compare against
async def test_get_root(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await ofrak_client.get(f"/{body['id']}/get_root")
    assert resp.status == 200


async def test_unpack_recursively(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/unpack_recursively")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["created"] is not None


# Cannot find manual example to compare against
async def test_pack(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await ofrak_client.post(f"/{body['id']}/pack")
    assert resp.status == 200


# Cannot find manual example to compare against
async def test_pack_recursively(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await ofrak_client.post(f"/{body['id']}/pack_recursively")
    assert resp.status == 200


async def test_analyze(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/analyze")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body is not None


async def test_identify(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resp = await ofrak_client.post(f"/{create_body['id']}/identify")
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]


async def test_data_summary(ofrak_client, ofrak_server, hello_world_elf, test_resource):
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


async def test_get_parent(ofrak_client, hello_world_elf):
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


async def test_get_ancestors(ofrak_client, hello_world_elf):
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


async def test_queue_patch(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    unpack_resp = await ofrak_client.post(f"/{create_body['id']}/unpack")
    resp = await ofrak_client.post(f"/{create_body['id']}/queue_patch", data=hello_world_elf)
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["id"] == create_body["id"]


async def test_create_mapped_child(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    unpack_resp = await ofrak_client.post(f"/{create_body['id']}/unpack")
    unpack_body = await unpack_resp.json()
    resp = await ofrak_client.post(
        f"/{unpack_body['created'][0]['id']}/create_mapped_child", json=[0, 1]
    )
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["parent_id"] == unpack_body["created"][0]["id"]


# find_and_replace doesn't appear to send back any information in the response
async def test_find_and_replace(ofrak_client, hello_world_elf):
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
                "null_terminate": "true",
                "allow_overflow": "false",
            },
        ],
    )
    assert resp.status == 200


async def test_add_comment(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    resp = await client.post(f"/{create_body['id']}/add_comment", json=[[0, 425], "test"])
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]


async def test_delete_comment(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    await client.post(f"/{create_body['id']}/add_comment", json=[[0, 425], "test"])
    resp = await client.post(f"/{create_body['id']}/delete_comment", json=[0, 425])
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body["modified"][0]["id"] == create_body["id"]


async def test_search_for_vaddr(ofrak_client, hello_world_elf):
    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    await ofrak_client.post(f"/{create_body['id']}/unpack_recursively")
    resp = await ofrak_client.post(f"/{create_body['id']}/search_for_vaddr", json=[0, None])
    assert resp.status == 200
    resp_body = await resp.json()
    assert resp_body[0] is not None
