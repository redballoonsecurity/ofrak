# import pdb
import pytest


from ofrak.gui.server import AiohttpOFRAKServer
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
    # This is an OFRAK instance, not a server. Create a server instance specifically?
    ofrak = ofrak
    # ofrak.run(server.main, "127.0.0.1", 8080)

    ofrak.injector.bind_factory(PJSONSerializationService)

    ofrak.injector.bind_factory(
        AiohttpOFRAKServer,
        ofrak_context=ofrak_context,
        host="127.0.0.1",
        port=8080,
    )
    server = await ofrak.injector.get_instance(AiohttpOFRAKServer)
    return server


# Test server methods (run, start, etc.)

# Test calls to each of the routes set on the server, this should hit each of the callbacks
async def test_get_root(ofrak_server, aiohttp_client):
    client = await aiohttp_client(ofrak_server._app)
    resp = await client.get("/")
    assert resp.status == 200


async def test_get_root_resources(ofrak_server, aiohttp_client):
    client = await aiohttp_client(ofrak_server._app)
    resp = await client.get("/get_root_resources")
    assert resp.status == 200


async def test_create_root_resource(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    # pdb.set_trace()
    resp = await client.post("/create_root_resource", params={"name": "test"}, data=hello_world_elf)
    assert resp.status == 200


async def test_get_resource(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.get(f"/{body['id']}/")
    assert resp.status == 200


async def test_get_data(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.get(f"/{body['id']}/get_data")
    assert resp.status == 200


async def test_get_data_range(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.get(f"/{body['id']}/get_data_range_within_parent")
    assert resp.status == 200


async def test_get_root(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.get(f"/{body['id']}/get_root")
    assert resp.status == 200


async def test_unpack(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.post(f"/{body['id']}/unpack")
    assert resp.status == 200


async def test_unpack_recursively(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.post(f"/{body['id']}/unpack_recursively")
    assert resp.status == 200


async def test_pack(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.post(f"/{body['id']}/pack")
    assert resp.status == 200


async def test_pack_recursively(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.post(f"/{body['id']}/pack_recursively")
    assert resp.status == 200


async def test_analyze(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.post(f"/{body['id']}/analyze")
    assert resp.status == 200


async def test_identify(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.post(f"/{body['id']}/identify")
    assert resp.status == 200


async def test_data_summary(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.post(f"/{body['id']}/data_summary")
    assert resp.status == 200


async def test_get_parent(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    create_body = await create_resp.json()
    unpack_resp = await client.post(f"/{create_body['id']}/unpack")
    unpack_body = await unpack_resp.json()
    resp = await client.get(f"/{unpack_body['created'][0]['id']}/get_parent")
    assert resp.status == 200


async def test_get_ancestors(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.get(f"/{body['id']}/get_ancestors")
    assert resp.status == 200


async def test_get_children(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.get(f"/{body['id']}/get_children")
    assert resp.status == 200


async def test_queue_patch(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.post(f"/{body['id']}/queue_patch")
    assert resp.status == 200


async def test_create_mapped_child(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.post(f"/{body['id']}/create_mapped_child", json=[0, 16])
    assert resp.status == 200


async def test_find_and_replace(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.post(
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
    body = await create_resp.json()
    resp = await client.post(f"/{body['id']}/add_comment", json=[[10, 20], "test"])
    assert resp.status == 200


async def test_delete_comment(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    await client.post(f"/{body['id']}/add_comment", json=[[10, 20], "test"])
    resp = await client.post(f"/{body['id']}/delete_comment", json=[10, 20])
    assert resp.status == 200


async def test_search_for_vaddr(ofrak_server, aiohttp_client, hello_world_elf):
    client = await aiohttp_client(ofrak_server._app)
    create_resp = await client.post(
        "/create_root_resource", params={"name": "test"}, data=hello_world_elf
    )
    body = await create_resp.json()
    resp = await client.post(f"/{body['id']}/search_for_vaddr", json=[16, 20])
    assert resp.status == 200
