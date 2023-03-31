import itertools
import json
import pytest
import sys

from multiprocessing import Process

from aiohttp.test_utils import TestClient

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
    assert resp_body == [
        "from ofrak import *",
        "from ofrak.core import *",
        "",
        "",
        "async def main(ofrak_context: OFRAKContext):",
        "",
        "    root_resource = await ofrak_context.create_root_resource_from_file(",
        '        "hello_world_elf"',
        "    )",
        "",
        "    await root_resource.unpack()",
        "",
        "    elfbasicheader_0x0 = await root_resource.get_only_child(",
        "        r_filter=ResourceFilter(",
        "            tags={ElfBasicHeader},",
        "            attribute_filters=[",
        "                ResourceAttributeValueFilter(attribute=Data.Offset, value=0)",
        "            ],",
        "        )",
        "    )",
        "",
        "    await elfbasicheader_0x0.auto_run(all_analyzers=True)",
        "",
        "",
        'if __name__ == "__main__":',
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
        "    ofrak = OFRAK()",
        "    ofrak.run(main)",
        "",
    ]


async def test_selectable_attr_err(ofrak_client: TestClient, hello_world_elf):
    def get_child_sort_key(child):
        attrs = dict(child.get("attributes"))
        data_attr = attrs.get("ofrak.model.resource_model.Data")
        if data_attr is not None:
            return data_attr[1]["_offset"]
        else:
            return sys.maxsize

    create_resp = await ofrak_client.post(
        "/create_root_resource", params={"name": "hello_world_elf"}, data=hello_world_elf
    )
    root = await create_resp.json()
    root_id = root["id"]

    # Carving the root resource twice will result in 2 children with identical attributes, which
    # leads to a SelectableAttributesError when you attempt to unpack the second child
    await ofrak_client.post(f"/{root_id}/create_mapped_child", json=[0, 8181])

    await ofrak_client.post(f"/{root_id}/create_mapped_child", json=[0, 8181])
    children_resp = await ofrak_client.post(f"/batch/get_children", json=[root_id])
    children_body = await children_resp.json()

    child_one = children_body[root_id][0]
    child_two = children_body[root_id][1]
    child_one_res = await ofrak_client.post(f"/{child_one['id']}/unpack")
    child_two_res = await ofrak_client.post(f"/{child_two['id']}/unpack")
    child_one_body = await child_one_res.json()
    child_two_body = await child_two_res.json()
    child_one_resources = child_one_body["created"]
    child_two_resources = child_two_body["created"]
    # Must sort results of unpacking so that comparison works
    child_one_resources.sort(key=get_child_sort_key)
    child_two_resources.sort(key=get_child_sort_key)

    # Verify results of unpacking are the same for both children and are what we expect
    attrs_to_skip = {"id", "data_id", "parent_id", "attributes"}
    assert len(child_one_resources) == len(child_two_resources)
    assert all(
        list(
            map(
                dicts_are_similar,
                child_one_resources,
                child_two_resources,
                itertools.repeat(attrs_to_skip),
            )
        )
    )
    assert all(
        list(
            map(
                dicts_are_similar,
                child_two_resources,
                child_one_resources,
                itertools.repeat(attrs_to_skip),
            )
        )
    )
    assert "ofrak.core.elf.model.ElfBasicHeader" in child_one_resources[0]["tags"]

    # Verify script is as expected
    resp = await ofrak_client.get(
        f"/{root_id}/get_script",
    )
    resp_body = await resp.json()
    assert resp_body == [
        "from ofrak import *",
        "from ofrak.core import *",
        "",
        "",
        "async def main(ofrak_context: OFRAKContext):",
        "",
        "    root_resource = await ofrak_context.create_root_resource_from_file(",
        '        "hello_world_elf"',
        "    )",
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
        "    raise RuntimeError(",
        '        "Resource with ID 0x00000003 cannot be uniquely identified by attribute Data.Offset (resource has value 0)."',
        "    )",
        "",
        "    await root_resource_MISSING_RESOURCE.unpack()",
        "",
        "    # Resource with parent root_resource is missing, could not find selectable attributes.",
        "    raise RuntimeError(",
        '        "Resource with ID 0x00000004 cannot be uniquely identified by attribute Data.Offset (resource has value 0)."',
        "    )",
        "",
        "    await root_resource_MISSING_RESOURCE.unpack()",
        "",
        "",
        'if __name__ == "__main__":',
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
        "    ofrak = OFRAK()",
        "    ofrak.run(main)",
        "",
    ]
