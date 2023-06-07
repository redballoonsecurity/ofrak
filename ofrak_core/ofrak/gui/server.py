import asyncio
import dataclasses
from enum import Enum
import functools
import itertools
import logging

import typing_inspect
from typing_inspect import get_args
import json
import orjson
import inspect
import os
import sys
import webbrowser
from collections import defaultdict
from typing import (
    Iterable,
    Optional,
    Dict,
    cast,
    Set,
    Tuple,
    Union,
    Type,
    Callable,
    TypeVar,
    Any,
    List,
)

from aiohttp import web
from aiohttp.web_exceptions import HTTPBadRequest
from aiohttp.web_request import Request
from aiohttp.web_response import Response
from aiohttp.web_fileresponse import FileResponse
from dataclasses import fields

from ofrak.component.interface import ComponentInterface
from ofrak.model.component_filters import (
    ComponentOrMetaFilter,
    ComponentTypeFilter,
    ComponentTargetFilter,
    ComponentAndMetaFilter,
)
from ofrak.ofrak_context import get_current_ofrak_context
from ofrak.service.component_locator_i import ComponentFilter
from ofrak_patch_maker.toolchain.abstract import Toolchain
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range
from ofrak import (
    OFRAKContext,
    ResourceFilter,
    ResourceAttributeRangeFilter,
    ResourceAttributeValueFilter,
    ResourceSort,
    ResourceTag,
    Packer,
    Unpacker,
    Modifier,
    Analyzer,
)
from ofrak.core import Addressable, File
from ofrak.core import (
    GenericBinary,
    AddCommentModifier,
    AddCommentModifierConfig,
    DeleteCommentModifierConfig,
    DeleteCommentModifier,
    StringFindReplaceConfig,
    StringFindReplaceModifier,
)
from ofrak.model.component_model import (
    ComponentContext,
    ClientComponentContext,
    ComponentRunResult,
    ComponentConfig,
)
from ofrak.model.resource_model import (
    ResourceContext,
    ClientResourceContext,
    ResourceModel,
    ResourceAttributes,
    MutableResourceModel,
)
from ofrak.model.viewable_tag_model import ResourceViewContext
from ofrak.resource import Resource
from ofrak.service.error import SerializedError
from ofrak.service.serialization.pjson import (
    SerializationServiceInterface,
    PJSONSerializationService,
)
from ofrak.gui.script_builder import ActionType, ScriptBuilder
from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.core.entropy import DataSummaryAnalyzer

T = TypeVar("T")
LOGGER = logging.getLogger(__name__)


def exceptions_to_http(error_class: Type[SerializedError]):
    """
    Decorator for a server function that attempts to do some work, and
    forwards the exception, if any, to the client over HTTP.

    Usage:

    @exceptions_to_http(MyErrorClass)
    async def handle_some_request(self, request...):
        ...
    """

    def exceptions_to_http_decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as error:
                LOGGER.exception("Exception raised in aiohttp endpoint")
                return respond_with_error(error, error_class)

        return wrapper

    return exceptions_to_http_decorator


class AiohttpOFRAKServer:
    routes = web.RouteTableDef()

    def __init__(
        self,
        serializer: SerializationServiceInterface,
        ofrak_context: OFRAKContext,
        host: str,
        port: int,
        enable_cors: bool = False,
    ):
        self._serializer = serializer
        self._app = web.Application(client_max_size=None)  # type: ignore
        self._host = host
        self._port = port
        self._ofrak_context = ofrak_context
        self.resource_context: ResourceContext = ClientResourceContext()
        self.resource_view_context: ResourceViewContext = ResourceViewContext()
        self.component_context: ComponentContext = ClientComponentContext()
        self.script_builder: ScriptBuilder = ScriptBuilder()
        self._app.add_routes(
            [
                web.post("/create_root_resource", self.create_root_resource),
                web.get("/get_root_resources", self.get_root_resources),
                web.get("/{resource_id}/", self.get_resource),
                web.get("/{resource_id}/get_data", self.get_data),
                web.get("/{resource_id}/get_data_length", self.get_data_length),
                web.post(
                    "/batch/get_data_range_within_parent",
                    self.batch_get_range,
                ),
                web.get(
                    "/{resource_id}/get_child_data_ranges",
                    self.get_child_data_ranges,
                ),
                web.get("/{resource_id}/get_root", self.get_root_resource_from_child),
                web.post("/{resource_id}/unpack", self.unpack),
                web.post("/{resource_id}/unpack_recursively", self.unpack_recursively),
                web.post("/{resource_id}/pack", self.pack),
                web.post("/{resource_id}/pack_recursively", self.pack_recursively),
                web.post("/{resource_id}/analyze", self.analyze),
                web.post("/{resource_id}/identify", self.identify),
                web.post("/{resource_id}/data_summary", self.data_summary),
                web.get("/{resource_id}/get_parent", self.get_parent),
                web.get("/{resource_id}/get_ancestors", self.get_ancestors),
                web.get("/{resource_id}/get_descendants", self.get_descendants),
                web.post("/batch/get_children", self.batch_get_children),
                web.post("/{resource_id}/queue_patch", self.queue_patch),
                web.post("/{resource_id}/create_mapped_child", self.create_mapped_child),
                web.post("/{resource_id}/find_and_replace", self.find_and_replace),
                web.post("/{resource_id}/add_comment", self.add_comment),
                web.post("/{resource_id}/delete_comment", self.delete_comment),
                web.post("/{resource_id}/search_for_vaddr", self.search_for_vaddr),
                web.post("/{resource_id}/add_tag", self.add_tag),
                web.post(
                    "/{resource_id}/add_flush_to_disk_to_script", self.add_flush_to_disk_to_script
                ),
                web.get("/get_all_tags", self.get_all_tags),
                web.get("/{resource_id}/get_script", self.get_script),
                web.post(
                    "/{resource_id}/get_components",
                    self.get_components,
                ),
                web.get("/{resource_id}/get_config_for_component", self.get_config_for_component),
                web.post("/{resource_id}/run_component", self.run_component),
                web.post(
                    "/{resource_id}/get_tags_and_num_components", self.get_tags_and_num_components
                ),
                web.get("/", self.get_static_files),
                web.static(
                    "/",
                    os.path.join(os.path.dirname(__file__), "./public"),
                    show_index=True,
                ),
            ]
        )

        self._job_ids: Dict[str, bytes] = defaultdict(
            lambda: ofrak_context.id_service.generate_id()
        )
        self._all_tags: Dict[str, ResourceTag] = {tag.__name__: tag for tag in ResourceTag.all_tags}

        if enable_cors:
            try:
                import aiohttp_cors  # type: ignore

                # From: https://github.com/aio-libs/aiohttp-cors
                # Configure default CORS settings.
                cors = aiohttp_cors.setup(
                    self._app,
                    defaults={
                        "*": aiohttp_cors.ResourceOptions(
                            allow_credentials=True,
                            expose_headers="*",
                            allow_headers="*",
                        )
                    },
                )

                # Configure CORS on all routes.
                for route in list(self._app.router.routes()):
                    cors.add(route)
            except ImportError:
                LOGGER.warning(
                    "Unable to enable CORS. Please confirm that aiohttp_cors is installed."
                )

    async def start(self):  # pragma: no cover
        """
        Start the server then return.
        """
        self.runner = web.AppRunner(self._app)
        await self.runner.setup()
        server = web.TCPSite(self.runner, host=self._host, port=self._port)
        await server.start()

    async def stop(self):  # pragma: no cover
        """
        Stop the server.
        """
        await self.runner.server.shutdown()
        await self.runner.cleanup()

    async def run_until_cancelled(self):  # pragma: no cover
        """
        To be run after `start_server`, within an asyncio Task.
        cancel() that task to shutdown the server.
        """
        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await self.runner.cleanup()

    @exceptions_to_http(SerializedError)
    async def create_root_resource(self, request: Request) -> Response:
        name = request.query.get("name")
        if name is None:
            return HTTPBadRequest(reason="Missing root resource `name` from request")
        resource_data = await request.read()
        script_str = rf"""
        if root_resource is None:
            root_resource = await ofrak_context.create_root_resource_from_file("{name}")"""
        try:
            root_resource = await self._ofrak_context.create_root_resource(
                name, resource_data, (File,)
            )
            await self.script_builder.add_action(root_resource, script_str, ActionType.UNPACK)
            if request.remote is not None:
                self._job_ids[request.remote] = root_resource.get_job_id()
            await self.script_builder.commit_to_script(root_resource)
        except Exception as e:
            await self.script_builder.clear_script_queue(root_resource)
            raise e
        return json_response(self._serialize_resource(root_resource))

    @exceptions_to_http(SerializedError)
    async def get_root_resources(self, request: Request) -> Response:
        roots = await self._ofrak_context.resource_service.get_root_resources()

        return json_response(list(map(self._serialize_resource_model, roots)))

    @exceptions_to_http(SerializedError)
    async def get_resource(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        return json_response(self._serialize_resource(resource))

    @exceptions_to_http(SerializedError)
    async def get_data(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        _range = self._serializer.from_pjson(
            get_query_string_as_pjson(request).get("range"), Optional[Range]
        )
        data = await resource.get_data(_range)
        return Response(body=data)

    @exceptions_to_http(SerializedError)
    async def get_data_length(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        data_len = await resource.get_data_length()
        return json_response(data_len)

    @exceptions_to_http(SerializedError)
    async def get_child_data_ranges(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        resource_service = self._ofrak_context.resource_factory._resource_service
        data_service = self._ofrak_context.resource_factory._data_service
        children = await resource_service.get_descendants_by_id(
            resource.get_id(),
            max_depth=1,
        )

        async def get_range(child):
            try:
                if child.data_id is None:
                    return
                data_range = await data_service.get_range_within_other(
                    child.data_id, resource.get_data_id()
                )
                return child.id.hex(), (data_range.start, data_range.end)
            except ValueError:
                pass

        return json_response(
            dict(filter(lambda x: x is not None, await asyncio.gather(*map(get_range, children))))
        )

    @exceptions_to_http(SerializedError)
    async def batch_get_range(self, request: Request) -> Response:
        if request.remote is not None:
            job_id = self._job_ids[request.remote]
        else:
            raise ValueError("No IP address found for the remote request!")

        async def get_resource_range(resource_id):
            resource_model = await self._get_resource_model_by_id(
                bytes.fromhex(resource_id), job_id
            )
            if resource_model.data_id is None:
                raise ValueError(
                    "Resource does not have a data_id. Cannot get data range from a "
                    "resource with no data."
                )
            if resource_model.parent_id is None:
                data_range = Range(0, 0)
            else:
                resource_service = self._ofrak_context.resource_factory._resource_service
                data_service = self._ofrak_context.resource_factory._data_service
                parent_models = list(
                    await resource_service.get_ancestors_by_id(resource_model.id, max_count=1)
                )
                if len(parent_models) != 1:
                    raise NotFoundError(
                        f"There is no parent for resource {resource_model.id.hex()}"
                    )
                parent_model = parent_models[0]

                parent_data_id = parent_model.data_id
                if parent_data_id is None:
                    data_range = Range(0, 0)
                else:
                    try:
                        data_range = await data_service.get_range_within_other(
                            resource_model.data_id, parent_data_id
                        )
                    except ValueError:
                        data_range = Range(0, 0)
            return resource_id, [data_range.start, data_range.end]

        return json_response(
            dict(await asyncio.gather(*map(get_resource_range, await request.json())))
        )

    @exceptions_to_http(SerializedError)
    async def unpack(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        script_str = """
        await {resource}.unpack()"""
        await self.script_builder.add_action(resource, script_str, ActionType.UNPACK)
        try:
            result = await resource.unpack()
            await self.script_builder.commit_to_script(resource)
        except Exception as e:
            await self.script_builder.clear_script_queue(resource)
            raise e
        return json_response(await self._serialize_component_result(result))

    @exceptions_to_http(SerializedError)
    async def unpack_recursively(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        script_str = """
        await {resource}.unpack_recursively()"""
        await self.script_builder.add_action(resource, script_str, ActionType.UNPACK)
        try:
            result = await resource.unpack_recursively()
            await self.script_builder.commit_to_script(resource)
        except Exception as e:
            await self.script_builder.clear_script_queue(resource)
            raise e
        return json_response(await self._serialize_component_result(result))

    @exceptions_to_http(SerializedError)
    async def pack(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        script_str = """
        await {resource}.pack()"""
        await self.script_builder.add_action(resource, script_str, ActionType.PACK)
        try:
            result = await resource.pack()
            await self.script_builder.commit_to_script(resource)
        except Exception as e:
            await self.script_builder.clear_script_queue(resource)
            raise e
        return json_response(await self._serialize_component_result(result))

    @exceptions_to_http(SerializedError)
    async def pack_recursively(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        script_str = """
        await {resource}.pack_recursively()"""
        await self.script_builder.add_action(resource, script_str, ActionType.PACK)
        try:
            result = await resource.pack_recursively()
            await self.script_builder.commit_to_script(resource)
        except Exception as e:
            await self.script_builder.clear_script_queue(resource)
            raise e
        return json_response(await self._serialize_component_result(result))

    @exceptions_to_http(SerializedError)
    async def identify(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        script_str = """
        await {resource}.identify()"""
        await self.script_builder.add_action(resource, script_str, ActionType.MOD)
        try:
            result = await resource.identify()
            await self.script_builder.commit_to_script(resource)
        except Exception as e:
            await self.script_builder.clear_script_queue(resource)
            raise e
        return json_response(await self._serialize_component_result(result))

    @exceptions_to_http(SerializedError)
    async def data_summary(self, request: Request) -> Response:
        resource = cast(Resource, await self._get_resource_for_request(request))
        result = await resource.run(DataSummaryAnalyzer)

        return json_response(await self._serialize_component_result(result))

    @exceptions_to_http(SerializedError)
    async def analyze(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        script_str = """
        await {resource}.auto_run(all_analyzers=True)"""
        await self.script_builder.add_action(resource, script_str, ActionType.MOD)
        try:
            result = await resource.auto_run(all_analyzers=True)
            await self.script_builder.commit_to_script(resource)
        except Exception as e:
            await self.script_builder.clear_script_queue(resource)
            raise e
        return json_response(await self._serialize_component_result(result))

    @exceptions_to_http(SerializedError)
    async def get_parent(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        parent = await resource.get_parent()

        return json_response(self._serialize_resource(parent))

    @exceptions_to_http(SerializedError)
    async def get_ancestors(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        ancestors = await resource.get_ancestors()

        return json_response(self._serialize_multi_resource(ancestors))

    @exceptions_to_http(SerializedError)
    async def get_descendants(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        descendants = await resource.get_descendants()

        return json_response(self._serialize_multi_resource(descendants))

    @exceptions_to_http(SerializedError)
    async def batch_get_children(self, request: Request) -> Response:
        if request.remote is not None:
            job_id = self._job_ids[request.remote]
        else:
            raise ValueError("No IP address found for the remote request!")

        async def get_resource_children(resource_id):
            resource = await self._get_resource_by_id(bytes.fromhex(resource_id), job_id)
            child_models = await resource._resource_service.get_descendants_by_id(
                resource._resource.id,
                max_depth=1,
            )
            serialized_children = list(map(self._serialize_resource_model, child_models))
            serialized_children.sort(key=get_child_sort_key)

            return resource_id, serialized_children

        def get_child_sort_key(child):
            attrs = dict(child.get("attributes"))
            data_attr = attrs.get("ofrak.model.resource_model.Data")
            if data_attr is not None:
                return data_attr[1]["_offset"]
            else:
                return sys.maxsize

        return json_response(
            dict(await asyncio.gather(*map(get_resource_children, await request.json())))
        )

    @exceptions_to_http(SerializedError)
    async def get_root_resource_from_child(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        parent = resource
        try:
            # Assume get_ancestors returns an ordered list with the parent first and the root last
            for parent in await resource.get_ancestors():
                pass
        except NotFoundError:
            pass

        return json_response(self._serialize_resource(parent))

    @exceptions_to_http(SerializedError)
    async def queue_patch(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        new_data = await request.read()

        start_param = request.query.get("start")
        start = int(start_param) if start_param is not None else 0
        end_param = request.query.get("end")
        end = int(end_param) if end_param is not None else (await resource.get_data_length())
        # TODO: There has to be a better way
        new_data_string = "\\x" + "\\x".join(
            [new_data.hex()[i : i + 2] for i in range(0, len(new_data.hex()), 2)]
        )
        script_str = (
            """
        {resource}.queue_patch"""
            f"""(Range({hex(start)}, {hex(end)}), b"{new_data_string}")"""
        )
        await self.script_builder.add_action(resource, script_str, ActionType.MOD)
        script_str = """
        await {resource}.save()"""
        await self.script_builder.add_action(resource, script_str, ActionType.MOD)
        try:
            resource.queue_patch(Range(start, end), new_data)
            await resource.save()
            await self.script_builder.commit_to_script(resource)
        except Exception as e:
            await self.script_builder.clear_script_queue(resource)
            raise e
        return json_response(self._serialize_resource(resource))

    @exceptions_to_http(SerializedError)
    async def create_mapped_child(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        _range = self._serializer.from_pjson(await request.json(), Optional[Range])
        script_str = (
            """
        await {resource}"""
            f""".create_child(tags=(GenericBinary,), data_range={_range})
        """
        )
        await self.script_builder.add_action(resource, script_str, ActionType.MOD)
        try:
            child = await resource.create_child(tags=(GenericBinary,), data_range=_range)
            await self.script_builder.commit_to_script(resource)
        except Exception as e:
            await self.script_builder.clear_script_queue(resource)
            raise e
        return json_response(self._serialize_resource(child))

    @exceptions_to_http(SerializedError)
    async def find_and_replace(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        config = self._serializer.from_pjson(await request.json(), StringFindReplaceConfig)
        script_str = f"""
        config = StringFindReplaceConfig(
            to_find="{config.to_find}", 
            replace_with="{config.replace_with}", 
            null_terminate={config.null_terminate}, 
            allow_overflow={config.allow_overflow}
        )"""
        await self.script_builder.add_action(resource, script_str, ActionType.MOD)
        script_str = """
        await {resource}.run(StringFindReplaceModifier, config)"""
        await self.script_builder.add_action(resource, script_str, ActionType.MOD)
        try:
            result = await resource.run(StringFindReplaceModifier, config=config)
            await self.script_builder.commit_to_script(resource)
            return json_response(await self._serialize_component_result(result))
        except Exception as e:
            await self.script_builder.clear_script_queue(resource)
            raise e

    async def add_comment(self, request: Request) -> Response:
        """
        Expected POST body is a comment in the form Tuple[Optional[Range], str] (serialized to JSON).
        """
        resource = await self._get_resource_for_request(request)
        comment = self._serializer.from_pjson(await request.json(), Tuple[Optional[Range], str])
        script_str = (
            """
        await {resource}.run"""
            f"""(AddCommentModifier, AddCommentModifierConfig({comment}))
        """
        )
        await self.script_builder.add_action(resource, script_str, ActionType.MOD)
        try:
            result = await resource.run(AddCommentModifier, AddCommentModifierConfig(comment))
            await self.script_builder.commit_to_script(resource)
        except Exception as e:
            await self.script_builder.clear_script_queue(resource)
            raise e
        return json_response(await self._serialize_component_result(result))

    @exceptions_to_http(SerializedError)
    async def delete_comment(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        comment_range = self._serializer.from_pjson(await request.json(), Optional[Range])
        script_str = (
            """
        await {resource}.run"""
            f"""(
            DeleteCommentModifier, DeleteCommentModifierConfig({comment_range})
        )"""
        )
        await self.script_builder.add_action(resource, script_str, ActionType.MOD)
        try:
            result = await resource.run(
                DeleteCommentModifier, DeleteCommentModifierConfig(comment_range)
            )
            await self.script_builder.commit_to_script(resource)
        except Exception as e:
            await self.script_builder.clear_script_queue(resource)
            raise e
        return json_response(await self._serialize_component_result(result))

    @exceptions_to_http(SerializedError)
    async def search_for_vaddr(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        vaddr_start, vaddr_end = self._serializer.from_pjson(
            await request.json(), Tuple[int, Optional[int]]
        )

        try:
            vaddr_filter: Union[ResourceAttributeRangeFilter, ResourceAttributeValueFilter]
            if vaddr_end is not None:
                vaddr_filter = ResourceAttributeRangeFilter(
                    Addressable.VirtualAddress, vaddr_start, vaddr_end
                )
            else:
                vaddr_filter = ResourceAttributeValueFilter(Addressable.VirtualAddress, vaddr_start)
            matching_resources = await resource.get_descendants(
                r_filter=ResourceFilter(attribute_filters=(vaddr_filter,)),
                r_sort=ResourceSort(Addressable.VirtualAddress),
            )

            return json_response(list(map(self._serialize_resource, matching_resources)))

        except NotFoundError:
            return json_response([])

    @exceptions_to_http(SerializedError)
    async def add_tag(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        tag = self._serializer.from_pjson(await request.json(), ResourceTag)
        script_str = (
            """
        {resource}.add_tag"""
            f"""({tag.__name__})"""
        )
        await self.script_builder.add_action(resource, script_str, ActionType.MOD)
        script_str = """
        await {resource}.save()"""
        await self.script_builder.add_action(resource, script_str, ActionType.MOD)
        try:
            resource.add_tag(tag)
            await resource.save()
            await self.script_builder.commit_to_script(resource)
        except Exception as e:
            await self.script_builder.clear_script_queue(resource)
            raise e
        return json_response(self._serialize_resource(resource))

    @exceptions_to_http(SerializedError)
    async def get_all_tags(self, request: Request) -> Response:
        return json_response(
            self._serializer.to_pjson(set(self._all_tags.values()), Set[ResourceTag])
        )

    @exceptions_to_http(SerializedError)
    async def add_flush_to_disk_to_script(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        output_file_name = self._serializer.from_pjson(await request.json(), str)
        # Use FilesystemEntry name as filename if available, otherwise generate random filename
        if not output_file_name:
            output_file_name = self._ofrak_context.id_service.generate_id().hex()
        script_str = (
            """
        await {resource}"""
            f""".flush_to_disk("{output_file_name}")"""
        )
        await self.script_builder.add_action(resource, script_str, ActionType.UNDEF)
        await self.script_builder.commit_to_script(resource)
        return json_response(self._serialize_resource(resource))

    @exceptions_to_http(SerializedError)
    async def get_script(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        return json_response(await self.script_builder.get_script(resource))

    @exceptions_to_http(SerializedError)
    async def get_components(self, request: Request) -> Response:
        resource: Resource = await self._get_resource_for_request(request)
        options = await request.json()
        show_all_components = options["show_all_components"]
        target_filter = options["target_filter"]
        incl_analyzers = options["analyzers"]
        incl_modifiers = options["modifiers"]
        incl_packers = options["packers"]
        incl_unpackers = options["unpackers"]
        components = self._get_specific_components(
            resource,
            show_all_components,
            target_filter,
            incl_analyzers,
            incl_modifiers,
            incl_packers,
            incl_unpackers,
        )
        return json_response(self._serializer.to_pjson(components, Set[str]))

    @exceptions_to_http(SerializedError)
    async def get_config_for_component(self, request: Request) -> Response:
        component_string = request.query.get("component")
        if component_string is not None:
            component = self._ofrak_context.component_locator.get_by_id(
                component_string.encode("ascii")
            )
            config = self._get_config_for_component(type(component))
        else:
            return json_response([])
        if (
            not config == inspect._empty
            and not type(config) == type(None)
            and not typing_inspect.is_optional_type(config)
        ):
            _fields = []
            for field in fields(config):
                field.type = self._modify_by_case(field.type)
                if isinstance(field.default, dataclasses._MISSING_TYPE):
                    field.default = None
                _fields.append(
                    {
                        "name": field.name,
                        "type": self._convert_to_class_name_str(field.type),
                        "args": self._construct_arg_response(field.type),
                        "fields": self._construct_field_response(field.type),
                        "enum": self._construct_enum_response(field.type),
                        "default": field.default
                        if not isinstance(field.default, dataclasses._MISSING_TYPE)
                        else None,
                    }
                )
            return json_response(
                {
                    "name": config.__name__,
                    "type": self._convert_to_class_name_str(config),
                    "args": self._construct_arg_response(self._convert_to_class_name_str(config)),
                    "enum": self._construct_enum_response(config),
                    "fields": _fields,
                }
            )
        else:
            return json_response([])

    @exceptions_to_http(SerializedError)
    async def run_component(self, request: Request) -> Response:
        resource: Resource = await self._get_resource_for_request(request)
        component_string = request.query.get("component")
        if component_string is not None:
            component = type(
                self._ofrak_context.component_locator.get_by_id(component_string.encode("ascii"))
            )
            config_type = self._get_config_for_component(component)
        else:
            return json_response([])
        if config_type == inspect._empty:
            config = None
        else:
            config = self._serializer.from_pjson(await request.json(), config_type)

        config_str = str(config).replace("{", "{{").replace("}", "}}")
        script_str = (
            """
        await {resource}"""
            f""".run({request.query.get("component")}, {config_str})"""
        )
        await self.script_builder.add_action(resource, script_str, ActionType.MOD)
        try:
            result = await resource.run(component, config)
            await self.script_builder.commit_to_script(resource)
        except Exception as e:
            await self.script_builder.clear_script_queue(resource)
            raise e
        return json_response(await self._serialize_component_result(result))

    @exceptions_to_http(SerializedError)
    async def get_static_files(self, request: Request) -> FileResponse:
        return FileResponse(os.path.join(os.path.dirname(__file__), "./public/index.html"))

    @exceptions_to_http(SerializedError)
    async def get_tags_and_num_components(self, request: Request):
        resource = await self._get_resource_for_request(request)
        options = await request.json()
        only_target = options["target"]
        incl_analyzers = options["analyzers"]
        incl_modifiers = options["modifiers"]
        incl_packers = options["packers"]
        incl_unpackers = options["unpackers"]
        all_resource_tags: Set[Tuple[str, int]] = set()
        for specific_tag in resource.get_most_specific_tags():
            for tag in specific_tag.tag_classes():
                components = self._get_specific_components(
                    resource,
                    only_target,
                    tag.__qualname__,
                    incl_analyzers,
                    incl_modifiers,
                    incl_packers,
                    incl_unpackers,
                )
                all_resource_tags.add((tag.__qualname__, len(components)))
        all_resource_tags_l: List[Tuple[str, int]] = list(all_resource_tags)
        for resource_tag in all_resource_tags_l:
            if "object" in resource_tag:
                all_resource_tags_l.remove(resource_tag)
        return json_response(all_resource_tags_l)

    def _construct_field_response(self, obj):
        if dataclasses.is_dataclass(obj):
            res = []
            for field in fields(obj):
                if field.init:
                    field.type = self._modify_by_case(field.type)
                    res.append(
                        {
                            "name": field.name,
                            "type": self._convert_to_class_name_str(field.type),
                            "args": self._construct_arg_response(field.type),
                            "fields": self._construct_field_response(field.type),
                            "enum": self._construct_enum_response(field.type),
                            "default": field.default
                            if not isinstance(field.default, dataclasses._MISSING_TYPE)
                            else None,
                        }
                    )
            return res
        else:
            return None

    def _construct_arg_response(self, obj):
        args = get_args(obj)
        if len(args) != 0:
            res = []
            for arg in args:
                arg = self._modify_by_case(arg)
                res.append(
                    {
                        "name": None,
                        "type": self._convert_to_class_name_str(arg),
                        "args": self._construct_arg_response(arg),
                        "fields": self._construct_field_response(arg),
                        "enum": self._construct_enum_response(arg),
                        "default": None,
                    }
                )
            return res
        else:
            return None

    def _modify_by_case(self, obj):
        args = get_args(obj)
        if self._has_elipsis(obj):
            if len(args) == 2:
                other_arg = [arg for arg in args if not isinstance(arg, type(...))][0]
                obj = List[other_arg]
            else:
                raise AttributeError("Unexpected type format with elipsis")
        return obj

    def _construct_enum_response(self, obj):
        if obj == Type[Toolchain]:
            return {
                tc.__name__: f"{tc.__module__}.{tc.__qualname__}"
                for tc in Toolchain.toolchain_implementations
                if not inspect.isabstract(tc)
            }
        if not inspect.isclass(obj):
            return None
        elif not issubclass(obj, Enum):
            return None
        else:
            return {name: value.value for name, value in obj.__members__.items()}

    def _has_elipsis(self, obj):
        return any([isinstance(arg, type(...)) for arg in get_args(obj)])

    def _convert_to_class_name_str(self, obj: Any):
        if hasattr(obj, "__qualname__") and hasattr(obj, "__module__"):
            return f"{obj.__module__}.{obj.__qualname__}"
        else:
            if obj in {bool, str, bytes, int}:
                return f"builtins.{obj.__name__}"
            elif typing_inspect.is_optional_type(obj):
                return "typing.Optional"
            elif typing_inspect.is_union_type(obj):
                return "typing.Union"
            elif obj is Range:
                return "ofrak_type.range.Range"
            elif hasattr(obj, "__origin__"):
                origin = obj.__origin__
                if origin is list:
                    return "typing.List"
                elif origin is Iterable.__origin__:  # type: ignore
                    return "typing.Iterable"
                elif origin is tuple:
                    return "typing.Tuple"
                elif origin is dict:
                    return "typing.Dict"
            else:
                return repr(obj).split("[")[0]

    async def _get_resource_by_id(self, resource_id: bytes, job_id: bytes) -> Resource:
        resource = await self._ofrak_context.resource_factory.create(
            job_id,
            resource_id,
            self.resource_context,
            self.resource_view_context,
            self.component_context,
        )
        return resource

    def _get_specific_components(
        self,
        resource: Resource,
        show_all_components: bool,
        target_filter: Optional[str],
        incl_analyzers: bool,
        incl_modifiers: bool,
        incl_packers: bool,
        incl_unpackers: bool,
    ) -> List[str]:
        selected_components = []
        tags = resource.get_tags()
        if show_all_components and len(set(tags)) == 0:
            return []

        requested_components = [incl_analyzers, incl_modifiers, incl_packers, incl_unpackers]
        categories: Tuple[Type[ComponentInterface], ...] = (Analyzer, Modifier, Packer, Unpacker)
        if any(requested_components):
            categories = tuple(itertools.compress(categories, requested_components))

        component_filters: List[ComponentFilter] = [
            ComponentOrMetaFilter(*(ComponentTypeFilter(cat) for cat in categories)),
        ]
        if not show_all_components:
            component_filters.append(ComponentTargetFilter(*tags))
            if target_filter is not None:
                component_filters.append(ComponentTargetFilter(self._all_tags[target_filter]))

        for component in self._ofrak_context.component_locator.get_components_matching_filter(
            ComponentAndMetaFilter(*component_filters)
        ):
            if type(component).__name__ != component.get_id().decode("ascii"):
                # TODO: The server lookups for these components won't work yet
                continue
            if type(component).__name__ == "AngrAnalyzer":
                # TODO: The config for this includes some angr types and can't be serialized
                continue
            selected_components.append(type(component).__name__)

        return selected_components

    def _get_config_for_component(
        self, component: Type[ComponentInterface]
    ) -> Type[ComponentConfig]:
        if issubclass(component, Packer):
            config = inspect.signature(component.pack).parameters["config"].annotation
        elif issubclass(component, Unpacker):
            config = inspect.signature(component.unpack).parameters["config"].annotation
        elif issubclass(component, Modifier):
            config = inspect.signature(component.modify).parameters["config"].annotation
        elif issubclass(component, Analyzer):
            config = inspect.signature(component.analyze).parameters["config"].annotation
        else:
            raise ValueError("{component} can not be run from the web API.")
        if hasattr(config, "_name"):
            if config._name == "Optional":
                config = [conf for conf in get_args(config) if conf is not None][0]
        return config

    async def _get_resource_model_by_id(
        self, resource_id: bytes, job_id: bytes
    ) -> Optional[Union[ResourceModel, MutableResourceModel]]:
        resource_m: Optional[Union[ResourceModel, MutableResourceModel]] = None
        resource_m = self.resource_context.resource_models.get(resource_id)
        if resource_m is None:
            resource_m = await self._ofrak_context.resource_factory._resource_service.get_by_id(
                resource_id
            )
        return resource_m

    async def _serialize_component_result(self, result: ComponentRunResult) -> PJSONType:
        async def get_and_serialize(resource_id) -> PJSONType:
            resource_model = await self._ofrak_context.resource_service.get_by_id(resource_id)
            return self._serialize_resource_model(resource_model)

        serialized_result = {
            "created": await asyncio.gather(*map(get_and_serialize, result.resources_created)),
            "modified": await asyncio.gather(
                *map(
                    get_and_serialize,
                    result.resources_modified.difference(result.resources_created).difference(
                        result.resources_deleted
                    ),
                )
            ),
            "deleted": self._serializer.to_pjson(result.resources_deleted, Set[bytes]),
        }
        return serialized_result

    async def _get_resource_for_request(self, request: Request) -> Resource:
        resource_id = pluck_id(request, "resource_id")
        if request.remote is not None:
            job_id = self._job_ids[request.remote]
        else:
            raise ValueError("No IP address found for the remote request!")
        return await self._get_resource_by_id(resource_id, job_id)

    def _serialize_resource_model(self, resource_model: ResourceModel) -> PJSONType:
        """
        Serialize the resource model, stripped of information irrelevant to the frontend.
        """
        result = {
            "id": resource_model.id.hex(),
            "data_id": resource_model.data_id.hex() if resource_model.data_id else None,
            "parent_id": resource_model.parent_id.hex() if resource_model.parent_id else None,
            "tags": [tag.__module__ + "." + tag.__qualname__ for tag in resource_model.tags],
            "attributes": self._serializer.to_pjson(
                resource_model.attributes, Dict[Type[ResourceAttributes], ResourceAttributes]
            ),
            "caption": resource_model.caption,
        }
        return result

    def _serialize_resource(self, resource: Resource) -> PJSONType:
        """
        Serialize the resource as a serialized model, stripped of information irrelevant to the
        frontend.
        """
        return self._serialize_resource_model(resource.get_model())

    def _serialize_multi_resource(self, resources: Iterable[Resource]) -> PJSONType:
        """
        Serialize the resources as serialized models, stripped of information irrelevant to the
        frontend.
        """
        return list(map(self._serialize_resource, resources))


async def start_server(
    ofrak_context: OFRAKContext,
    host: str,
    port: int,
    enable_cors: bool = False,
) -> AiohttpOFRAKServer:  # pragma: no cover
    # Force using the correct PJSON serialization with the expected structure. Otherwise the
    # dependency injector may accidentally use the Stashed PJSON serialization service,
    # which returns PJSON that has a different, problematic structure.
    ofrak_context.injector.bind_factory(PJSONSerializationService)

    ofrak_context.injector.bind_factory(
        AiohttpOFRAKServer,
        ofrak_context=ofrak_context,
        host=host,
        port=port,
        enable_cors=enable_cors,
    )
    server = await ofrak_context.injector.get_instance(AiohttpOFRAKServer)
    await server.start()

    return server


def respond_with_error(error: Exception, error_cls: Type[SerializedError]) -> Response:
    if isinstance(error, error_cls):
        text = error.to_json()
    else:
        text = json.dumps(error_cls.to_dict(error))
    response = Response(text=text, status=500)
    return response


def pluck_id(request: Request, get_parameter_name: str) -> bytes:
    return bytes.fromhex(request.match_info[get_parameter_name])


def get_query_string_as_pjson(request: Request) -> Dict[str, PJSONType]:
    """
    URL-encoded GET parameters are all strings. For example, None is encoded as 'None',
    or 1 as '1', which isn't valid PJSON. We fix this by applying `json.loads` on each parameter.
    """
    return {key: json.loads(value) for key, value in request.query.items()}


async def open_gui(
    host: str,
    port: int,
    focus_resource: Optional[Resource] = None,
    ofrak_context: Optional[OFRAKContext] = None,
    open_in_browser: bool = True,
    enable_cors: bool = False,
) -> AiohttpOFRAKServer:  # pragma: no cover
    if ofrak_context is None:
        ofrak_context = get_current_ofrak_context()

    server = await start_server(ofrak_context, host, port, enable_cors)

    if focus_resource is None:
        url = f"http://{server._host}:{server._port}/"
    else:
        url = f"http://{server._host}:{server._port}/#{focus_resource.get_id().hex()}"
    print(f"GUI is being served on {url}")

    if open_in_browser:
        webbrowser.open(url)

    return server


def json_response(
    data: Any = None,
    *,
    text: Optional[str] = None,
    body: Optional[bytes] = None,
    status: int = 200,
    reason: Optional[str] = None,
    headers=None,
    content_type: str = "application/json",
    dumps=orjson.dumps,
) -> Response:
    if data is not None:
        if text or body:
            raise ValueError("only one of data, text, or body should be specified")
        else:
            body = dumps(data)
    return Response(
        text=text,
        body=body,
        status=status,
        reason=reason,
        headers=headers,
        content_type=content_type,
    )
