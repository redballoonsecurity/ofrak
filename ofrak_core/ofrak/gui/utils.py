import functools
import json
import logging
from typing import Type, Callable, Any, Optional, Dict, Iterable, Union

import orjson
from aiohttp.web_request import Request
from aiohttp.web_response import Response

from ofrak import Resource
from ofrak.gui.script_builder import ScriptBuilder
from ofrak.model.component_model import ComponentContext, ClientComponentContext
from ofrak.model.resource_model import (
    ResourceContext,
    ClientResourceContext,
    ResourceAttributes,
    ResourceModel,
    MutableResourceModel,
)
from ofrak.model.viewable_tag_model import ResourceViewContext
from ofrak.service.error import SerializedError
from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.service_i import SerializationServiceInterface

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


class OfrakShim:
    def __init__(
        self,
        ofrak_context,
        serializer: SerializationServiceInterface,
        job_ids: Dict[str, bytes],
        resource_context: ResourceContext = ClientResourceContext(),
        resource_view_context: ResourceViewContext = ResourceViewContext(),
        component_context: ComponentContext = ClientComponentContext(),
        script_builder: ScriptBuilder = ScriptBuilder(),
    ):
        # Use all the same ones server is using
        self.serializer: SerializationServiceInterface = serializer
        self._ofrak_context = ofrak_context
        self.resource_context: ResourceContext = resource_context
        self.resource_view_context: ResourceViewContext = resource_view_context
        self.component_context: ComponentContext = component_context
        self.script_builder: ScriptBuilder = script_builder
        self._job_ids: Dict[str, bytes] = job_ids

    async def get_resource_model_by_id(
        self,
        resource_id: bytes,
    ) -> Optional[Union[ResourceModel, MutableResourceModel]]:
        resource_m: Optional[
            Union[ResourceModel, MutableResourceModel]
        ] = self.resource_context.resource_models.get(resource_id)
        if resource_m is None:
            resource_m = await self._ofrak_context.resource_factory._resource_service.get_by_id(
                resource_id
            )
        return resource_m

    async def get_resource_by_id(self, resource_id: bytes, job_id: bytes) -> Resource:
        resource = await self._ofrak_context.resource_factory.create(
            job_id,
            resource_id,
            self.resource_context,
            self.resource_view_context,
            self.component_context,
        )
        return resource

    async def get_resource_for_request(self, request: Request) -> Resource:
        resource_id = pluck_id(request, "resource_id")
        if request.remote is not None:
            job_id = self._job_ids[request.remote]
        else:
            raise ValueError("No IP address found for the remote request!")
        return await self.get_resource_by_id(resource_id, job_id)

    def serialize_resource_model(self, resource_model: ResourceModel) -> PJSONType:
        """
        Serialize the resource model, stripped of information irrelevant to the frontend.
        """
        result = {
            "id": resource_model.id.hex(),
            "data_id": resource_model.data_id.hex() if resource_model.data_id else None,
            "parent_id": resource_model.parent_id.hex() if resource_model.parent_id else None,
            "tags": [tag.__module__ + "." + tag.__qualname__ for tag in resource_model.tags],
            "attributes": self.serializer.to_pjson(
                resource_model.attributes, Dict[Type[ResourceAttributes], ResourceAttributes]
            ),
            "caption": resource_model.caption,
        }
        return result

    def serialize_resource(self, resource: Resource) -> PJSONType:
        """
        Serialize the resource as a serialized model, stripped of information irrelevant to the
        frontend.
        """
        return self.serialize_resource_model(resource.get_model())

    def serialize_multi_resource(self, resources: Iterable[Resource]) -> PJSONType:
        """
        Serialize the resources as serialized models, stripped of information irrelevant to the
        frontend.
        """
        return list(map(self.serialize_resource, resources))
