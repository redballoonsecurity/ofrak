import os
from dataclasses import dataclass
from typing import Any, Iterable

import aiohttp

from ofrak.resource import Resource
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import ResourceFilter


@dataclass
class GhidraProject(ResourceView):
    """
    A resource which may be loaded into Ghidra and analyzed.
    """

    project_url: str
    ghidra_url: str


class GhidraComponentException(Exception):
    pass


class GhidraEnvironmentException(Exception):
    pass


class OfrakGhidraScript:
    """
    Class encapsulating a Ghidra script callable by OFRAK.

    :var script_path: A relative filepath to the script

    """

    script_dir: str
    script_name: str

    def __init__(self, script_path: str):
        self.script_dir = os.path.dirname(script_path)
        self.script_name = os.path.basename(script_path).split(".")[0]

    async def call_script(self, resource: Resource, *script_args: str) -> Any:
        """
        Call this script from the Ghidra analysis server and return the result.

        :param resource: A resource with a GhidraProject ancestor
        :param script_args: Arguments to send to the script as ordered arguments,
        available via the Ghidra API's getScriptArgs() method

        :return: The response, parsed from JSON to Python data structures
        """
        root_ghidra_project = await OfrakGhidraMixin.get_ghidra_project(resource)
        params = {f"__arg_{i}": arg for i, arg in enumerate(script_args)}

        async with aiohttp.ClientSession() as requests:
            response = await requests.get(
                f"{root_ghidra_project.ghidra_url}/{self.script_name}", params=params
            )
            if response.status == 200:
                return await response.json(content_type=None)
            elif response.status == 404:
                raise GhidraComponentException(
                    f"Ghidra OFRAK server has no registered endpoint '{self.script_name}'"
                )
            elif response.status == 500:
                server_error_msg = await response.text()
                paramtext = ",".join("=".join(k_v) for k_v in params.items())
                raise GhidraComponentException(
                    f"OFRAK Ghidra server encountered the following exception for request to "
                    f"{self.script_name} with params {paramtext}: \n{server_error_msg}"
                )
            else:
                response.raise_for_status()


class OfrakGhidraMixin:
    """
    A mixin for OFRAK components which use OFRAK scripts. Each OFRAK script should be defined as a
    `OfrakGhidraScript` member of the class.
    """

    def get_scripts(self) -> Iterable[OfrakGhidraScript]:
        """
        Generator yielding all scripts used by this class, as defined by class members of type
        `OfrakGhidraScript`.
        """
        for member in type(self).__dict__.values():
            if isinstance(member, OfrakGhidraScript):
                yield member

    @staticmethod
    async def get_ghidra_project(resource: Resource) -> GhidraProject:
        """Return `resource` or its relevant ancestor as a `GhidraProject` view."""
        return await resource.get_only_ancestor_as_view(
            GhidraProject,
            r_filter=ResourceFilter(
                include_self=True,
                tags=(GhidraProject,),
            ),
        )
