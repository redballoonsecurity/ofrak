import asyncio
import hashlib
import logging
import os
import tempfile
import time
from dataclasses import dataclass
from typing import Optional, List

from ofrak import ResourceFilter
from ofrak.core import CodeRegion
from ofrak.component.analyzer import Analyzer
from ofrak.component.modifier import Modifier
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource, ResourceFactory
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface
from ofrak_ghidra.constants import (
    GHIDRA_HEADLESS_EXEC,
    GHIDRA_USER,
    GHIDRA_PASS,
    GHIDRA_SERVER_STARTED,
    GHIDRA_REPOSITORY_HOST,
    GHIDRA_REPOSITORY_PORT,
    GHIDRA_SERVER_HOST,
    GHIDRA_SERVER_PORT,
    GHIDRA_LOG_FILE,
    CORE_OFRAK_GHIDRA_SCRIPTS,
)
from ofrak_ghidra.ghidra_model import (
    GhidraProject,
    OfrakGhidraScript,
    OfrakGhidraMixin,
    GhidraComponentException,
)

LOGGER = logging.getLogger(__name__)


@dataclass
class GhidraProjectConfig(ComponentConfig):
    """
    Config for GhidraProjectAnalyzer to pass in a pre-analyzed Ghidra project for a binary as a
    Ghidra Zip file.

    A Ghidra Zip File can be exported from Ghidra's project window, right-clicking on an analyzed
    file and "Export...". Then select the Ghidra Zip File format and save the file. This will
    create a .gzf file that you can import with this GhidraProjectConfig.
    """

    ghidra_zip_file: str


class GhidraProjectAnalyzer(Analyzer[Optional[GhidraProjectConfig], GhidraProject]):
    """
    Use Ghidra backend to create project for and analyze a binary. This analyzer must run before
    Ghidra analysis can be accessed from OFRAK. This Analyzer can either create a new project and
    new analysis for a binary or, if a config is passed to it, load an existing Ghidra project.
    """

    id = b"GhidraProjectAnalyzer"
    targets = (GhidraProject,)
    outputs = (GhidraProject,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        ghidra_mixins: List[OfrakGhidraMixin],
    ):
        super().__init__(
            resource_factory,
            data_service,
            resource_service,
        )

        self._script_directories = set()
        self._scripts = set()

        for ghidra_mixin_implementation in ghidra_mixins:
            if type(ghidra_mixin_implementation) is OfrakGhidraMixin:
                # Skip the base class instance
                continue
            for script in ghidra_mixin_implementation.get_scripts():
                self._script_directories.add(script.script_dir)
                self._scripts.add(script.script_name)

    async def analyze(
        self, resource: Resource, config: Optional[GhidraProjectConfig] = None
    ) -> GhidraProject:
        # TODO: allow multiple headless server instances
        os.system("pkill -if analyzeHeadless")
        if config is not None:
            full_fname = config.ghidra_zip_file
            tmp_dir = None
        else:
            tmp_dir = tempfile.TemporaryDirectory()
            data = await resource.get_data()
            hash_sha256 = hashlib.sha256()
            hash_sha256.update(data)
            full_fname = os.path.join(tmp_dir.name, hash_sha256.hexdigest())
            data = await resource.get_data()
            with open(full_fname, "wb") as f:
                f.write(data)

        ghidra_project = f"ghidra://{GHIDRA_REPOSITORY_HOST}:{GHIDRA_REPOSITORY_PORT}/ofrak"

        program_name = await self._do_ghidra_import(ghidra_project, full_fname)
        await self._do_ghidra_analyze_and_serve(
            ghidra_project, program_name, skip_analysis=config is not None
        )

        if tmp_dir:
            tmp_dir.cleanup()

        return GhidraProject(ghidra_project, f"http://{GHIDRA_SERVER_HOST}:{GHIDRA_SERVER_PORT}")

    async def _do_ghidra_import(self, ghidra_project: str, full_fname: str):
        args = [
            ghidra_project,
            "-connect",
            GHIDRA_USER,
            "-p",
            "-import",
            full_fname,
            "-overwrite",
        ]

        cmd_str = " ".join([GHIDRA_HEADLESS_EXEC] + args)
        LOGGER.debug(f"Running command: {cmd_str}")
        ghidra_proc = await asyncio.create_subprocess_exec(
            GHIDRA_HEADLESS_EXEC,
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        LOGGER.debug(f"Started ghidra import.: {ghidra_proc.pid}")

        while True:
            line = (await ghidra_proc.stdout.readline()).decode("ascii")

            if len(line) > 0:
                LOGGER.debug(line)
            elif ghidra_proc.stdout.at_eof():
                raise GhidraComponentException("Ghidra client exited unexpectedly")

            if "Repository Server: localhost" in line:
                time.sleep(0.5)
                ghidra_proc.stdin.write((GHIDRA_PASS + "\n").encode("ascii"))
                await ghidra_proc.stdin.drain()
            if "Disconnected from repository" in line:
                raise GhidraComponentException(
                    "Disconnected from Ghidra repository before file import succeeded!"
                )
            if "ERROR Connection to server failed" in line:
                raise GhidraComponentException(
                    f"Ghidra server seems to be down. Run 'python -m "
                    f"ofrak_ghidra.server start' to start it. "
                    f"Refer to our Ghidra User Guide for more troubleshooting instructions."
                )
            if "Import failed for file" in line:
                raise GhidraComponentException(f"Error importing file {full_fname}")
            if "Added file to repository" in line:
                program_name = line.split("REPORT: Added file to repository: /")[1].split(
                    " (HeadlessAnalyzer)"
                )[0]

                if program_name == "":
                    raise GhidraComponentException(f"Parsed a blank program name from {line}!")

                return program_name

    async def _do_ghidra_analyze_and_serve(
        self, ghidra_project: str, program_name: str, skip_analysis: bool
    ):
        args = [
            ghidra_project,
            "-connect",
            GHIDRA_USER,
            "-p",
            "-process",
            program_name,
            "-readOnly",
        ]

        if skip_analysis:
            args.append("-noanalysis")

        args.extend(["-scriptPath", (";".join(self._script_directories))])

        args.extend(["-postScript", "AnalysisServer.java"])
        args.extend(self._build_ghidra_server_args())

        cmd_str = " ".join([GHIDRA_HEADLESS_EXEC] + args)
        LOGGER.debug(f"Running command: {cmd_str}")

        ghidra_proc = await asyncio.create_subprocess_exec(
            GHIDRA_HEADLESS_EXEC,
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        LOGGER.debug(f"Started ghidra analysis server process: {ghidra_proc.pid}")

        while ghidra_proc.returncode is None:
            line = (await ghidra_proc.stdout.readline()).decode("ascii")

            if len(line) > 0:
                LOGGER.debug(line)
            if "Repository Server: localhost" in line:
                time.sleep(0.5)
                ghidra_proc.stdin.write((GHIDRA_PASS + "\n").encode("ascii"))
                await ghidra_proc.stdin.drain()
            if "Disconnected from repository" in line:
                raise GhidraComponentException(
                    f"Error starting ghidra remote, check logs (at {GHIDRA_LOG_FILE})"
                )
            if GHIDRA_SERVER_STARTED in line:
                return

        ghidra_errors = await ghidra_proc.stderr.read()
        raise GhidraComponentException(f"Ghidra server exited unexpectedly! \n{ghidra_errors}")

    def _build_ghidra_server_args(self) -> List[str]:
        args = [str(GHIDRA_SERVER_PORT)]

        for ghidra_script in self._scripts:
            args.append(ghidra_script)

        return args


class GhidraCodeRegionModifier(Modifier, OfrakGhidraMixin):
    id = b"GhidraCodeRegionModifier"
    targets = (CodeRegion,)

    get_code_regions_script = OfrakGhidraScript(
        os.path.join(CORE_OFRAK_GHIDRA_SCRIPTS, "GetCodeRegions.java"),
    )

    async def modify(self, resource: Resource, config=None):
        code_region = await resource.view_as(CodeRegion)
        ghidra_project = await OfrakGhidraMixin.get_ghidra_project(resource)

        ofrak_code_regions = await ghidra_project.resource.get_descendants_as_view(
            v_type=CodeRegion, r_filter=ResourceFilter(tags=[CodeRegion])
        )

        backend_code_regions_json = await self.get_code_regions_script.call_script(resource)
        backend_code_regions = []

        for cr_j in backend_code_regions_json:
            cr = CodeRegion(cr_j["start"], cr_j["size"])
            backend_code_regions.append(cr)

        ofrak_code_regions = sorted(ofrak_code_regions, key=lambda cr: cr.virtual_address)
        backend_code_regions = sorted(backend_code_regions, key=lambda cr: cr.virtual_address)

        if len(ofrak_code_regions) > 0:
            relative_va = code_region.virtual_address - ofrak_code_regions[0].virtual_address

            for backend_cr in backend_code_regions:
                backend_relative_va = (
                    backend_cr.virtual_address - backend_code_regions[0].virtual_address
                )

                if backend_relative_va == relative_va and backend_cr.size == code_region.size:
                    resource.add_view(backend_cr)
                    return

            LOGGER.debug(
                f"No code region with relative offset {relative_va} and size {code_region.size} found in Ghidra"
            )
        else:
            LOGGER.debug("No OFRAK code regions to match in Ghidra")
