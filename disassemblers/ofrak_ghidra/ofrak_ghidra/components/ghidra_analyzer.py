import asyncio
import hashlib
import logging
import os
from ofrak import tempfile
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional, List, Dict
from xml.etree import ElementTree

from ofrak import ResourceFilter
from ofrak.core import CodeRegion, MemoryRegion, NamedProgramSection, ProgramAttributes, Program
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
    GHIDRA_PATH,
    GHIDRA_VERSION,
)
from ofrak_ghidra.ghidra_model import (
    GhidraProject,
    OfrakGhidraScript,
    OfrakGhidraMixin,
    GhidraComponentException,
    GhidraCustomLoadProject,
    GhidraAutoLoadProject,
)
from ofrak_type import ArchInfo, InstructionSet, Endianness

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

    ghidra_zip_file: Optional[str]
    name: Optional[str]
    use_existing: bool


@dataclass
class GhidraProgramLoadConfig(ComponentConfig):
    """
    Config for GhidraProjectAnalyzer to pass in a pre-analyzed Ghidra project for a binary as a
    Ghidra Zip file.

    A Ghidra Zip File can be exported from Ghidra's project window, right-clicking on an analyzed
    file and "Export...". Then select the Ghidra Zip File format and save the file. This will
    create a .gzf file that you can import with this GhidraProjectConfig.
    """

    ghidra_zip_file: str


class GhidraProjectAnalyzer(Analyzer[None, GhidraProject]):
    """
    Use Ghidra backend to create project for and analyze a binary. This analyzer must run before
    Ghidra analysis can be accessed from OFRAK. This Analyzer can either create a new project and
    new analysis for a binary or, if a config is passed to it, load an existing Ghidra project.
    """

    id = b"GhidraProjectAnalyzer"
    targets = (GhidraAutoLoadProject,)
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

    @asynccontextmanager
    async def _prepare_ghidra_project(
        self, resource: Resource, ghidra_zip_file: Optional[str] = None, name: Optional[str] = None
    ):
        # TODO: allow multiple headless server instances
        os.system("pkill -if analyzeHeadless")
        if ghidra_zip_file is not None:
            full_fname = ghidra_zip_file
            tmp_dir = None
        else:
            tmp_dir = tempfile.TemporaryDirectory()
            data = await resource.get_data()
            hash_sha256 = hashlib.sha256()
            hash_sha256.update(data)

            fname = name if name is not None else hash_sha256.hexdigest()
            full_fname = os.path.join(tmp_dir.name, fname)

            data = await resource.get_data()
            with open(full_fname, "wb") as f:
                f.write(data)

        ghidra_project = f"ghidra://{GHIDRA_REPOSITORY_HOST}:{GHIDRA_REPOSITORY_PORT}/ofrak"

        try:
            yield ghidra_project, full_fname
        finally:
            if tmp_dir is not None:
                tmp_dir.cleanup()

    async def analyze(
        self, resource: Resource, config: Optional[GhidraProjectConfig] = None
    ) -> GhidraProject:
        gzf = config.ghidra_zip_file if config is not None else None
        binary_fname = config.name if config is not None else None

        # if passing a name for the file, by default don't overwrite an existing file
        # of the same name in the ghidra project.
        use_existing = config.use_existing if config is not None else binary_fname is not None

        async with self._prepare_ghidra_project(resource, gzf, binary_fname) as (
            ghidra_project,
            full_fname,
        ):
            program_name = await self._do_ghidra_import(
                ghidra_project, full_fname, use_existing=use_existing, use_binary_loader=False
            )
            await self._do_ghidra_analyze_and_serve(
                ghidra_project,
                program_name,
                skip_analysis=config is not None,
            )

            return GhidraProject(
                ghidra_project, f"http://{GHIDRA_SERVER_HOST}:{GHIDRA_SERVER_PORT}"
            )

    async def _do_ghidra_import(
        self,
        ghidra_project: str,
        full_fname: str,
        use_existing: bool,
        use_binary_loader: bool,
        processor: Optional[ArchInfo] = None,
        blocks: Optional[List[MemoryRegion]] = None,
    ):
        args = [
            ghidra_project,
            "-connect",
            GHIDRA_USER,
            "-p",
            "-import",
            full_fname,
            "-noanalysis",
        ]

        if not use_existing:
            args.append("-overwrite")

        if use_binary_loader:
            args.extend(["-loader", "BinaryLoader"])

        if processor:
            processor_id = self._arch_info_to_processor_id(processor)
            args.extend(["-processor", processor_id])

        if blocks is not None:
            args.extend(["-scriptPath", (";".join(self._script_directories))])
            args.extend(["-preScript", "CreateMemoryBlocks.java"])
            args.extend(await self._build_create_memory_args(blocks))

        cmd_str = " ".join([GHIDRA_HEADLESS_EXEC] + args)
        LOGGER.debug(f"Running command: {cmd_str}")
        ghidra_proc = await asyncio.create_subprocess_exec(
            GHIDRA_HEADLESS_EXEC,
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        LOGGER.debug(f"Started ghidra import: {ghidra_proc.pid}")

        while True:
            line = (await ghidra_proc.stdout.readline()).decode("ascii")

            if len(line) > 0:
                LOGGER.debug(line)
            elif ghidra_proc.stdout.at_eof():
                raise GhidraComponentException("Ghidra client exited unexpectedly")

            if line.startswith("Repository Server:"):
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
            if "Found conflicting program file in project" in line:
                if use_existing:
                    program_name = line.split(":")[-1].strip().split(" ")[0].strip("/")

                    if program_name == "":
                        raise GhidraComponentException(f"Parsed a blank program name from {line}!")

                    return program_name
                else:
                    raise GhidraComponentException(f"Conflicting file on import for {full_fname}")

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
        self,
        ghidra_project: str,
        program_name: str,
        skip_analysis: bool,
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

        if GHIDRA_VERSION <= "10.1.2":
            script_dir_joiner = "\\;"
        else:
            script_dir_joiner = ";"

        args.extend(["-scriptPath", f"'{script_dir_joiner.join(self._script_directories)}'"])

        args.extend(["-postScript", "AnalysisServer.java"])
        args.extend(self._build_ghidra_server_args())

        cmd_str = " ".join([GHIDRA_HEADLESS_EXEC] + args)
        LOGGER.debug(f"Running command: {cmd_str}")

        ghidra_proc = await asyncio.create_subprocess_shell(
            cmd_str,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        LOGGER.debug(f"Started ghidra analysis server process: {ghidra_proc.pid}")

        while ghidra_proc.returncode is None:
            line = (await ghidra_proc.stdout.readline()).decode("ascii")

            if len(line) > 0:
                LOGGER.debug(line)
            if line.startswith("Repository Server:"):
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

    @lru_cache(maxsize=None)
    def _arch_info_to_processor_id(self, processor: ArchInfo):
        families: Dict[InstructionSet, str] = {
            InstructionSet.ARM: "ARM",
            InstructionSet.AARCH64: "AARCH64",
            InstructionSet.MIPS: "MIPS",
            InstructionSet.PPC: "PowerPC",
            InstructionSet.M68K: "68000",
            InstructionSet.X86: "x86",
        }
        family = families.get(processor.isa)

        endian = "BE" if processor.endianness is Endianness.BIG_ENDIAN else "LE"
        # Ghidra proc IDs are of the form "ISA:endianness:bitWidth:suffix", where the suffix can indicate a specific processor or sub-ISA
        # The goal of the follow code is to identify the best proc ID for the ArchInfo, and we expect to be able to fall back on this default
        partial_proc_id = f"{family}:{endian}:{processor.bit_width.value}"
        # TODO: There are also some proc_ids that end with '_any' which are default-like
        default_proc_id = f"{partial_proc_id}:default"

        ldefs = os.path.join(GHIDRA_PATH, "Ghidra", "Processors", family, "data", "languages")
        processors_rejected = set()
        default_proc_id_found = False
        for file in os.listdir(ldefs):
            if not file.endswith(".ldefs"):
                continue

            tree = ElementTree.parse(os.path.join(ldefs, file))
            for language in tree.getroot().iter(tag="language"):
                proc_id = language.attrib["id"]
                # Ghidra has a list of alternative names for each support language spec
                # This is useful and interesting, for example it has the IDA equivalent name
                if not proc_id.startswith(partial_proc_id):
                    # Don't even consider language if it doesn't match ISA, bitwidth, endianness
                    continue
                if proc_id == default_proc_id:
                    default_proc_id_found = True
                    if not processor.sub_isa and not processor.processor:
                        # default_proc_id found, and the ArchoInfo doesn't contain any info to narrow it down further, so just break early to return the default
                        break

                for name_elem in language.iter(tag="external_name"):
                    name = name_elem.attrib["name"].lower()

                    if not processor.sub_isa and not processor.processor:
                        if name.endswith("_any"):
                            return proc_id

                    if processor.sub_isa and processor.sub_isa.value.lower() == name:
                        return proc_id

                    if processor.processor and processor.processor.value.lower() == name:
                        return proc_id

                processors_rejected.add(proc_id)

        if default_proc_id_found:
            return default_proc_id

        if len(processors_rejected) == 1:
            return processors_rejected.pop()

        raise GhidraComponentException(
            f"Could not determine a Ghidra language spec for the given architecture info "
            f"{processor}. Considered the following specs:\n{', '.join(processors_rejected)}"
        )

    async def _build_create_memory_args(self, blocks: List[MemoryRegion]) -> List[str]:
        args: List[str] = []

        for i, block in enumerate(blocks):
            block_info: List[str] = [
                str(block.virtual_address),
                str(block.size),
            ]

            if block.resource.has_tag(CodeRegion):
                block_info.append("rx")
            else:
                block_info.append("rw")

            if block.resource.has_tag(NamedProgramSection):
                named_section = await block.resource.view_as(NamedProgramSection)
                if " " in named_section.name or "!" in named_section.name:
                    raise ValueError(
                        f"Bad character in section name {named_section.name} which interferes with "
                        f"encoding arguments to CreateMemoryRegions.java"
                    )
                block_info.append(named_section.name)
            else:
                block_info.append(f"block_{i}")

            try:
                block_offset_range = await block.resource.get_data_range_within_parent()
                block_info.append(str(block_offset_range.start))
            except ValueError:
                # region has no data
                block_info.append("-1")

            args.append("!".join(block_info))

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


class GhidraCustomLoadAnalyzer(GhidraProjectAnalyzer):
    id = b"GhidraCustomLoadProjectAnalyzer"
    targets = (GhidraCustomLoadProject,)
    outputs = (GhidraCustomLoadProject,)

    async def analyze(
        self, resource: Resource, config: Optional[GhidraProjectConfig] = None
    ) -> GhidraProject:
        arch_info: ArchInfo = await resource.analyze(ProgramAttributes)
        mem_blocks = await self._get_memory_blocks(await resource.view_as(Program))
        use_existing = config.use_existing if config is not None else False

        async with self._prepare_ghidra_project(resource) as (ghidra_project, full_fname):
            program_name = await self._do_ghidra_import(
                ghidra_project,
                full_fname,
                use_existing=use_existing,
                use_binary_loader=True,
                processor=arch_info,
                blocks=mem_blocks,
            )
            await self._do_ghidra_analyze_and_serve(
                ghidra_project,
                program_name,
                skip_analysis=config is not None,
            )

            return GhidraProject(
                ghidra_project, f"http://{GHIDRA_SERVER_HOST}:{GHIDRA_SERVER_PORT}"
            )

    async def _get_memory_blocks(self, program: Program):
        mem_regions = await program.resource.get_children_as_view(
            MemoryRegion, r_filter=ResourceFilter.with_tags(MemoryRegion)
        )
        return list(mem_regions)
