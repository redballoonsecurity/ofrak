import asyncio
import logging
import os
import re
import shutil
import sys
import tempfile
from io import StringIO
from subprocess import CalledProcessError
from typing import Dict, List, Optional, Tuple, Type

from aiohttp import web
from aiohttp.web_request import Request
from aiohttp.web_response import Response, StreamResponse

from ofrak import Resource
from ofrak.core import (
    ProgramAttributes,
    Program,
    SegmentInjectorModifier,
    SegmentInjectorModifierConfig,
    LinkableBinary,
    Allocatable,
    LiefAddSegmentModifier,
    LiefAddSegmentConfig,
    Elf,
    ElfProgramHeaderType,
    ElfUnpacker,
    FreeSpace,
    FreeSpaceAnalyzer,
    ComplexBlock,
    FreeSpaceModifier,
)
from ofrak.core.elf.load_alignment_modifier import ElfLoadAlignmentModifier
from ofrak.core.free_space import FreeSpaceModifierConfig
from ofrak.gui.utils import OfrakServerHelper, exceptions_to_http, json_response
from ofrak.service.error import SerializedError
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_patch_maker.model import BOM, PatchRegionConfig, PatchMakerException
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.abstract import Toolchain
from ofrak_patch_maker.toolchain.model import ToolchainConfig, ToolchainException, Segment
from ofrak_type import MemoryPermissions, Range


class InvalidStateException(Exception):
    def __init__(self, current_step: str, missing_step: str):
        super().__init__(f"Could not {current_step}, required step ({missing_step}) not completed")


class PatchWizard:
    def __init__(self, shim: OfrakServerHelper):
        self.patches: Dict[str, PatchInProgress] = {}
        self.helper: OfrakServerHelper = shim

    def routes(self) -> List:
        return [
            web.post(
                "/{resource_id}/patch_wizard/start_new_patch",
                self.start_new_patch,
            ),
            web.post(
                "/patch_wizard/remove_patch",
                self.remove_patch,
            ),
            web.post(
                "/patch_wizard/add_file",
                self.add_file,
            ),
            web.post(
                "/patch_wizard/delete_file",
                self.delete_file,
            ),
            web.post(
                "/patch_wizard/get_object_infos",
                self.get_object_infos,
            ),
            web.post(
                "/patch_wizard/get_target_info",
                self.get_target_info,
            ),
            web.post("/patch_wizard/get_all_patches_in_progress", self.get_patches_in_progress),
            web.post("/patch_wizard/listen_logs", self.get_next_log_message),
            web.post("/{resource_id}/patch_wizard/save_current_patch", self.save_current_patch),
            web.post("/patch_wizard/inject_patch", self.inject_patch),
            web.post("/patch_wizard/extend_elf", self.extend_elf),
            web.post("/patch_wizard/get_complex_blocks", self.get_complex_blocks),
            web.post("/patch_wizard/free_complex_blocks", self.free_complex_blocks),
        ]

    @exceptions_to_http(SerializedError)
    async def start_new_patch(self, request: Request) -> Response:
        resource = await self.helper.get_resource_for_request(request)
        name = request.query["patch_name"]
        patch = PatchInProgress(name, resource)
        self.patches[name] = patch

        return json_response(patch.latest_metadata)

    @exceptions_to_http(SerializedError)
    async def remove_patch(self, request: Request) -> Response:
        name = request.query["patch_name"]
        del self.patches[name]

        return Response(status=200)

    @exceptions_to_http(SerializedError)
    async def add_file(self, request: Request) -> Response:
        patch_name = request.query["patch_name"]
        file_name = request.query["file_name"]
        body = await request.read()
        self.patches[patch_name].files[file_name] = body

        return Response(status=200)

    @exceptions_to_http(SerializedError)
    async def delete_file(self, request: Request) -> Response:
        patch_name = request.query["patch_name"]
        file_name = request.query["file_name"]

        del self.patches[patch_name].files[file_name]

        return Response(status=200)

    @exceptions_to_http(SerializedError)
    async def get_object_infos(self, request: Request) -> Response:
        patch_name = request.query["patch_name"]
        patch_in_progress = self.patches[patch_name]

        body = await request.json()
        toolchain = self.helper.serializer.from_pjson(body["toolchain"], Type[Toolchain])
        toolchain_config = self.helper.serializer.from_pjson(
            body["toolchainConfig"], ToolchainConfig
        )

        patch_in_progress.latest_metadata["userInputs"]["toolchain"] = body["toolchain"]
        patch_in_progress.latest_metadata["userInputs"]["toolchainConfig"] = body["toolchainConfig"]

        patch_bom = await patch_in_progress.build_patch_bom(toolchain, toolchain_config)

        object_infos_struct = [
            {
                "name": os.path.basename(source_name),
                "segments": [
                    {
                        "name": seg.segment_name,
                        "size": seg.length,
                        "permissions": seg.access_perms.as_str(),
                        "include": False,
                        "allocatedVaddr": None,
                        "unit": os.path.basename(obj.path),
                    }
                    for seg in obj.segment_map.values()
                ],
                "strongSymbols": list(obj.strong_symbols.keys()),
                "unresolvedSymbols": list(obj.unresolved_symbols.keys()),
            }
            for source_name, obj in patch_bom.object_map.items()
        ]

        return json_response(object_infos_struct)

    @exceptions_to_http(SerializedError)
    async def get_patches_in_progress(self, request: Request) -> Response:
        # Get all patches in progress, with populated patchInfos according to how much stuff is ready for each patch
        patches = [
            p.latest_metadata for p in self.patches.values() if p.latest_metadata is not None
        ]
        return json_response(patches)

    @exceptions_to_http(SerializedError)
    async def get_source_file_body(self, request: Request) -> Response:
        # Get the source file body for one patch
        raise NotImplementedError()

    @exceptions_to_http(SerializedError)
    async def get_target_info(self, request: Request) -> Response:
        patch_name = request.query["patch_name"]
        patch_in_progress = self.patches[patch_name]

        target_bom, _ = await patch_in_progress.build_target_bom()

        symbols = set()
        for obj in target_bom.object_map.values():
            symbols.update(obj.strong_symbols)

        if "empty_source.c" in symbols:
            # Empty source file created by LinkableBinary.make_linkable_bom so that it can always make a stub BOM
            symbols.remove("empty_source.c")

        target_info_struct = {"symbols": list(symbols)}

        return json_response(target_info_struct)

    @exceptions_to_http(SerializedError)
    async def get_next_log_message(self, request: Request) -> Response:
        patch_name = request.query["patch_name"]

        logged_message = await self.patches[patch_name].logs.listen()

        return Response(status=200, text=logged_message)

    @exceptions_to_http(SerializedError)
    async def save_current_patch(self, request: Request) -> Response:
        resource = await self.helper.get_resource_for_request(request)

        patch_info = await request.json()

        self.patches[patch_info["name"]].latest_metadata = patch_info
        return Response(
            status=200,
        )

    @exceptions_to_http(SerializedError)
    async def inject_patch(self, request: Request) -> Response:
        patch_name = request.query["patch_name"]
        patch = self.patches[patch_name]

        patch_spec = await request.json()

        extra_syms = patch_spec["userSymbols"]
        object_infos = patch_spec["objectInfos"]

        obj_to_segs = {}

        for obj in object_infos:
            segments = []
            for segInfo in obj["segments"]:
                if not segInfo["include"]:
                    continue

                seg = Segment(
                    segInfo["name"],
                    segInfo["allocatedVaddr"],
                    0,
                    False,
                    segInfo["size"],
                    MemoryPermissions[segInfo["permissions"].upper()],
                )
                segments.append(seg)
            obj_path = patch.source_file_name_to_object_path(obj["name"])

            obj_to_segs[obj_path] = tuple(segments)

        patch_regions = PatchRegionConfig(
            patch_name,
            obj_to_segs,
        )

        injected_bytes = await patch.inject_bom(patch_regions, dict(extra_syms))

        return Response(status=200, text=f"Success! Injected {hex(injected_bytes)} bytes")

    @exceptions_to_http(SerializedError)
    async def extend_elf(self, request) -> StreamResponse:
        patch_name = request.query["patch_name"]
        method = request.query.get("method")
        # extension_size = request.query.get("ext_size")
        patch = self.patches[patch_name]
        resource = patch.resource

        # Guess a reasonable vaddr
        elf = await resource.view_as(Elf)

        # Option 1: Use lief modifier to replace NOTE segment
        if method == "note":
            note_idx = None
            for ph in await elf.get_program_headers():
                if ph.p_type == ElfProgramHeaderType.NOTE.value:
                    note_idx = ph.segment_index
                    break
            if note_idx is None:
                return Response(status=520, text="No NOTE segment found")
            MIN_SIZE = 0x1000
            DEFAULT_SIZE = 0x1000
            DEFAULT_ALIGN = 0x1000

            def align_up(x):
                if x % DEFAULT_ALIGN != 0:
                    return x + (DEFAULT_ALIGN - (x % DEFAULT_ALIGN))
                else:
                    return x

            def align_down(x):
                if x % DEFAULT_ALIGN != 0:
                    return x - (x % DEFAULT_ALIGN)
                else:
                    return x

            occupied_mem = Range.merge_ranges(
                [Range.from_size(ph.p_vaddr, ph.p_memsz) for ph in await elf.get_program_headers()]
            )

            existing_code_mem = Range.merge_ranges(
                [
                    Range.from_size(ph.p_vaddr, ph.p_memsz)
                    for ph in await elf.get_program_headers()
                    if ph.p_type == ElfProgramHeaderType.LOAD.value
                    and ph.p_flags & MemoryPermissions.RX.value
                ]
            )

            free_space_between_occupied_mem = [
                Range(free_block_start, free_block_end)
                for free_block_start, free_block_end in zip(
                    [r.start for r in occupied_mem[:-1]], [r.start for r in occupied_mem[1:]]
                )
            ]

            free_space_between_occupied_mem = [
                Range(align_up(r.start), align_down(r.end))
                for r in free_space_between_occupied_mem
                if align_up(r.start) < align_down(r.end)
            ]

            closest_to_existing: Tuple[Optional[Range], int, bool] = (None, sys.maxsize, False)
            # Iterate over all
            for free_block in free_space_between_occupied_mem:
                # for i, occupied_range in enumerate(occupied_mem):
                for existing_code in existing_code_mem:
                    _, closest_distance, _ = closest_to_existing

                    distance_up = abs(free_block.end - existing_code.start)
                    distance_down = abs(free_block.start - existing_code.end)

                    if distance_up < closest_distance:
                        # This free memory is closest to existing code memory at a HIGHER vaddr
                        closest_to_existing = (free_block, distance_up, True)
                    if distance_down < closest_distance:
                        # This free memory is closest to existing code memory at a LOWER vaddr
                        closest_to_existing = (free_block, distance_down, False)

            closest_free_block, _, closest_high = closest_to_existing
            if closest_free_block is None:
                # This should only make sense when there are no gaps in occupied memory
                if len(occupied_mem) > 1:
                    if len(existing_code_mem) == 0:
                        raise ValueError("No existing code memory to base new vaddr off of!")
                    else:
                        raise ValueError(
                            "Found no closest vaddr but there are gaps in existing memory!"
                        )
                closest_free_block = Range.from_size(align_up(occupied_mem[-1].end), DEFAULT_SIZE)
                closest_high = False

            ext_size = min(closest_free_block.length(), DEFAULT_SIZE)
            if ext_size < MIN_SIZE:
                raise ValueError(
                    f"Best place to add a block would be {closest_free_block}, but it would be smaller than the minimum size!"
                )

            if closest_high:
                new_block = Range(closest_free_block.end - ext_size, closest_free_block.end)
            else:
                new_block = Range(closest_free_block.start, closest_free_block.start + ext_size)

            children = list(await resource.get_children())
            for child in children:
                await child.delete()
                await child.save()

            resource.remove_component(ElfUnpacker.get_id())
            await resource.save()

            await resource.run(
                LiefAddSegmentModifier,
                LiefAddSegmentConfig(
                    new_block.start,
                    new_block.length(),
                    [0 * new_block.length()],
                    "rx",
                ),
            )

            await resource.unpack()
            elf = await resource.view_as(Elf)
            load_idx = None
            for ph in await elf.get_program_headers():
                if ph.p_vaddr == new_block.start:
                    await resource.create_child_from_view(
                        FreeSpace(ph.p_vaddr, ph.p_memsz, MemoryPermissions.RX),
                        data_range=Range.from_size(ph.p_offset, ph.p_filesz),
                    )
                    load_idx = ph.segment_index
                    break
            resource.remove_component(FreeSpaceAnalyzer.get_id())
            await resource.save()

            return Response(
                status=200,
                text=f"Replaced NOTE program header at #{note_idx} with a LOAD header at #{load_idx}",
            )

        elif method == "load_align":
            # Option 2: LoadAlignmentModifier
            resource.add_tag(Allocatable)
            await resource.save()
            alloc = await resource.view_as(Allocatable)
            original_range_count = sum(len(ranges) for ranges in alloc.free_space_ranges.values())

            await resource.run(ElfLoadAlignmentModifier)

            resource.remove_component(FreeSpaceAnalyzer.get_id())
            await resource.save()
            alloc = await resource.view_as(Allocatable)
            updated_range_count = sum(len(ranges) for ranges in alloc.free_space_ranges.values())

            if updated_range_count > original_range_count:
                n_new_ranges = updated_range_count - original_range_count
                possesion_suffixes = ("'s", "") if n_new_ranges == 1 else ("s'", "s")
                return json_response(
                    status=200,
                    text=f"Recovered free space from {n_new_ranges} segment{possesion_suffixes[0]} alignment{possesion_suffixes[1]}",
                )
            else:
                return Response(
                    status=520, text="Load alignment modifier could not recover any free space!"
                )

        return Response(status=400, text="No extension method specified")

    @exceptions_to_http(SerializedError)
    async def get_complex_blocks(self, request: Request) -> Response:
        patch_name = request.query["patch_name"]
        patch = self.patches[patch_name]

        results = [
            {
                "id": cb.resource.get_id().hex(),
                "name": cb.name,
                "vaddr": cb.virtual_address,
                "size": cb.size,
            }
            for cb in await patch.resource.get_descendants_as_view(
                ComplexBlock, r_filter=ResourceFilter.with_tags(ComplexBlock)
            )
        ]
        return json_response(results)

    @exceptions_to_http(SerializedError)
    async def free_complex_blocks(self, request: Request) -> Response:
        patch_name = request.query["patch_name"]
        patch = self.patches[patch_name]

        cb_ids = {bytes.fromhex(id_str) for id_str in await request.json()}

        cbs_to_free = [
            cb_r
            for cb_r in await patch.resource.get_descendants(
                r_filter=ResourceFilter.with_tags(ComplexBlock)
            )
            if cb_r.get_id() in cb_ids
        ]

        await asyncio.gather(
            *(
                cb_r.run(FreeSpaceModifier, FreeSpaceModifierConfig(MemoryPermissions.RX))
                for cb_r in cbs_to_free
            )
        )

        patch.resource.remove_component(FreeSpaceAnalyzer.get_id())
        await patch.resource.save()

        return Response(status=200)


class LogStreamer(StringIO):
    tmpfile_regex = re.compile(r"/tmp/tmp[a-zA-Z0-9]+/")

    def __init__(self):
        self.message_queue = asyncio.Queue()
        super().__init__()

    def write(self, msg: str):
        stripped_msg = self.tmpfile_regex.sub("", msg)
        self.message_queue.put_nowait(stripped_msg)

    def flush(self):
        pass

    async def listen(self) -> str:
        return await self.message_queue.get()


class PatchInProgress:
    def __init__(self, name: str, target_resource: Resource):
        self.name = name
        self.resource = target_resource
        self.build_tmp_dir = tempfile.TemporaryDirectory()

        self.logs = LogStreamer()
        self.currentLogger: Optional[logging.Logger] = None

        self.files: Dict[str, bytes] = {}

        self.patch_maker: Optional[PatchMaker] = None
        self.patch_bom: Optional[BOM] = None
        self.patch_bom_dir: Optional[str] = None
        self.target_linkable_bom_info: Optional[Tuple[BOM, PatchRegionConfig]] = None

        self.latest_metadata: Dict = {
            "name": self.name,
            "sourceInfos": [],
            "objectInfosValid": False,
            "objectInfos": [],
            "targetInfo": {"symbols": []},
            "targetInfoValid": False,
            "userInputs": {
                "symbols": [],
                "toolchain": None,
                "toolchainConfig": None,
            },
            "symbolRefMap": None,
        }

    def __del__(self):
        if self.build_tmp_dir:
            self.build_tmp_dir.cleanup()

    def source_file_name_to_object_path(self, src_fname):
        for old_src_path, obj in self.patch_bom.object_map.items():
            if os.path.basename(old_src_path) == src_fname:
                return obj.path

    def add_file(self, name: str, body: bytes):
        self.files[name] = body

    def delete_file(self, name: str):
        del self.files[name]

    async def build_patch_bom(self, toolchain_type, toolchain_config):
        program_attributes = await self.resource.analyze(ProgramAttributes)

        self.currentLogger = logging.Logger("patchmaker logs", level=logging.DEBUG)
        self.currentLogger.addHandler(logging.StreamHandler(stream=self.logs))

        toolchain = self._try_and_log_errors(
            toolchain_type,
            program_attributes,
            toolchain_config,
            logger=self.currentLogger,
        )

        self.patch_maker = self._try_and_log_errors(
            PatchMaker,
            toolchain=toolchain,
            build_dir=self.build_tmp_dir.name,
            logger=self.currentLogger,
        )

        if self.patch_bom_dir:
            shutil.rmtree(self.patch_bom_dir)

        # Need to save this to make it possible to clear it later
        self.patch_bom_dir = os.path.join(self.build_tmp_dir.name, f"{self.name}_bom_files")

        with tempfile.TemporaryDirectory() as source_temp_dir:
            with tempfile.TemporaryDirectory() as header_temp_dir:
                source_list = []
                for filename, contents in self.files.items():
                    if filename.split(".")[-1] in ("c", "as", "S"):
                        # source file
                        path = os.path.join(source_temp_dir, filename)
                        with open(path, "wb") as f:
                            f.write(contents)
                        source_list.append(path)
                    else:
                        # header file (presumably)
                        path = os.path.join(header_temp_dir, filename)
                        with open(path, "wb") as f:
                            f.write(contents)

                self.patch_bom = self._try_and_log_errors(
                    self.patch_maker.make_bom,
                    name=self.name,
                    source_list=source_list,
                    object_list=[],
                    header_dirs=[header_temp_dir],
                )

        return self.patch_bom

    async def build_target_bom(self):
        target_program = await self.resource.view_as(Program)

        stubs_bom_dir = os.path.join(self.build_tmp_dir.name, "stubs_bom_files")
        if os.path.exists(stubs_bom_dir):
            shutil.rmtree(stubs_bom_dir)

        with tempfile.TemporaryDirectory() as stubs_sources_dir:
            self.target_linkable_bom_info = await target_program.make_linkable_bom(
                self.patch_maker,
                stubs_sources_dir,
                self.patch_bom.unresolved_symbols,
            )

        return self.target_linkable_bom_info

    async def inject_bom(self, patch_regions: PatchRegionConfig, extra_syms: Dict[str, int]):
        exec_path = os.path.join(self.build_tmp_dir.name, "output_exec")

        if self.patch_maker is None or self.patch_bom is None:
            raise InvalidStateException("inject BOM", "build patch BOM")

        fem = self._try_and_log_errors(
            self.patch_maker.make_fem,
            [(self.patch_bom, patch_regions), self.target_linkable_bom_info],
            exec_path,
            additional_symbols=extra_syms,
        )

        config = SegmentInjectorModifierConfig.from_fem(fem)

        final_injected_size = 0
        for _, data in config.segments_and_data:
            final_injected_size += len(data)

        await self.resource.run(
            SegmentInjectorModifier,
            config,
        )

        # Refresh LinkableBinary with the LinkableSymbols used in this patch
        target_binary = await self.resource.view_as(LinkableBinary)
        program_attributes = await self.resource.analyze(ProgramAttributes)
        await target_binary.define_linkable_symbols_from_patch(
            fem.executable.symbols, program_attributes
        )

        return final_injected_size

    def _try_and_log_errors(self, f, *args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ToolchainException as e:
            self.currentLogger.error(str(e))
            raise

        except PatchMakerException as e:
            self.currentLogger.error(str(e))
            raise

        except CalledProcessError as e:
            self.currentLogger.error(str(e))
            raise
