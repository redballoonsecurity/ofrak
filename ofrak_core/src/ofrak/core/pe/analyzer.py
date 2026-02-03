from typing import Optional

from ofrak.component.analyzer import Analyzer
from ofrak.core.pe.model import Pe, PeOptionalHeader, PeWinOptionalHeader
from ofrak.core.program_metadata import ProgramMetadata
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_type.error import NotFoundError


class PeProgramMetadataAnalyzer(Analyzer[None, ProgramMetadata]):
    """
    Extracts program metadata from PE binaries for use by disassembler backends.

    Provides the entry point address (image_base + address_of_entry_point RVA) and the
    base address (ImageBase field from the optional header). This metadata helps
    disassembler backends properly analyze PE binaries, especially when loading
    raw memory dumps or when the backend doesn't natively understand PE format.

    Note: For PE files, AddressOfEntryPoint=0 means "no entry point" (per PE spec),
    which is different from ELF where e_entry=0 can be a valid entry address.
    """

    id = b"PeProgramMetadataAnalyzer"
    targets = (Pe,)
    outputs = (ProgramMetadata,)

    async def analyze(
        self, resource: Resource, config: Optional[ComponentConfig] = None
    ) -> ProgramMetadata:
        # Try to get Windows optional header (with image_base) first
        try:
            optional_header = await resource.get_only_child_as_view(
                PeWinOptionalHeader,
                ResourceFilter(tags=(PeOptionalHeader,)),
            )
            entry_rva = optional_header.address_of_entry_point
            image_base = optional_header.image_base
            # PE spec: AddressOfEntryPoint=0 means "no entry point", not entry at address 0
            entry_point = image_base + entry_rva if entry_rva else None
            base_address = image_base
        except NotFoundError:
            # Fall back to basic optional header (no image_base)
            pe = await resource.view_as(Pe)
            optional_header = await pe.get_optional_header()
            if optional_header is None:
                return ProgramMetadata()
            entry_rva = optional_header.address_of_entry_point
            # PE spec: AddressOfEntryPoint=0 means "no entry point"
            entry_point = entry_rva if entry_rva else None
            base_address = None

        return ProgramMetadata(
            entry_points=(entry_point,) if entry_point is not None else (),
            base_address=base_address,
        )
