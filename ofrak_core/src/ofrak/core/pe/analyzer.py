from typing import Optional

from ofrak.component.analyzer import Analyzer
from ofrak.core.pe.model import Pe, PeWinOptionalHeader
from ofrak.core.program_metadata import ProgramMetadata
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource


class PeProgramMetadataAnalyzer(Analyzer[None, ProgramMetadata]):
    """
    Extracts program metadata from PE binaries for use by disassembler backends.

    Provides the entry point address (image_base + address_of_entry_point RVA) and the
    base address (ImageBase field from the optional header). This metadata helps
    disassembler backends properly analyze PE binaries, especially when loading
    raw memory dumps or when the backend doesn't natively understand PE format.
    """

    id = b"PeProgramMetadataAnalyzer"
    targets = (Pe,)
    outputs = (ProgramMetadata,)

    async def analyze(
        self, resource: Resource, config: Optional[ComponentConfig] = None
    ) -> ProgramMetadata:
        pe = await resource.view_as(Pe)
        optional_header = await pe.get_optional_header()

        if optional_header is None:
            return ProgramMetadata()

        # Compute absolute entry point VA
        # address_of_entry_point is an RVA, need to add image_base
        entry_rva = optional_header.address_of_entry_point
        if isinstance(optional_header, PeWinOptionalHeader):
            image_base = optional_header.image_base
            entry_point = image_base + entry_rva if entry_rva else None
            base_address = image_base
        else:
            # Non-Windows PE without image_base
            entry_point = entry_rva if entry_rva else None
            base_address = None

        return ProgramMetadata(
            entry_points=(entry_point,) if entry_point else (),
            base_address=base_address,
        )
