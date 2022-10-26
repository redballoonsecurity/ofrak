import ofrak_ghidra
from ofrak import OFRAKContext, OFRAK

busybox_path = "/opt/rbs/busybox-1.31.0/unstripped_binaries/busybox_unstripped_arm32"


async def main(ofrak_context: OFRAKContext):
    root = await ofrak_context.create_root_resource_from_file(busybox_path)
    await root.unpack_recursively()


ofrak = OFRAK()
ofrak.discover(ofrak_ghidra)

ofrak.run(main)
