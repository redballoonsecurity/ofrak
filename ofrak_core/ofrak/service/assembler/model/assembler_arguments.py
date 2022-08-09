class AssemblerFileArguments:
    def __init__(
        self,
        source_file,  # type: str
        vm_address,  # type: int
    ):
        self.source_file = source_file
        self.vm_address = vm_address

    def __repr__(self):
        return f"AsssemblerFileArguments({self.source_file}, {self.vm_address})"
