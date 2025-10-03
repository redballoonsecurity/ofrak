import setuptools
from setuptools.command.egg_info import egg_info


class egg_info_ex(egg_info):
    """Includes license file into `.egg-info` folder."""

    def run(self):
        # don't duplicate license into `.egg-info` when building a distribution
        if not self.distribution.have_run.get("install", True):
            # `install` command is in progress, copy license
            self.mkpath(self.egg_info)
            self.copy_file("LICENSE", self.egg_info)

        egg_info.run(self)


with open("LICENSE") as f:
    license = "".join(["\n", f.read()])


setuptools.setup(
    name="ofrak_cached_disassembly",
    version="0.1.0",
    author="Red Balloon Security",
    author_email="ofrak@redballoonsecurity.com",
    description="OFRAK Disassembler Components for Cached Results",
    url="",  # TODO
    packages=setuptools.find_packages("src"),
    package_dir={"": "src"},
    package_data={"ofrak_cached_disassembly": ["py.typed"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=["ofrak>=3.3.0,==3.*"],
    python_requires=">=3.9",
    include_package_data=True,
    license=license,
    cmdclass={"egg_info": egg_info_ex},
    entry_points={"ofrak.packages": ["ofrak_cached_disassembly_pkg = ofrak_cached_disassembly"]},
)
