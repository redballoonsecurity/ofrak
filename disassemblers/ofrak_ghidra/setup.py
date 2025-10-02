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
    name="ofrak_ghidra",
    version="0.2.0rc3",
    author="Red Balloon Security",
    author_email="ofrak@redballoonsecurity.com",
    description="OFRAK Ghidra Components",
    url="",  # TODO
    packages=setuptools.find_packages("src"),
    package_dir={"": "src"},
    package_data={"ofrak_ghidra": ["py.typed"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "ofrak>=3.3.0rc10",
        "PyYAML>=5.4,",
        "aiohttp~=3.12.14",
    ],
    python_requires=">=3.9",
    include_package_data=True,
    license=license,
    cmdclass={"egg_info": egg_info_ex},
    entry_points={"ofrak.packages": ["ofrak_ghidra_pkg = ofrak_ghidra"]},
)
