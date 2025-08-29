import setuptools
import pkg_resources
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


# Should be the same as in build_image.py
def read_requirements(requirements_path):
    with open(requirements_path) as requirements_handle:
        return [
            str(requirement)
            for requirement in pkg_resources.parse_requirements(requirements_handle)
        ]


setuptools.setup(
    name="ofrak_pyghidra",
    version="0.1.0",
    author="Red Balloon Security",
    author_email="ofrak@redballoonsecurity.com",
    description="OFRAK PyGhidra Components",
    url="",  # TODO
    packages=setuptools.find_packages(),
    package_data={"ofrak_pyghidra": ["py.typed"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=["ofrak>=3.3.0rc0", "ofrak_cached_disassembly>=0.1.0"]
    + read_requirements("requirements.txt"),
    extras_require={
        "test": [
            "fun-coverage==0.2.0",
            "pytest",
            "pytest-cov",
        ]
    },
    python_requires=">=3.9",
    include_package_data=True,
    license=license,
    cmdclass={"egg_info": egg_info_ex},
    entry_points={"ofrak.packages": ["ofrak_pyghidra_pkg = ofrak_pyghidra"]},
)
