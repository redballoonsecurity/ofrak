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
    name="ofrak_ghidra",
    version="0.1.0",
    author="Red Balloon Security",
    author_email="ofrak@redballoonsecurity.com",
    description="OFRAK Ghidra Components",
    url="",  # TODO
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=read_requirements("requirements.txt"),
    extras_require={
        "test": [
            "fun-coverage==0.2.0",
            "pytest",
            "pytest-asyncio==0.19.0",
            "pytest-cov",
            "requests",
            "psutil",
        ]
    },
    python_requires=">=3.7",
    include_package_data=True,
    license=license,
    cmdclass={"egg_info": egg_info_ex},
    entry_points={"ofrak.packages": ["ofrak_ghidra_pkg = ofrak_ghidra"]},
)
