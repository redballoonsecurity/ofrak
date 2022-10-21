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
    name="ofrak_angr",
    version="0.1.0",
    author="Red Balloon Security",
    author_email="ofrak@redballoonsecurity.com",
    description="OFRAK angr Components",
    url="",  # TODO
    packages=[
        "ofrak_angr",
    ],
    package_data={"ofrak_angr": ["py.typed"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "angr==9.2.6",
    ],
    extras_require={
        "test": [
            "fun-coverage~=0.1.0",
            "pytest",
            "pytest-asyncio==0.19.0",
            "pytest-cov",
            "requests",
        ],
        "graphical": ["pygraphviz"],
    },
    python_requires=">=3.7",
    license=license,
    cmdclass={"egg_info": egg_info_ex},
)
