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


with open("README.md") as f:
    long_description = f.read()


# Should be the same as in build_image.py
def read_requirements(requirements_path):
    with open(requirements_path) as requirements_handle:
        return [
            str(requirement)
            for requirement in pkg_resources.parse_requirements(requirements_handle)
        ]


setuptools.setup(
    name="ofrak_angr",
    version="1.0.1",
    description="OFRAK angr Components",
    packages=setuptools.find_packages(exclude=["ofrak_angr_test", "ofrak_angr_test.*"]),
    package_data={"ofrak_angr": ["py.typed"]},
    install_requires=[
        "ofrak",
    ]
    + read_requirements("requirements.txt"),
    extras_require={
        "test": [
            "fun-coverage==0.2.0",
            "pytest",
            "pytest-asyncio==0.19.0",
            "pytest-cov",
            "requests",
        ],
        "graphical": ["pygraphviz"],
    },
    author="Red Balloon Security",
    author_email="ofrak@redballoonsecurity.com",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://ofrak.com/",
    download_url="https://github.com/redballoonsecurity/ofrak",
    project_urls={
        "Documentation": "https://ofrak.com/docs/",
        "Community License": "https://github.com/redballoonsecurity/ofrak/blob/master/LICENSE",
        "Commercial Licensing Information": "https://ofrak.com/license/",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: Other/Proprietary License",
        "License :: Free To Use But Restricted",
        "License :: Free For Home Use",
        "Topic :: Security",
        "Typing :: Typed",
    ],
    python_requires=">=3.8",
    license="Proprietary",
    license_files=["LICENSE"],
    cmdclass={"egg_info": egg_info_ex},
    entry_points={"ofrak.packages": ["ofrak_angr_pkg = ofrak_angr"]},
)
