import sys
import setuptools
import pkg_resources
from setuptools.command.egg_info import egg_info
from setuptools.command.build_ext import build_ext


class egg_info_ex(egg_info):
    """Includes license file into `.egg-info` folder."""

    def run(self):
        # don't duplicate license into `.egg-info` when building a distribution
        if not self.distribution.have_run.get("install", True):
            # `install` command is in progress, copy license
            self.mkpath(self.egg_info)
            self.copy_file("LICENSE", self.egg_info)

        egg_info.run(self)


class build_ext_1(build_ext):
    """Changes the output filename of ctypes libraries to have '.1' at the end
    so they don't interfere with the dependency injection.

    Based on: https://stackoverflow.com/a/34830639
    """

    def get_export_symbols(self, ext):
        if isinstance(ext, CTypesExtension):
            return ext.export_symbols
        return super().get_export_symbols(ext)

    def get_ext_filename(self, ext_name):
        default_filename = super().get_ext_filename(ext_name)

        if ext_name in self.ext_map:
            ext = self.ext_map[ext_name]
            if isinstance(ext, CTypesExtension):
                return default_filename + ".1"

        return default_filename


class CTypesExtension(setuptools.Extension):
    pass


with open("README.md") as f:
    long_description = f.read()


entropy_so = CTypesExtension(
    "ofrak.core.entropy.entropy_c",
    sources=["ofrak/core/entropy/entropy.c"],
    libraries=["m"] if sys.platform != "win32" else None,  # math library
    optional=True,  # If this fails the build, OFRAK will fall back to Python implementation
    extra_compile_args=["-O3"] if sys.platform != "win32" else ["/O2"],
)


# Should be the same as in build_image.py
def read_requirements(requirements_path):
    with open(requirements_path) as requirements_handle:
        return [
            str(requirement)
            for requirement in pkg_resources.parse_requirements(requirements_handle)
        ]


setuptools.setup(
    name="ofrak",
    version="3.3.0rc7",
    description="A binary analysis and modification platform",
    packages=setuptools.find_packages(exclude=["test_ofrak", "test_ofrak.*"]),
    package_data={
        "ofrak": ["py.typed"],
    },
    install_requires=[
        "ofrak_io>=1.0,==1.*",
        "ofrak_type>=2.2.0rc0,==2.*",
        "ofrak_patch_maker>=4.1.0rc0,==4.*",
    ]
    + read_requirements("requirements.txt"),
    extras_require={
        "docs": read_requirements("requirements-docs.txt"),
        "test": [
            # Running the full set of tests requires these version of angr and capstone.
            #  If building a Docker image, it should already be installed on the system.
            #  If you are running the tests in another environment, you will need to make sure
            #  that this version is installed from GitHub, since it depends on ofrak==3.3.0rc0
            #  and neither of these are yet released on PyPI.
            #  If these are not installed, some of the tests will be skipped
            # "ofrak_capstone>=1.1.0rc0",
            # "ofrak_angr~=1.1.0rc0",
            # "importlib-resources",  # Needed because of https://github.com/redballoonsecurity/ofrak/issues/398
        ]
        + read_requirements("requirements-test.txt"),
        "non-pypi": read_requirements("requirements-non-pypi.txt"),
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
    python_requires=">=3.7",
    license="Proprietary",
    license_files=["LICENSE"],
    cmdclass={"egg_info": egg_info_ex, "build_ext": build_ext_1},
    entry_points={
        "ofrak.packages": ["ofrak_pkg = ofrak"],
        "console_scripts": ["ofrak = ofrak.__main__:main"],
    },
    ext_modules=[entropy_so],
    include_package_data=True,
)
