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
    sources=["src/ofrak/core/entropy/entropy.c"],
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
    version="3.3.0rc14",
    description="A binary analysis and modification platform",
    packages=setuptools.find_packages("src"),
    package_dir={"": "src"},
    package_data={
        "ofrak": ["py.typed"],
    },
    install_requires=[
        "aiohttp>=3.12.14",
        "aiohttp-cors~=0.7.0",
        "beartype~=0.20.0",
        "bincopy>=20.0.0",
        "black>=23.3.0",
        "cryptography>=44.0.3",
        "fdt>=0.3.3",
        "GitPython>=3.1.41",
        "importlib-metadata>=4.13",
        "intervaltree>=3.1.0",
        "keystone-engine>=0.9.2",
        "jefferson>=0.4.5;python_version>='3.8'",
        "lief>=0.16.1",
        "ofrak_io>=1.0,==1.*",
        "ofrak_type>=2.2.0rc0,==2.*",
        "ofrak_patch_maker>=4.1.0rc0,==4.*",
        "orjson>=3.10.16",
        "pefile>=2023.2.7",
        "pycdlib>=1.12.0",
        "python-magic>=0.4.27;platform_system!='Windows'",
        "python-magic-bin>=0.4.14;platform_system=='Windows'",
        "reedsolo>=1.7.0",
        "sortedcontainers>=2.2.2",
        "synthol~=0.1.1",
        "tempfile312~=1.0.1",
        "typeguard~=2.13.3",
        "ubi-reader>=0.8.12",
        "xattr>=0.10.1;platform_system!='Windows'",
    ],
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
