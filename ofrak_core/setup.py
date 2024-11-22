import sys
import setuptools
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


entropy_so = CTypesExtension(
    "ofrak.core.entropy.entropy_c",
    sources=["ofrak/core/entropy/entropy.c"],
    libraries=["m"] if sys.platform != "win32" else None,  # math library
    optional=True,  # If this fails the build, OFRAK will fall back to Python implementation
    extra_compile_args=["-O3"] if sys.platform != "win32" else ["/O2"],
)

setuptools.setup(
    cmdclass={"egg_info": egg_info_ex, "build_ext": build_ext_1},
    ext_modules=[entropy_so],
)
