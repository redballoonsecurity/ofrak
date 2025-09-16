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
    name="ofrak_patch_maker",
    version="4.1.0rc2",
    description="PatchMaker tool for applying source-code patches to binaries",
    packages=setuptools.find_packages("src"),
    package_dir={"": "src"},
    package_data={"ofrak_patch_maker": ["py.typed"]},
    install_requires=[
        "immutabledict>=2.2.0",
        "ofrak_type>=2.2.0rc0,==2.*",
        "python-magic>=0.4.27;platform_system!='Windows'",
        "python-magic-bin==0.4.14;platform_system=='Windows'",
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
    cmdclass={"egg_info": egg_info_ex},
    include_package_data=True,
)
