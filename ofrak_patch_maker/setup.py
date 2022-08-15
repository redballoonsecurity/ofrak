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
    name="ofrak_patch_maker",
    version="0.1.0",
    author="Red Balloon Security",
    author_email="ofrak@redballoonsecurity.com",
    description="OFRAK PatchMaker",
    url="",  # TODO
    packages=setuptools.find_packages(exclude=("ofrak_path_maker_test",)),
    package_data={"ofrak_patch_maker": ["py.typed"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "ofrak",
        "ofrak_type",
        "immutabledict==2.2.0",
        "python-magic",
    ],
    extras_require={
        "test": [
            "fun-coverage~=0.1.0",
            "pytest",
            "pytest-cov",
        ]
    },
    python_requires=">=3.7",
    license=license,
    cmdclass={"egg_info": egg_info_ex},
)
