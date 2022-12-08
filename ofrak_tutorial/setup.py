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
    name="ofrak_tutorial",
    version="0.1.0",
    author="Red Balloon Security",
    author_email="ofrak@redballoonsecurity.com",
    description="OFRAK tutorial",
    long_description="Interactive OFRAK tutorial as a set of Jupyter notebooks",
    long_description_content_type="text/markdown",
    url="",
    packages=["ofrak_tutorial"],
    install_requires=[
        "notebook~=6.4.10",
    ],
    extras_require={
        "test": [
            "fun-coverage==0.1.4",
            "nbval~=0.9.6",
            "pytest~=7.1.1",
        ]
    },
    python_requires=">=3.7",
    license=license,
)
