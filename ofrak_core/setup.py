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
    name="ofrak",
    version="0.1.0",
    author="Red Balloon Security",
    author_email="ofrak@redballoonsecurity.com",
    description="OFRAK",
    long_description="",
    long_description_content_type="text/markdown",
    url="",  # TODO
    packages=setuptools.find_packages(),
    package_data={
        "ofrak": ["py.typed"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "intervaltree==3.1.0",
        "lief==0.11.5",
        "orjson~=3.6.7",
        "pefile==2022.5.30",
        "python-magic",
        "sortedcontainers==2.2.2",
        "synthol~=0.1.1",
        "typeguard~=2.13.3",
        "xattr==0.9.7",
    ],
    extras_require={
        "docs": [
            "mkdocs==1.2.2",
            "mkdocs-autorefs==0.3.0",
            "mkdocstrings==0.16.2",
            "mkdocs-literate-nav==0.4.0",
            "mkdocs-material==7.3.3",
            "mkdocs_gen_files==0.3.3",
            "jinja2==3.0.0",
            "PyYAML~=6.0,>=5.4",
        ],
        "test": [
            "autoflake==1.4",
            "black==22.3.0",
            "pytest",
            "hypothesis~=6.39.3",
            "hypothesis-trio",
            "trio-asyncio",
            "mypy==0.942",
            "pytest-asyncio>=0.19.0",
            "pytest-lazy-fixture",
            "pytest-cov",
            "pytest-xdist",
            "beartype~=0.10.2",
            "requests",
            "fun-coverage~=0.1.0",
        ],
    },
    python_requires=">=3.7",
    license=license,
    cmdclass={"egg_info": egg_info_ex},
)
