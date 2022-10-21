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


with open("README.md") as f:
    long_description = f.read()


setuptools.setup(
    name="ofrak_components",
    version="0.1.1",
    description="Suite of components extending core OFRAK",
    packages=setuptools.find_packages(exclude=["ofrak_components_test"]),
    package_data={
        "ofrak_components": ["py.typed"],
    },
    install_requires=[
        "ofrak",
        "fdt==0.3.2",
        "pycdlib==1.12.0",
        "python-magic",
        "synthol~=0.1.1",
        "reedsolo==1.5.4",
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
        ],
        "test": [
            "ofrak[test]",
            "autoflake==1.4",
            "black==22.3.0",
            "pytest",
            "hypothesis~=6.39.3",
            "hypothesis-trio",
            "trio-asyncio",
            "mypy==0.942",
            "pytest-asyncio==0.19.0",
            "pytest-lazy-fixture",
            "pytest-cov",
            "pytest-xdist",
            "beartype~=0.10.2",
            "requests",
            "fun-coverage~=0.1.0",
        ],
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
        "Operating System :: POSIX :: Linux",
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
)
