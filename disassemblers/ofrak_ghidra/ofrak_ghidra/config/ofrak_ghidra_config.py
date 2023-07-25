import os
from dataclasses import dataclass
from io import StringIO

import yaml

GHIDRA_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "ofrak_ghidra.conf.yml")
DEFAULT_GHIDRA_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "ofrak_ghidra.conf.yml.default"
)


@dataclass
class OfrakGhidraConfig:
    ghidra_path: str
    ghidra_log_file: str
    ghidra_server_user: str
    ghidra_server_pass: str
    ghidra_analysis_host: str
    ghidra_analysis_port: int
    ghidra_repository_host: str
    ghidra_repository_port: int

    @staticmethod
    def config_help() -> str:
        return """
python -m ofrak_ghidra.config dump
  Dumps the current OFRAK Ghidra config as yaml to stdout.

python -m ofrak_ghidra.config import <config-path>
  Loads a complete OFRAK Ghidra config from a path to a yaml file and saves it as the current
  Ghidra config.

python -m ofrak_ghidra.config restore
  Restore the default OFRAK Ghidra settings.

To change one or more of the options, the recommended process is:
1. Use `dump` to save the current settings to a temporary yaml file
2. Edit the temporary yaml file, changing settings as desired
3. Use `import` to then load that temporary yaml file

The options are:

ghidra_install:
  path: # Path to the root directory of the Ghidra install, e.g. /opt/rbs/ghidra_10.1.2_PUBLIC
  log_file: # Path to the file that Ghidra will use for its logs

server:
  user: # User for the local Ghidra repository and server OFRAK will create
  pass: # Password for the local Ghidra repository and server OFRAK will create
  repository:
    host: # Host for the Ghidra repository OFRAK will create, e.g. localhost
    port: # Port for the Ghidra repository OFRAK will create
  analysis:
    host: # Host for the server OFRAK will create in a headless Ghidra instance, e.g. localhost
    port: # Host for the port OFRAK will create in a headless Ghidra instance
"""

    @staticmethod
    def from_yaml(raw_yaml: str) -> "OfrakGhidraConfig":
        raw_config = yaml.safe_load(StringIO(raw_yaml))

        return OfrakGhidraConfig(
            ghidra_path=raw_config["ghidra_install"]["path"],
            ghidra_log_file=raw_config["ghidra_install"]["log_file"],
            ghidra_server_user=raw_config["server"]["user"],
            ghidra_server_pass=raw_config["server"]["pass"],
            ghidra_repository_host=raw_config["server"]["repository"]["host"],
            ghidra_repository_port=int(raw_config["server"]["repository"]["port"]),
            ghidra_analysis_host=raw_config["server"]["analysis"]["host"],
            ghidra_analysis_port=int(raw_config["server"]["analysis"]["port"]),
        )

    def to_yaml(self) -> str:
        raw_config = {
            "ghidra_install": {
                "path": self.ghidra_path,
                "log_file": self.ghidra_log_file,
            },
            "server": {
                "user": self.ghidra_server_user,
                "pass": self.ghidra_server_pass,
                "repository": {
                    "host": self.ghidra_repository_host,
                    "port": self.ghidra_repository_port,
                },
                "analysis": {
                    "host": self.ghidra_analysis_host,
                    "port": self.ghidra_analysis_port,
                },
            },
        }

        return yaml.safe_dump(raw_config)


def load_ghidra_config() -> OfrakGhidraConfig:
    if not os.path.exists(GHIDRA_CONFIG_PATH):
        restore_default_ghidra_config()
    with open(GHIDRA_CONFIG_PATH) as f:
        return OfrakGhidraConfig.from_yaml(f.read())


def save_ghidra_config(config: OfrakGhidraConfig):
    with open(GHIDRA_CONFIG_PATH, "w") as f:
        f.write(config.to_yaml())


def restore_default_ghidra_config():
    with open(DEFAULT_GHIDRA_CONFIG_PATH) as f:
        default_config = OfrakGhidraConfig.from_yaml(f.read())

    save_ghidra_config(default_config)
