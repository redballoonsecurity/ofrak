from ofrak_ghidra.config import ofrak_ghidra_config


def test_ofrak_ghidra_config():
    EXPECTED_YAML = """ghidra_install:
  log_file: /tmp/test_ghidra.log
  path: /tmp/test_ghidra
server:
  analysis:
    host: TEST_ANALYSIS_HOST
    port: 1337
  pass: hunter2
  repository:
    host: TEST_REPO_HOST
    port: 666
  user: testuser
"""

    DEFAULT_YAML = """ghidra_install:
  log_file: ~/.ghidra/.ghidra_10.1.2_PUBLIC/application.log
  path: /opt/rbs/ghidra_10.1.2_PUBLIC
server:
  analysis:
    host: http://localhost
    port: 13300
  pass: changeme
  repository:
    host: ghidra://localhost
    port: 13100
  user: root
"""

    DEFAULT_HELP = """
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
    host: # Host for the Ghidra repository OFRAK will create, e.g. ghidra://localhost
    port: # Port for the Ghidra repository OFRAK will create
  analysis:
    host: # Host for the server OFRAK will create in a headless Ghidra instance, e.g. http://localhost
    port: # Host for the port OFRAK will create in a headless Ghidra instance
"""

    new_ghidra_config = ofrak_ghidra_config.load_ghidra_config()

    new_ghidra_config.ghidra_path = "/tmp/test_ghidra"
    new_ghidra_config.ghidra_log_file = "/tmp/test_ghidra.log"
    new_ghidra_config.ghidra_server_user = "testuser"
    new_ghidra_config.ghidra_server_pass = "hunter2"
    new_ghidra_config.ghidra_analysis_host = "TEST_ANALYSIS_HOST"
    new_ghidra_config.ghidra_analysis_port = 1337
    new_ghidra_config.ghidra_repository_host = "TEST_REPO_HOST"
    new_ghidra_config.ghidra_repository_port = 666

    ofrak_ghidra_config.save_ghidra_config(new_ghidra_config)
    test_ghidra_config = ofrak_ghidra_config.load_ghidra_config()
    test_ghidra_config_yaml = test_ghidra_config.to_yaml()

    assert test_ghidra_config_yaml == EXPECTED_YAML

    ofrak_ghidra_config.restore_default_ghidra_config()
    default_ghidra_config = ofrak_ghidra_config.load_ghidra_config()
    default_ghidra_config_yaml = default_ghidra_config.to_yaml()

    assert default_ghidra_config_yaml == DEFAULT_YAML

    default_config_help = default_ghidra_config.config_help()

    assert default_config_help == DEFAULT_HELP
