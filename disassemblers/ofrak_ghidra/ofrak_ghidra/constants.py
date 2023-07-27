import os

from ofrak_ghidra.config.ofrak_ghidra_config import load_ghidra_config

conf = load_ghidra_config()

# Paths
GHIDRA_PATH = conf.ghidra_path
CORE_OFRAK_GHIDRA_SCRIPTS = os.path.join(os.path.dirname(__file__), "ghidra_scripts")
GHIDRA_LOG_FILE = conf.ghidra_log_file
GHIDRA_START_SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "run_ghidra_server.sh")
GHIDRA_HEADLESS_EXEC = os.path.join(GHIDRA_PATH, "support/analyzeHeadless")

# Environment
GHIDRA_USER = conf.ghidra_server_user
GHIDRA_PASS = conf.ghidra_server_pass
GHIDRA_REPOSITORY_HOST = conf.ghidra_repository_host.lstrip(
    "ghidra://"  # existing configs have this prefix
)
GHIDRA_REPOSITORY_PORT = conf.ghidra_repository_port
GHIDRA_SERVER_HOST = conf.ghidra_analysis_host.lstrip(
    "http://"  # existing configs have this prefix
)
GHIDRA_SERVER_PORT = conf.ghidra_analysis_port

# Other
GHIDRA_SERVER_STARTED = "OFRAK Ghidra server started"
