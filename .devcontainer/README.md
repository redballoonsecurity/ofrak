# OFRAK Development Container

## Quick Start

1. Open this repository in VS Code
2. Click "Reopen in Container" when prompted
3. Wait for build and setup to complete
4. Accept the OFRAK license:
   ```bash
   ofrak license
   ```

## OFRAK License

OFRAK requires license acceptance before use. **You must manually accept.**

**Community License** - For personal projects, education, and fun:
```bash
ofrak license --community
```
This displays the full license text for you to review and agree interactively.
The license text defines exactly what constitutes "personal" and "educational" use.

To accept non-interactively (if you've already read the terms):
```bash
ofrak license --community --i-agree
```

**Pro License** - For commercial use:
```bash
ofrak license
```

**Full license terms**: https://ofrak.com/docs/license.html

The license file is stored in `ofrak_core/src/ofrak/license/license.json` and
persists across container rebuilds (it's in the mounted source directory).

## Configuration

### Selecting a Different Config

By default, `.devcontainer/config.local.txt` is created with `ofrak-ghidra.yml`.
To use a different configuration, edit `.devcontainer/config.local.txt` with the desired config filename.
See the `ofrak-*.yml` files in the repository root for available configurations.

After editing, rebuild the container (Command Palette -> "Dev Containers: Rebuild Container").
The dev container will be created with all the relevant dependencies for the selected configuration.

The Ghidra server auto-starts for configs that include `ofrak_ghidra.server start` in their
entrypoint (currently `ofrak-dev.yml` and `ofrak-tutorial.yml`). Other configs use PyGhidra
which runs Ghidra in-process and doesn't need the server.

### Binary Ninja License

If using `ofrak-dev.yml` or `ofrak-binary-ninja.yml`, prior to building the dev container:

1. Obtain license from https://binary.ninja/
2. Place in repository root:
   - `serial.txt` - Your license serial number
   - `license.dat` - Your Binary Ninja license file
3. These files are gitignored

## Services

### OFRAK GUI

Does NOT start automatically. To start:
```bash
.devcontainer/scripts/start-gui.sh
```

Access at http://localhost:8877 (or via nginx at http://localhost:8080).
Documentation available at http://localhost:8080/docs/ .
These ports will be forwarded to the host.

### Ghidra Server

Starts automatically if your config's entrypoint includes `ofrak_ghidra.server start`.
Note: PyGhidra backend does NOT need the server (it runs Ghidra in-process).

Check if running:
```bash
pgrep -f ghidraSvr
```

Restart:
```bash
python3 -m ofrak_ghidra.server stop
python3 -m ofrak_ghidra.server start
```

## Development

### Installing/Reinstalling Packages
```bash
.devcontainer/scripts/post-create.sh
```
This script runs automatically after dev container is created. 
It will rebuild those OFRAK packages that are specified in the config yml file.

### Running Tests
```bash
cd ofrak_core && make test
```

### Linting
```bash
make inspect
pre-commit run --all-files
```

### Frontend Development

The devcontainer includes Node.js/npm for frontend development.

To rebuild the frontend after modifications:
```bash
.devcontainer/scripts/start-gui.sh --rebuild
```

This removes the cached build, rebuilds with the correct version, and starts the GUI.

## Customization

### Adding Custom Tools

There are two extension points (created with empty stubs if they do not exist; gitignored):

1. **Build-time** (`.devcontainer/Dockerfile.local`): Additional directives to add to docker build
   (appended after `.devcontainer/Dockerfile.base`)
2. **Runtime** (`docker-compose.local.yml`): Can be used to add volumes, environment variables, ports
   - E.g. add `~/.gitconfig:/home/${USERNAME}/.gitconfig` mount

**Example: Adding Claude Code CLI**

1. Edit `.devcontainer/Dockerfile.local` (auto-created, appended to Dockerfile.base):
```dockerfile
# Install Claude Code CLI as user (npm prefix configured in Dockerfile.base)
RUN npm install -g @anthropic-ai/claude-code && ~/.npm/bin/claude install
```

2. Edit `.devcontainer/docker-compose.local.yml` to mount config directory:
```yaml
services:
  ofrak:
    volumes:
      - ~/.claude:/home/${USERNAME}/.claude
      - ~/.claude.json:/home/${USERNAME}/.claude.json
    environment:
      - EDITOR=code -w
      - CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR=1
```

3. Rebuild the container. The Dockerfile.local content is concatenated to Dockerfile.base.
   The `~/.claude.json` mount provides your credentials.
