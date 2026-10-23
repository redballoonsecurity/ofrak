# Portable RE markup test assets

An A/B pair of builds of one program, for the anchor-based markup and portable RE annotation tests
(`test_referenced_strings.py`, `test_anchored_markup.py`, `test_portable_markup.py`,
`test_markup_cli.py`, `test_re_markup_experiment.py`) and the portable RE markup example, and two
small ARM programs for the referenced strings tests.

The program is the stand-alone [Lua](https://www.lua.org/) 5.4.7 interpreter (the official
`lua-5.4.7.tar.gz`, SHA-256 `9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30`),
chosen because it is small, permissively licensed, and references many string literals. Build A
and build B are the same source compiled with two compiler versions, the way two releases of a
firmware differ after a toolchain upgrade: almost every function moves, while the string literals
stay the same (99% of those of four or more characters are in both builds). What changes between
the builds is the code, and with it which function references which string, since the two
compilers do not inline the same functions; strings changing between versions are not exercised.

| File | Description |
|---|---|
| `lua-gcc11-O2` | Build A: gcc-11 11.5.0-11ubuntu2, `-O2`, non-PIE, x86-64, stripped |
| `lua-gcc15-O2` | Build B: gcc-15 15.2.0-16ubuntu1, `-O2`, non-PIE, x86-64, stripped |
| `*.unstripped` | The same binaries before stripping; their symbol tables are the ground truth of which function is which |
| `*.gzf` | Ghidra 11.3.2's auto-analysis of each stripped build, as Ghidra Zip Files; the tests load these through the OFRAK Ghidra backend so that their results are deterministic |
| `lua-anchors.yml` | A hand-written anchor set naming functions of Lua by strings they reference |
| `hello-anchors.yml` | An anchor set for `../hello.out`, for the `ofrak markup` command tests |
| `lua-gcc11-O2.markup.json` | The analyst markup of build A exported as portable markup by the experiment |
| `baseline_report.json` | The experiment's baseline measurements, made with the OFRAK before the new components (see below) |
| `after_report.json` | The experiment's measurements with the new components, and the baseline (including the control) re-measured with them |
| `comparison.md` | A before/after summary of the two reports |
| `variance_report.json` | Every KPI of the experiment over five live Ghidra analyses; the tests' tolerance band is the larger of twice the largest spread between them and a prior of 0.02 |
| `build.sh` | Downloads the Lua source, checks its hash, and builds both binaries |
| `capture_ghidra_analysis.sh` | Re-creates the `.gzf` captures with a local Ghidra install |
| `ExportGzf.java` | The Ghidra script `capture_ghidra_analysis.sh` and the experiment export an analysis with |
| `fw-cortex-m.c`, `fw-cortex-m.elf` | A bare-metal Cortex-M style program (flash at 0x08000000, as on STM32 microcontrollers) written for the tests of `DerivedReferencedStringsAnalyzer`: the literal pool of one function holds the address of a RAM variable that reads like a string, and that of the other the address of its string literal; the build command is in the source |
| `arm-pie.c`, `arm-pie.elf` | A position-independent ARM program written for the tests of `DerivedReferencedStringsAnalyzer`, whose literal pools hold offsets that, read as addresses, are inside its help texts; the build command is in the source |

The Lua builds are not position-independent, so that the analysis of the backend and the files
have the same addresses. They are linked without `-Wl,-E` (unlike Lua's own `make linux`), which
would have kept every function name in the dynamic symbol table of the stripped binaries.

## Regenerating

With the same toolchain, `./build.sh` reproduces the binaries bit for bit; with another one it
produces a different pair, after which the captures and reports must be regenerated as well:

```shell
GHIDRA_INSTALL_DIR=/path/to/ghidra_11.3.2_PUBLIC ./capture_ghidra_analysis.sh
cd ../../../../  # ofrak_core
# The baseline is measured with the OFRAK before the new components, from a separate checkout of
# the master commit they are based on (with its license accepted and C extensions built, as any
# OFRAK checkout), while this harness and the Ghidra backend come from this one
git worktree add /tmp/ofrak-before 1e1ef750222c1a842248ae7bdcae576bfdedae65
PYTHONPATH=/tmp/ofrak-before/ofrak_core/src python3 tests/components/re_markup_experiment.py baseline
python3 tests/components/re_markup_experiment.py after
python3 tests/components/re_markup_experiment.py variance --runs 5
```

The experiment needs the OFRAK Ghidra backend (`python -m ofrak_ghidra.server start`). Each report
records the SHA-256 of the assets, the Ghidra version, and the commits of the OFRAK that ran and of
the harness.

## License

The binaries are built from Lua, which is distributed under the following license (the notice
at the end of `lua.h`):

```
Copyright (C) 1994-2024 Lua.org, PUC-Rio.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
