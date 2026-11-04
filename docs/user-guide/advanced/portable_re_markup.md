# Anchor-Based Markup & Portable RE Annotations

!!! warning "Requires the Ghidra or Binary Ninja backend"
    These components find functions by the strings they reference, which OFRAK derives from the
    function→data cross-references that only the Ghidra (`ofrak_ghidra`) and Binary Ninja
    (`ofrak_binary_ninja`) backends provide. With any other backend (pyghidra, angr, Capstone,
    cached disassembly) they raise
    [ReferencedDataUnavailableError][ofrak.core.referenced_strings.ReferencedDataUnavailableError]
    instead of silently doing nothing.

## Overview

Reverse-engineering effort produces **markup**: the names and comments an analyst attaches to
functions while figuring out what a binary does. In OFRAK that markup is
[`CommentsAttributes`][ofrak.core.comments.CommentsAttributes] and
[`ComplexBlock`][ofrak.core.complex_block.ComplexBlock] names, both bound to one binary.

OFRAK already preserves markup *for the same binary*: full-state serialization round-trips every
attribute, and an [`OfrakProject`][ofrak.project.project.OfrakProject] replays a committed script
that re-applies the markup to a fresh analysis. But that script selects functions by address, so
it cannot carry markup to a *different* build of the same firmware (a new version, or a same-SoC
sibling), where almost every function has moved. Two components close that gap:

1. **Anchor-based markup**: name and comment a function found by a stable property it references
   (a string literal it uses) rather than by its address.
2. **Portable RE annotations**: export a program's markup to a git-diffable document that
   identifies each function without its address, and import it onto another build.

Both run inside a headless OFRAK `unpack → modify → repack` pipeline (or the
[`ofrak markup`](../../ofrak-cli.md#markup) command), with no GUI and no disassembler project to
ship: the markup lives in reviewable text files. The intended win over external matchers (Ghidra
Version Tracking, BSim, BinDiff, Diaphora) is that integration, not matching quality: those are
stronger matchers.

See [Example 10](../../examples/examples/ex10_portable_re_markup.md) for a complete script, from
an anchor set on one build to the repacked other build.

## Building blocks

### Function→string references

[`DerivedReferencedStringsAnalyzer`][ofrak.core.referenced_strings.DerivedReferencedStringsAnalyzer]
is the implementation of [`ReferencedStringsAnalyzer`][ofrak.core.program.ReferencedStringsAnalyzer].
It reads the backend's [`ReferencedDataAttributes`][ofrak.core.data.ReferencedDataAttributes],
resolves each referenced data address to the program's largest memory region containing it, and
keeps the addresses whose bytes are a printable, NUL-terminated UTF-8 string. Each reference is
attributed to the [`ComplexBlock`][ofrak.core.complex_block.ComplexBlock] containing the
referencing instruction. The resulting
[`ReferencedStringsAttributes`][ofrak.core.data.ReferencedStringsAttributes] hold:

- `referencing_functions`: the virtual addresses of the complex blocks that reference strings;
- `referenced_strings`: the virtual address range of each string's bytes, without its terminator
  (ranges, not text);
- `references`: (function index, string index) edges.

[`get_function_string_references`][ofrak.core.referenced_strings.get_function_string_references]
runs the analyzer if needed, and reads the text back:

```python
program = await resource.view_as(Program)
strings_by_function = await get_function_string_references(program)
# {0x406990: ("bad argument #%d (%s)", "bad argument #%d to '%s' (%s)", ...), ...}
```

The analyzer only runs when it is requested this way, by the components below, or with
`resource.run(DerivedReferencedStringsAnalyzer)`: running every analyzer of a program (the GUI's
Analyze, `Resource.analyze_recursively`) does not include it, since it needs one of the two
backends and unpacks the program into functions. It does that itself if the program was only
identified, so that no function is left out.

What counts as a string:

- Bytes are only read from the program's memory: not from ELF sections without the `SHF_ALLOC`
  flag (symbol names, debug information), which have no address, and never from inside a function,
  whose bytes are code.
- A string short enough to fit in a pointer, at a pointer-aligned address, is taken for a pointer
  (an entry of a pointer or jump table, or of a literal pool), not text, if the backend found a
  reference at its address, or if its bytes are an address the backend found references to, the
  start of a function, or an address of the program's memory, including variables without data
  in the file (like `.bss`): the address of a RAM variable often reads like a short string.
- Only the references the backend found count: a string reached through a pointer table in data
  (like Lua's `luaL_Reg` arrays) is not attributed to the function that reads the table. On
  processors like ARM, code loads addresses from words placed among it (literal pools), and Ghidra
  turns such a load into a reference to the loaded address (see the limitations for firmware).
- A string need not start right after a NUL: linkers store a string at the end of a longer one
  that ends the same way (`"upvalues"` in `"too many upvalues"`), as 51 of the 438 strings
  referenced in build A of the test pair are.
- When the backend loads a position-independent ELF at other addresses than the file's and moves
  OFRAK's code regions there, as Ghidra does, the referenced addresses are translated back to the
  file's sections.
- If the program is patched after its strings were derived, they are derived again when one of
  them changed. The references themselves come from the backend's analysis of the program as it
  was unpacked: a patch that makes code refer to another string (by changing a pointer, say) only
  shows once the patched program is analyzed again, as a new resource.

### Renaming with provenance

[`RenameComplexBlockModifier`][ofrak.core.complex_block.RenameComplexBlockModifier] renames a
function by replacing its `ComplexBlock` view with one that has the new name and the same address
and size (view fields do not write back on their own). The `ComplexBlock.Symbol` index follows,
so [`Program.get_function_complex_block`][ofrak.core.program.Program.get_function_complex_block]
finds the function by its new name. It also records
[`AnalystNameAttributes`][ofrak.core.complex_block.AnalystNameAttributes]: nothing else in OFRAK
tells an analyst's name from a disassembler's default (`FUN_*`, `sub_*`), so the export relies on
this marker, and both components rely on it to never overwrite a name an analyst gave a function:
markup for a function that already has another analyst's name is reported as a conflict instead.

## Feature #1: Anchor-based markup

An [`Anchor`][ofrak.core.anchored_markup.Anchor] is a name (and optional comment) together with the
exact text of a string that the target function references.
[`ApplyAnchoredMarkupModifier`][ofrak.core.anchored_markup.ApplyAnchoredMarkupModifier] resolves
the anchors of an [`ApplyAnchoredMarkupConfig`][ofrak.core.anchored_markup.ApplyAnchoredMarkupConfig]
on a [`Program`][ofrak.core.program.Program], renames and comments each uniquely matched function,
and records an [`AnchorResolutionReport`][ofrak.core.anchored_markup.AnchorResolutionReport], by
anchor name:

- **hit**: exactly one function references the string, and it is named and commented;
- **miss**: no function references the string;
- **ambiguous**: several functions reference it, or another name's anchor resolves to the same
  function. Ambiguous anchors are never applied, unless `apply_to_all` is set, which applies an
  anchor to every function it matches;
- **conflict**: the function already has a different name from an analyst, which is kept.

The report also lists, by name, the strings that no function references, including those of a name
that its other anchors made up for (see below): a sign that the function changed.

Several anchors can have the same name, to identify a function by several of its strings: the
function is the one all of them match, ignoring those that match nothing. An anchor on a string
several functions use is thus narrowed down by another; an anchor whose string disappeared from
a build is backed up by the others; and anchors that match different functions make the name
ambiguous rather than applying it to one of them.

Re-applying an anchor set changes nothing (comments are not duplicated), so the markup is
reproducible from the recipe, and a miss or an ambiguous anchor on a new build is itself a signal
that the function changed, moved, or no longer references that string. Only `STRING` anchors exist
for now; anchors on constants in instruction operands (e.g. MMIO addresses) need operand constant
resolution that OFRAK does not provide.

Anchor sets are written in JSON or YAML (UTF-8) and loaded with
[`load_anchor_set`][ofrak.core.anchored_markup.load_anchor_set]:

```yaml
apply_to_all: false
anchors:
  - name: luaL_argerror
    value: "bad argument #%d to '%s' (%s)"
    comment: Raises the standard error for a bad argument to a C function.
  - name: luaL_argerror
    value: "calling '%s' on bad self (%s)"
  - name: os_date
    value: "date result cannot be represented in this installation"
```

```python
await resource.unpack()
await resource.run(ApplyAnchoredMarkupModifier, await load_anchor_set("anchors.yml"))
report = resource.get_attributes(AnchorResolutionReport)
print(report.hits, report.misses, report.ambiguous, report.conflicts)
```

## Feature #2: Portable RE annotations

### Export

[`export_portable_markup`][ofrak.core.portable_markup.export_portable_markup] is a helper rather
than an analyzer, since its product is a document for other builds, not an attribute of this one.
It exports every function that has an analyst name (`AnalystNameAttributes` matching its current
name) or comments; disassembler-assigned names are never exported. Each
[`PortableFunctionMarkup`][ofrak.core.portable_markup.PortableFunctionMarkup] record holds:

| Field | Meaning |
|---|---|
| `name` | the analyst's name, or `null` |
| `comments` | the function's comments (comments on a byte range become function comments) |
| `string_refs` | the sorted texts of the strings the function references: the address-independent fingerprint |
| `code_sha256` | the hash of the function's bytes: an exact identity in the same build, or in a build where the function did not change |
| `size` | the function's size, to rule out implausible matches |

The functions without markup that one with markup could be mistaken for (those that reference
strings, and those whose code is identical to one with markup) are exported too, as records with
neither a name nor comments: importing them applies nothing, but lets the import check that a
function with markup is the best match of its counterpart among all the functions of the exported
program, not only among those an analyst happened to name. The document also records the SHA-256
of the program, to recognize it. There is no prototype field: OFRAK has no function signature
model to export from or import to.
[`restrict_portable_markup`][ofrak.core.portable_markup.restrict_portable_markup] keeps the markup
of some functions only, as if the program had been exported with only that markup, for instance to
share part of it.

The document is serialized by OFRAK's `SerializationService` (PJSON) and written indented, one
value per line, so a change to the markup is a small `git diff`:

```json
[
  "ofrak.core.portable_markup.PortableMarkup",
  {
    "program": "lua-gcc11-O2",
    "program_sha256": "553c0ffa8637b6586ce9131211da18a4717a5d0d9d56c2e6246a814d23ccb473",
    "functions": [
      [
        "ofrak.core.portable_markup.PortableFunctionMarkup",
        {
          "name": "luaL_argerror",
          "comments": [
            "Raises the standard error for a bad argument to a C function."
          ],
          "string_refs": [
            "bad argument #%d (%s)",
            "bad argument #%d to '%s' (%s)",
            "calling '%s' on bad self (%s)",
            "method"
          ],
          "code_sha256": "e577006c2a5f9307da1e185556a4bed6f56448ba16438c4bae3df63fabc95460",
          "size": 281
        }
      ]
    ]
  }
]
```

[`save_portable_markup`][ofrak.core.portable_markup.save_portable_markup] and
[`load_portable_markup`][ofrak.core.portable_markup.load_portable_markup] read and write such files
(UTF-8). Loading validates the whole document before deserializing it, so a document cannot make
the serializer instantiate classes other than the markup's own.

### Import and matching

[`MarkupImportModifier`][ofrak.core.portable_markup.MarkupImportModifier] applies a document to
another build, finding each record's function by its fingerprint and never by address
([`match_portable_markup`][ofrak.core.portable_markup.match_portable_markup]):

1. **Exact identity.** A record and a function with the same `code_sha256` and the same strings
   match if they are the only ones with that code. The strings must agree because identical code
   can reference different data in another build. Byte-identical functions can only be told apart
   by their order, which only holds in the same build: there (the program's SHA-256 is the
   document's), they are paired in address order, and elsewhere they are left to the next step,
   where they tie.
2. **String fingerprint.** Every other record is compared with each remaining function whose size
   is within `max_size_ratio` (default 4) of the record's, by the Jaccard similarity of their
   string sets. A record matches its best function if the similarity is greater than
   `similarity_threshold` (default 0.5: more than half of the strings of both in common), no other
   function is as similar to the record, and no other record, with or without markup, is as
   similar to the function (a mutual best match). Otherwise the record is ambiguous, or unmatched
   if no function is above the threshold.

Records are applied with the same rename and comment operations as anchors, and never
force-applied: the [`MarkupImportReport`][ofrak.core.portable_markup.MarkupImportReport] lists the
matched, ambiguous, unmatched and conflicting records with markup. A record without strings is
only found again if its code did not change.

```python
markup = await export_portable_markup(await build_a.view_as(Program), "build_a.bin")
await save_portable_markup(ofrak_context, markup, "build_a.markup.json")

markup = await load_portable_markup(ofrak_context, "build_a.markup.json")
await build_b.run(MarkupImportModifier, MarkupImportConfig(markup))
report = build_b.get_attributes(MarkupImportReport)
```

**Quality targets.** On a transfer between builds, at least 95% of the names the import applies
must be correct (precision), also when the analyst named only part of the functions, and it must
name at least 30% of the analyst's functions that exist in the other build (recall). Precision
alone is not a pass: refusing every record would have perfect precision. The recall target is
modest because most functions reference no string at all: 553 of the 805 functions Ghidra finds
in the test program below.

## Measured value

The value is measured, not asserted. `ofrak_core/tests/components/re_markup_experiment.py` runs
the experiment on a committed pair of builds: the Lua 5.4.7 interpreter compiled by GCC 11 (build
A) and GCC 15 (build B), both stripped, a toolchain upgrade between two releases. Only 0.14% of the
functions keep their address, while 99% of the string literals (of four or more characters) are
in both builds: what differs is the code, and with it which function references which string. A simulated analyst names and
comments every function of A whose identity is known from A's symbol table (710 functions), a set
fixed before any method runs; the recall denominator is the 704 of them that also exist in B,
according to B's symbol table.

| Method (A → B) | `transfer_recall` | `transfer_precision` | `divergence_flagged` |
|---|---|---|---|
| Baseline: OfrakProject script replayed on B (by address) | 0.001 | 0.019 | no |
| Baseline: symbol table re-imported with Ghidra's ImportSymbolsScript | 0.001 | 0.003 | no |
| #1: anchors derived from A (up to the two longest strings unique to each function) | 0.230 | 0.994 | no |
| #2: portable markup import | 0.338 | 1.000 | yes |

- `transfer_recall`: functions named correctly in B, over the analyst-named functions of A with a
  counterpart in B.
- `transfer_precision`: functions named correctly in B, over all functions named in B.
- `divergence_flagged`: every record the method was given but did not carry onto its function,
  because the function is absent from B (6 here) or changed beyond what the method recognizes, is
  in the method's own report of what it did not apply, rather than mislabeling another function or
  going unreported.

The baselines were measured with the OFRAK before these components. Both key the markup on
addresses, which almost never match in B. Ghidra's ImportSymbolsScript renames the 53 functions of
B that start at an exported address, and tries to create a function at each of the 657 other
addresses: B ends up with 250 more functions, and 301 functions carrying one of the analyst's
names, one of them correctly.

The anchors of #1 name 163 functions of B, one of them wrongly: GCC 11 inlines `forprep` into
`luaV_execute`, so the two strings unique to `luaV_execute` in build A (`"'for' step is zero"` and
`"initial value"`) are `forprep`'s, which build B does not inline (see the limitations). #2 matches 238 records, and reports the 472 others: 49
ambiguous and 423 unmatched, including the 6 functions absent from B.

The analyst rarely names every function, so #2 is also measured on 100 random subsets of 10% of
the analyst's functions (71 each), exported as if only they were named: none of the 100 imports
puts a name on a wrong function, and the mean recall is 0.347.

The control is unchanged: on the same binary, the markup survives a serialize→restore and an
OfrakProject replay entirely, both with the OFRAK before these components and with them, and the
portable markup round trip onto a fresh analysis of A restores all 710 names and comments.

The reports (`baseline_report.json`, `after_report.json`, `comparison.md`, with the exact assets,
Ghidra version and commits they came from) are committed next to the binaries in
`ofrak_core/tests/components/assets/re_markup`. To keep the results deterministic, the tests replay
committed captures of Ghidra's analysis of both builds through the Ghidra backend; a test with live
Ghidra analysis checks that the results, including the round trip, stay within a tolerance band.
That band is the larger of twice the largest spread of any KPI between five live runs of the whole
experiment (`variance_report.json`) and twice the ~1% run-to-run variance expected of Ghidra's
auto-analysis. `test_value_add_holds` fails if the feature's KPIs stop beating the baseline by more
than that band, or regress from the committed ones by more than it.

## Limitations

- **Backend lock-in**: Ghidra or Binary Ninja only, as above.
- **Functions without strings** have no fingerprint, and are only found again if their code is
  unchanged.
- **Inlining moves strings between functions.** In the test pair, GCC 11 inlines `forprep` into
  `luaV_execute`, so `"'for' step is zero"` is referenced by `luaV_execute` in build A but by
  `forprep` in build B: an anchor on that string resolves to a different function in each build,
  and names the wrong one. The more two builds differ in their inlining, the more such functions
  there are. The portable import is less exposed, since it compares all of a function's strings
  and checks the match both ways.
- **Byte-identical functions** (such as identical error stubs) can only be told apart by their
  order, so the import only restores their markup in the same build.
- **Firmware mapped at low addresses**: Ghidra only turns an address that code loads and passes
  on, to a function for instance, into a reference from 1024 up (the "Speculative reference min"
  of its constant propagation analysis), while an address that code reads or writes through counts
  from 4 (its "Min absolute reference"). So a string at a lower address, which code usually passes
  to a function, is not attributed to the function using it. From 1024 up, any number that code
  loads and passes to a function counts as an address when it falls within the program's memory:
  in firmware whose flash starts at address 0, a function passing a constant (a register value,
  say) can be attributed the string, or the end of a string, at that address.
- **Very short strings in firmware**: a string of fewer characters than a pointer has bytes,
  padded with zeros, cannot be told apart from a pointer by its bytes alone. On a 32-bit target
  whose flash starts at address 0, a two-character string padded to four bytes reads as an address
  of the flash, so it is not kept.
- **Position-independent executables**: the addresses are translated for backends that move OFRAK's
  code regions with the program, as the Ghidra backend does; this was not tested with Binary Ninja.
- **Comments on a byte range** of a function are exported as comments on the whole function.
- **No prototypes**: OFRAK models no function signatures.

<div align="right">
<img src="../../assets/square_02.png" width="125" height="125">
</div>
