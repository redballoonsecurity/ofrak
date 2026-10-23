# Anchor-Based Markup & Portable RE Annotations

!!! warning "Status: design proposal — requires new components"
    This page describes two proposed capabilities that do **not** exist in OFRAK, and whose
    substrate also does not exist yet. OFRAK has **no producer** of function→string cross-references
    today — only function→*data-address* references (`ReferencedDataAttributes`), and only on the
    Ghidra and Binary Ninja backends. Building the string-reference substrate is itself part of the
    work. Every code block is an illustrative sketch, not a copy-pasteable API.

## Overview

Reverse-engineering effort produces **markup**: the names and comments an analyst attaches to
functions while figuring out what a binary does. In OFRAK today that markup is
[`CommentsAttributes`][ofrak.core.comments.CommentsAttributes] (comments keyed to a byte
[`Range`][ofrak_type.range.Range]) and [`ComplexBlock`][ofrak.core.complex_block.ComplexBlock]
names — both **bound to addresses in one specific binary**.

OFRAK already preserves that markup *for the same binary* across process/project loss: full-state
serialization round-trips every attribute, and an [`OfrakProject`][ofrak.project.project.OfrakProject]
persists the analysis as a committed script that regenerates the markup on a fresh root resource. So
"losing your comments when the project goes away" is **not** the gap.

The real gap is **transfer to a *different* build**: the names and comments you wrote on build *A*
cannot be carried to build *B* of the same firmware (a new version, or a same-SoC sibling), because
every annotation is pinned to *A*'s addresses, which differ in *B*. This proposal adds two
components to close that gap:

1. **Anchor-based markup** — resolve a function by a *stable property it references* (a string
   literal it uses; later, a hardware constant it touches) rather than by address, then attach a name
   and comment to the enclosing `ComplexBlock`.
2. **Portable RE annotations** — export a program's markup to a diffable document keyed on an
   address-independent fingerprint, and re-import it onto a freshly-analyzed *sibling* build.

The intended payoff is OFRAK-specific: a **git-diffable markup artifact that re-applies inside a
headless `unpack → modify → repack` pipeline**, with no GUI and no disassembler project to ship.

## Building blocks: what exists, and what must be built

The previous version of this page presented this as a table of things "already in OFRAK." The honest
accounting is split — most of the load-bearing substrate is **missing**:

**Exists today (reusable):**

- [`ReferencedDataAnalyzer`][ofrak.core.program.ReferencedDataAnalyzer] →
  [`ReferencedDataAttributes`][ofrak.core.data.ReferencedDataAttributes]: function→*data-address*
  cross-references, with `get_xrefs_from` / `get_xrefs_to` helpers. **Implemented only by the Ghidra
  and Binary Ninja backends** (`GhidraReferencedDataAnalyzer`, `BinaryNinjaReferencedDataAnalyzer`) —
  not pyghidra, angr, Capstone, or the cached backend.
- [`ComplexBlock`][ofrak.core.complex_block.ComplexBlock] + `Program.get_memory_region_for_vaddr` /
  `Program.get_function_complex_block(name)`: map an address to its enclosing function, and look a
  function up by its `Symbol`-indexed name.
- [`CommentsAttributes`][ofrak.core.comments.CommentsAttributes] /
  [`AddCommentModifier`][ofrak.core.comments.AddCommentModifier]: store a comment on a resource.

**Does NOT exist — must be built by this work:**

- **A function→string producer.** [`ReferencedStringsAnalyzer`][ofrak.core.program.ReferencedStringsAnalyzer]
  is an *abstract class with no implementation*, and
  [`ReferencedStringsAttributes`][ofrak.core.data.ReferencedStringsAttributes] is a dataclass that
  **nothing constructs**. (Note its `referenced_strings` field is `Tuple[Range, ...]` — byte ranges,
  not text.) The anchor and fingerprint mechanisms both need function→string *content*, which no
  component produces. This is the central prerequisite (see below).
- **A rename operation.** There is no modifier that sets `ComplexBlock.name`; the name is written
  only at view-construction time by the disassembler's unpacker. Renaming must construct a fresh
  `ComplexBlock` view and `resource.add_view(...)` it (the documented write-back pattern) — a small
  but genuinely new `RenameComplexBlockModifier`.
- **A function-prototype model.** OFRAK models no function signature/prototype anywhere; `ComplexBlock`
  carries only `name`, `virtual_address`, `size`. Any "prototype" in exported markup has nothing to
  read from or write to, so prototypes are **out of scope** for v1 (or require a new attribute first).

### The prerequisite: a real `ReferencedStringsAnalyzer`

Because the substrate is missing, the first deliverable is a concrete analyzer that derives
function→string references from what *does* exist:

```python
# Sketch: derive string content from the data-reference graph that Ghidra/Binja already produce.
class DerivedReferencedStringsAnalyzer(ReferencedStringsAnalyzer):
    targets = (Program,)
    outputs = (ReferencedStringsAttributes,)

    async def analyze(self, resource, config=None):
        program = await resource.view_as(Program)
        data_refs = resource.get_attributes(ReferencedDataAttributes)   # Ghidra/Binja only
        # For each referenced data vaddr, read bytes at (vaddr - region.virtual_address) via
        # Program.get_memory_region_for_vaddr; if the bytes decode as a C string, keep it and its
        # Range. Then rebuild the function->string edges from data_refs.get_xrefs_from().
        ...
```

This is the step the earlier draft wrongly assumed was free. It is real work, and it inherits the
Ghidra/Binary-Ninja-only limitation of its input.

## Feature #1: Anchor-based markup

An **anchor** names a function indirectly, by a stable property it references. v1 supports **string**
anchors (constant/MMIO *scalar* anchors are deferred — they need instruction-operand resolution that
is additional work):

```python
class AnchorType(Enum):
    STRING = 0   # a literal string the target function references
    SCALAR = 1   # DEFERRED: a hardware constant in an instruction operand


@dataclass
class Anchor:
    name: str
    anchor_type: AnchorType
    value: Union[str, int]          # str|int, NOT `object` (the pjson AnySerializer is pass-through)
    comment: Optional[str] = None


@dataclass
class ApplyAnchoredMarkupConfig(ComponentConfig):
    anchors: List[Anchor]
```

The `Modifier` targets [`Program`][ofrak.core.program.Program]; it depends on the derived
string-reference analyzer above:

```python
class ApplyAnchoredMarkupModifier(Modifier[ApplyAnchoredMarkupConfig]):
    targets = (Program,)

    async def modify(self, resource, config):
        strings = await resource.analyze(ReferencedStringsAttributes)   # the NEW analyzer
        report = AnchorResolutionReport()
        for anchor in config.anchors:
            blocks = await _functions_referencing(resource, strings, anchor)  # -> ComplexBlocks
            if not blocks:
                report.misses.append(anchor.name); continue
            if len(blocks) > 1:
                report.ambiguous.append(anchor.name); continue    # conservative: never mislabel
            cb = blocks[0]
            await cb.resource.run(RenameComplexBlockModifier, ...)   # NEW modifier (add_view)
            if anchor.comment:
                await cb.resource.run(AddCommentModifier,
                                      AddCommentModifierConfig((None, anchor.comment)))
            report.hits[anchor.name] = cb.virtual_address
        resource.add_attributes(report)
```

Two useful properties: the markup is **reproducible from a recipe** (re-running the anchor set on a
fresh analysis reproduces it), and **a miss/ambiguous result is itself a cross-version signal** (the
function changed, moved, or no longer references that string).

## Feature #2: Portable RE annotations

Export every analyst-named / commented `ComplexBlock` to a portable document, with an
address-independent fingerprint so it can be re-located on a different build. The fingerprint is the
set of string contents the function references (derived via the Feature-#1 analyzer):

```json
{
  "program": "abl_odin",
  "functions": [
    {
      "name": "verify_image_policy",
      "comments": ["Aggregates secure-boot / anti-rollback policy before image verification."],
      "string_refs": ["Not enable the secure boot", "AVB", "rollback index %d"]
    }
  ]
}
```

Two caveats the earlier draft glossed:

- **`string_refs` is derived, not stored.** It comes from reading bytes at the referenced ranges, not
  from a ready-made attribute.
- **"Analyst-named" is not distinguishable today.** OFRAK records no provenance separating a name an
  analyst applied from a disassembler default (`FUN_*` / `sub_*`). Export must therefore track
  provenance itself — e.g. only names applied via the rename modifier, or a dedicated marker — or it
  will export machine defaults as if they were analysis.

Component shapes, with the contract caveat the review flagged:

```python
# Export is NOT analysis-to-attribute-store; writing a file is outside the Analyzer contract.
# Prefer a helper / CLI (or flush_data_to_disk) over an Analyzer whose only output nobody consumes.
def export_portable_markup(program: Program) -> PortableMarkup: ...

class MarkupImportModifier(Modifier[MarkupImportConfig]):
    targets = (Program,)
    # For each record: rank target functions by string_refs set-overlap; above a (to-be-designed)
    # similarity threshold AND unique, apply name + comments via the Feature-#1 helpers; otherwise
    # record unmatched. Conservative by default — never force-apply.
```

Both the portable schema and the import matcher should ride OFRAK's existing
`SerializationService` plumbing (it already serializes `Range`, etc.) rather than hand-rolled JSON.
The set-overlap ranking + threshold is a real matching algorithm to be designed, not a one-liner.

## Value

Honest value, after stripping the claims that didn't survive review:

- **Cross-build markup transfer is a real gap OFRAK does not fill.** Re-applying build *A*'s names and
  comments onto a sibling build *B* is not possible today; this provides it.
- **Markup becomes a git-diffable artifact.** A committed JSON keyed on stable fingerprints makes
  cross-version triage a `git diff` and makes markup reviewable in a PR.
- **Headless, no-GUI, pipeline-native.** The intended win over external matchers (Ghidra Version
  Tracking, BSim, bindiff, Diaphora) is not matching quality — those are stronger — but that this runs
  inside an OFRAK `unpack → modify → repack` pipeline with no GUI and no shipped disassembler project.

What this is **not**: it is not "survives project loss" (OFRAK already does, via serialization and
project scripts), and it is **not backend-agnostic** — it requires the Ghidra or Binary Ninja data-ref
analyzer and no-ops (and should fail loudly) elsewhere.

## Open questions / known limitations

- **No string-reference producer exists** — building `DerivedReferencedStringsAnalyzer` is the gating
  prerequisite, and it is Ghidra/Binary-Ninja-only.
- **Backend lock-in** — acceptable only if the core component fails loudly with a capability error on
  backends that lack data refs, rather than silently doing nothing.
- **Name provenance** — export needs a way to tell analyst names from disassembler defaults.
- **Import matching** — set-overlap similarity, tie-breaking, and a precision/recall target are an
  explicit design task; precision alone is not a sufficient quality bar.
- **Scalar/MMIO anchors** — deferred; need instruction-operand constant resolution.
- **String-less functions** — have no fingerprint; need a secondary identity or are non-portable.

<div align="right">
<img src="../../assets/square_02.png" width="125" height="125">
</div>
