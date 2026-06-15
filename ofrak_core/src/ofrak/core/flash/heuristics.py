"""
Heuristics and heuristic framework for the flash geometry heuristic analyzer.

Every heuristic carries a `HeuristicSpec` (uniform scoring parameters) and
returns a `HeuristicEvidence` from `evaluate`. The analyzer treats every
entry in the heuristic list identically.
"""

import struct
from dataclasses import dataclass
from enum import Enum
from typing import List, Protocol, Sequence, Tuple, Union, cast


# Constants shared with heuristics

# Linux MTD large-page OOB (64-byte spare) layout:
#   bytes [0, 40)  - bad-block / scrub markers (usually 0xFF after byte 0)
#   bytes [40, 64) - 24 bytes of Hamming ECC arranged as 8 triplets (3 bytes x 8 subpages)
LINUX_MTD_LARGE_PAGE_OOB_SIZE = 64
LINUX_MTD_OOB_ECC_OFFSET = 40
LINUX_MTD_OOB_ECC_END = 64
LINUX_MTD_OOB_ECC_LEN = LINUX_MTD_OOB_ECC_END - LINUX_MTD_OOB_ECC_OFFSET  # 24

# YAFFS2 "packed tags 2" layout inside OOB:
#   byte 0: 0xFF (leading erased byte, left untouched by YAFFS)
#   byte 1: 0x55 (YAFFS tag marker)
#   bytes [2, 18): 16 bytes of little-endian packed tags (seq, obj, chunk, n_bytes)
YAFFS2_TAG_MARKER_VALUE = 0x55
YAFFS2_PACKED_TAGS2_OFFSET = 2
YAFFS2_PACKED_TAGS2_LEN = 16
YAFFS2_PACKED_TAGS2_END = YAFFS2_PACKED_TAGS2_OFFSET + YAFFS2_PACKED_TAGS2_LEN  # 18

# Small-page NAND OOB (typically 8 or 16 bytes) convention:
#   byte 5: bad-block marker (0xFF = good block)
#   remaining bytes: ECC + metadata
SMALL_PAGE_OOB_MAX = 16
SMALL_PAGE_BBM_OFFSET = 5

# Linux MTD soft-Hamming ECC works over 256-byte sectors; the 64-byte large-page
# OOB holds up to 8 triplets (covering up to 2048 bytes of data). Pages whose
# data_size is not a multiple of this stride can't be verified exactly.
LINUX_MTD_HAMMING_SECTOR_SIZE = 256
LINUX_MTD_HAMMING_MAX_SECTORS = 8

# Page cap for the expensive exact-ECC pass.
ECC_VERIFY_PAGE_CAP = 1024


# Shared value types


@dataclass(frozen=True)
class GeometryCandidate:
    """
    A `(data_size, oob_size)` pairing that evenly divides the file being analyzed.

    :param data_size: size in bytes of the data region of one page
    :param oob_size: size in bytes of the out-of-band / spare region of one page
    :param num_pages: number of complete pages the candidate divides the file into
    """

    data_size: int
    oob_size: int
    num_pages: int

    @property
    def total_chunk_size(self) -> int:
        return self.data_size + self.oob_size


@dataclass
class ScanConfig:
    """
    Tunables for the evidence-collection pass.

    :param oob_scan_cap_pages: cap on total pages inspected by per-page heuristics and the
        entropy / gap sampler
    :param ecc_verify_page_cap: cap on pages inspected by the exact-ECC verifier
    :param ecc_verify_enabled: whether to run the exact-ECC verifier at all. This can be disabled since it is expensive.
    :param gap_sample_count: number of page boundaries charged against the gap-sampling budget
    :param gap_sample_max_scan: maximum page index that the gap sampler is allowed to consider
    :param entropy_enabled: whether to accumulate Shannon entropy of the data and OOB regions
    """

    oob_scan_cap_pages: int = 4096
    ecc_verify_page_cap: int = ECC_VERIFY_PAGE_CAP
    ecc_verify_enabled: bool = True
    gap_sample_count: int = 10
    gap_sample_max_scan: int = 100
    entropy_enabled: bool = True


# Heuristic framework (uniform scoring interface)


@dataclass(frozen=True)
class HeuristicSpec:
    """
    Uniform scoring parameters attached to every heuristic.

    :param name: short identifier used to look up the heuristic's evidence
    :param weight: multiplier applied to the hit count when contributing to `oob_signal_score`
    :param absolute_min_hits: floor on hits below which the heuristic's contribution is zeroed
    :param relative_min_hit_rate: fractional floor on hits per page examined, combined with
        `absolute_min_hits` via `max()`
    """

    name: str
    weight: int = 1
    absolute_min_hits: int = 1
    relative_min_hit_rate: float = 0.01

    def min_hits(self, pages_examined: int) -> int:
        return max(
            self.absolute_min_hits,
            int(pages_examined * self.relative_min_hit_rate),
        )


@dataclass
class HeuristicEvidence:
    """
    Per-heuristic result produced by a single evaluation pass.

    :param spec: the spec used to drive the evaluation
    :param hits: number of pages the heuristic matched
    :param pages_examined: number of pages the heuristic was given a chance to match
    """

    spec: HeuristicSpec
    hits: int
    pages_examined: int

    @property
    def name(self) -> str:
        return self.spec.name

    def score(self) -> int:
        """
        Compute the heuristic's uniform contribution to the primary signal score.

        :return: `hits * weight` if hits clear the spec's noise floor, else 0
        """
        if self.pages_examined <= 0:
            return 0
        if self.hits < self.spec.min_hits(self.pages_examined):
            return 0
        return self.hits * self.spec.weight


class GlobalHeuristic(Protocol):
    """
    Heuristic that runs its own pass over the whole image via `evaluate`.
    """

    @property
    def spec(self) -> HeuristicSpec:  # pragma: no cover
        ...

    def evaluate(
        self, data: bytes, candidate: GeometryCandidate, scan: ScanConfig
    ) -> HeuristicEvidence:  # pragma: no cover
        ...


class PerPageOobHeuristic(Protocol):
    """
    Heuristic whose per-page hit decision depends only on a page's OOB.

    Implementations supply `check_page` and `evaluate_heuristics` batches them into one shared
    scan loop via `_scan_per_page_batched`.
    """

    @property
    def spec(self) -> HeuristicSpec:  # pragma: no cover
        ...

    def check_page(self, oob: bytes, data_size: int) -> int:  # pragma: no cover
        ...


Heuristic = Union[GlobalHeuristic, PerPageOobHeuristic]


# Public entry point


def evaluate_heuristics(
    data: bytes,
    candidate: GeometryCandidate,
    scan: ScanConfig,
    heuristics: Sequence[Heuristic],
) -> List[HeuristicEvidence]:
    """
    Run every heuristic against a candidate and return one evidence per heuristic.

    The analyzer calls this entry point. Per-page heuristics (anything exposing `check_page`)
    are batched into a single shared scan loop; all other heuristics are run individually.

    :param data: the full flash image bytes
    :param candidate: the candidate geometry under evaluation
    :param scan: tunables for the evidence-collection pass
    :param heuristics: the ordered list of heuristics to evaluate

    :return: one `HeuristicEvidence` per entry in `heuristics`, in the same order
    """
    per_page: List[PerPageOobHeuristic] = [
        cast(PerPageOobHeuristic, h) for h in heuristics if hasattr(h, "check_page")
    ]
    other: List[GlobalHeuristic] = [
        cast(GlobalHeuristic, h) for h in heuristics if not hasattr(h, "check_page")
    ]

    results: List[HeuristicEvidence] = []
    if per_page:
        results.extend(_scan_per_page_batched(data, candidate, scan, per_page))
    results.extend(h.evaluate(data, candidate, scan) for h in other)

    by_name = {ev.name: ev for ev in results}
    return [by_name[h.spec.name] for h in heuristics]


def _scan_per_page_batched(
    data: bytes,
    candidate: GeometryCandidate,
    scan: ScanConfig,
    heuristics: Sequence[PerPageOobHeuristic],
) -> List[HeuristicEvidence]:
    """
    Shared per-page loop for heuristics that expose `check_page`.
    """
    pages_available = len(data) // candidate.total_chunk_size
    pages_to_scan = min(scan.oob_scan_cap_pages, pages_available)
    hits = [0] * len(heuristics)
    pages_examined = 0
    for page in range(pages_to_scan):
        base = page * candidate.total_chunk_size
        oob_off = base + candidate.data_size
        if oob_off + candidate.oob_size > len(data):
            break
        oob = data[oob_off : oob_off + candidate.oob_size]
        for i, h in enumerate(heuristics):
            hits[i] += h.check_page(oob, candidate.data_size)
        pages_examined += 1
    return [
        HeuristicEvidence(h.spec, hits=n, pages_examined=pages_examined)
        for h, n in zip(heuristics, hits)
    ]


# Concrete heuristics


class OobPageCategory(Enum):
    """
    Classification of a single page's spare area.
    """

    EMPTY = "EMPTY"  # oob is length 0
    ALL_FF = "ALL_FF"  # fully erased
    ECC_ONLY = "ECC_ONLY"  # matches Linux MTD large-page Hamming layout
    TAGGED = "TAGGED"  # starts with FF 55 (YAFFS2 tag marker)
    MIXED = "MIXED"  # anything else


def classify_oob(oob: bytes) -> OobPageCategory:
    """
    Classify a page's OOB bytes against the common NAND spare-area conventions.

    :param oob: the out-of-band / spare bytes for a single page

    :return: the matching `OobPageCategory` (`MIXED` if nothing else fits)
    """
    n = len(oob)
    if n == 0:
        return OobPageCategory.EMPTY
    if all(b == 0xFF for b in oob):
        return OobPageCategory.ALL_FF
    if n >= LINUX_MTD_LARGE_PAGE_OOB_SIZE:
        header_erased = oob[:LINUX_MTD_OOB_ECC_OFFSET] == b"\xff" * LINUX_MTD_OOB_ECC_OFFSET
        ecc_region = oob[LINUX_MTD_OOB_ECC_OFFSET:LINUX_MTD_OOB_ECC_END]
        if header_erased and ecc_region != b"\xff" * LINUX_MTD_OOB_ECC_LEN:
            return OobPageCategory.ECC_ONLY
        if oob[0] == 0xFF and oob[1] == YAFFS2_TAG_MARKER_VALUE:
            return OobPageCategory.TAGGED
    return OobPageCategory.MIXED


@dataclass(frozen=True)
class EccOnlyHeuristic:
    """
    Detects Linux MTD large-page layouts: the first 40 OOB bytes are 0xFF while the 24-byte
    ECC region is populated.
    """

    spec: HeuristicSpec = HeuristicSpec(name="ecc_only")

    def check_page(self, oob: bytes, data_size: int) -> int:
        return 1 if classify_oob(oob) == OobPageCategory.ECC_ONLY else 0


@dataclass(frozen=True)
class Yaffs2PackedTagsHeuristic:
    """
    Detects the YAFFS2 "packed tags 2" marker plus a plausible `n_bytes` field in the OOB.
    """

    spec: HeuristicSpec = HeuristicSpec(name="yaffs2", weight=2)

    def check_page(self, oob: bytes, data_size: int) -> int:
        if len(oob) < YAFFS2_PACKED_TAGS2_END:
            return 0
        if oob[0] != 0xFF or oob[1] != YAFFS2_TAG_MARKER_VALUE:
            return 0
        try:
            _seq, _obj, _chunk, n_bytes = struct.unpack(
                "<IIII", oob[YAFFS2_PACKED_TAGS2_OFFSET:YAFFS2_PACKED_TAGS2_END]
            )
        except struct.error:
            return 0
        return 1 if 0 < n_bytes <= data_size else 0


@dataclass(frozen=True)
class SmallPageEccHeuristic:
    """
    Matches small-page NAND OOB (<= 16 bytes) that looks densely populated.

    Classic small-page (512+16) OOB layout keeps byte 5 as the bad-block marker
    (0xFF for good blocks) and packs ECC + metadata across the remaining bytes.
    A page matches when the OOB is
    (a) shorter than the Linux large-page layout,
    (b) has 0xFF at the bad-block marker offset (if long enough to carry one),
    (c) the remaining bytes are densely populated with ECC/metadata.

    The density floor is intentionally strict: partial-erased data windows that
    happen to land 0xFF at the BBM position produce many FF bytes elsewhere, so
    requiring "nearly all non-BBM bytes populated" rejects them and leaves only
    genuine small-page OOB structure. Without this heuristic, (512, 16)
    candidates never score on OOB content and always lose the
    preference-index tie-break.

    :param bbm_offset: offset inside the OOB that is expected to carry 0xFF (bad-block marker)
    :param max_ff_outside_bbm: maximum number of 0xFF bytes outside `bbm_offset` before the
        OOB is rejected as "probably just an erased / partially-erased window"
    """

    bbm_offset: int = SMALL_PAGE_BBM_OFFSET
    max_ff_outside_bbm: int = 1
    spec: HeuristicSpec = HeuristicSpec(name="small_page_ecc")

    def check_page(self, oob: bytes, data_size: int) -> int:
        n = len(oob)
        if n == 0 or n > SMALL_PAGE_OOB_MAX:
            return 0
        if n > self.bbm_offset and oob[self.bbm_offset] != 0xFF:
            return 0
        ff_outside = sum(1 for i, b in enumerate(oob) if b == 0xFF and i != self.bbm_offset)
        return 1 if ff_outside <= self.max_ff_outside_bbm else 0


# Linux MTD soft-Hamming ECC over a 256-byte sector. Mirrors Linux
# `ecc_sw_hamming_calculate(..., step_size=256, sm_order=false)`.
# https://github.com/torvalds/linux/blob/59bd5ae0db22566e2b961742126269c151d587c7/drivers/mtd/nand/ecc-sw-hamming.c#L115
_ECC_INVPARITY = bytes(1 - (bin(i).count("1") & 1) for i in range(256))

_HAM256_ECC_STEPS: Tuple[Tuple[bool, Tuple[Tuple[int, int], ...]], ...] = (
    (True, ((0, 0),)),
    (False, ((1, 1),)),
    (False, ((0, 0),)),
    (False, ((2, 1),)),
    (False, ((0, 0), (1, 0))),
    (False, ((1, 1),)),
    (False, ((0, 0),)),
    (False, ((3, 1),)),
    (False, ((0, 0), (1, 0), (2, 0))),
    (False, ((1, 0), (2, 0))),
    (False, ((0, 0), (2, 0))),
    (False, ((2, 1),)),
    (False, ((0, 0), (1, 0))),
    (False, ((1, 1),)),
    (False, ((0, 0),)),
    (False, ()),
)


def _linux_mtd_hamming_ecc_256(sector: bytes) -> bytes:
    """
    Compute the 3-byte Linux MTD soft-Hamming ECC over one 256-byte sector.

    :param sector: exactly 256 bytes of page data

    :raises ValueError: if `sector` is not exactly 256 bytes

    :return: the 3-byte ECC code for `sector`
    """
    if len(sector) != LINUX_MTD_HAMMING_SECTOR_SIZE:
        raise ValueError("Hamming step must be exactly 256 bytes")
    w = iter(struct.unpack("<64I", sector))

    def fold_u8(x: int) -> int:
        x ^= x >> 16
        x ^= x >> 8
        return x & 0xFF

    par = 0
    acc = [0, 0, 0, 0]
    rp12 = rp14 = 0
    t = 0
    for q in range(4):
        for assign, ops in _HAM256_ECC_STEPS:
            cur = next(w)
            if assign:
                t = cur
            else:
                t ^= cur
            for rpi, use_t in ops:
                v = t if use_t else cur
                acc[rpi] ^= v
        par ^= t
        if (q & 1) == 0:
            rp12 ^= t
        if (q & 2) == 0:
            rp14 ^= t
    rp4, rp6, rp8, rp10 = acc
    rp4, rp6, rp8, rp10, rp12, rp14 = map(fold_u8, (rp4, rp6, rp8, rp10, rp12, rp14))

    rp3 = ((par >> 16) ^ ((par >> 16) >> 8)) & 0xFF
    rp2 = ((par & 0xFFFF) ^ ((par & 0xFFFF) >> 8)) & 0xFF
    par ^= par >> 16
    rp1 = (par >> 8) & 0xFF
    rp0 = par & 0xFF
    par ^= par >> 8
    par &= 0xFF

    rp5 = (par ^ rp4) & 0xFF
    rp7 = (par ^ rp6) & 0xFF
    rp9 = (par ^ rp8) & 0xFF
    rp11 = (par ^ rp10) & 0xFF
    rp13 = (par ^ rp12) & 0xFF
    rp15 = (par ^ rp14) & 0xFF

    inv = _ECC_INVPARITY
    lo = (rp7, rp6, rp5, rp4, rp3, rp2, rp1, rp0)
    hi = (rp15, rp14, rp13, rp12, rp11, rp10, rp9, rp8)
    code1 = sum(inv[b] << (7 - j) for j, b in enumerate(lo))
    code0 = sum(inv[b] << (7 - j) for j, b in enumerate(hi))
    code2 = (
        sum(inv[par & m] << (7 - k) for k, m in enumerate((0xF0, 0x0F, 0xCC, 0x33, 0xAA, 0x55))) | 3
    )
    return bytes((code0 & 0xFF, code1 & 0xFF, code2 & 0xFF))


def _verify_exact_ecc(
    data: bytes,
    candidate: GeometryCandidate,
    page_cap: int,
) -> Tuple[int, int]:
    """
    Verify Linux MTD soft-Hamming ECC on a sampled subset of pages.

    A non-zero match count is a very strong signal that the geometry guess is correct.
    Only meaningful when the OOB is at least 64 bytes and the data region is a multiple of
    256 bytes; otherwise returns `(0, 0)`.

    :param data: the full flash image bytes
    :param candidate: the candidate geometry to check
    :param page_cap: maximum number of pages to sample

    :return: `(pages_checked, exact_matches)` where `pages_checked` counts non-erased pages on
        which the check ran, and `exact_matches` counts pages whose 8 ECC triplets all match
        their recomputed value byte-for-byte
    """
    if (
        candidate.oob_size < LINUX_MTD_LARGE_PAGE_OOB_SIZE
        or candidate.data_size < LINUX_MTD_HAMMING_SECTOR_SIZE
        or candidate.data_size % LINUX_MTD_HAMMING_SECTOR_SIZE != 0
    ):
        return 0, 0

    total_chunk_size = candidate.total_chunk_size
    num_pages = len(data) // total_chunk_size
    pages_to_sample = min(page_cap, num_pages)
    if pages_to_sample <= 0:
        return 0, 0

    n_sectors = min(
        candidate.data_size // LINUX_MTD_HAMMING_SECTOR_SIZE,
        LINUX_MTD_HAMMING_MAX_SECTORS,
    )
    all_ff_sector = b"\xff" * LINUX_MTD_HAMMING_SECTOR_SIZE
    erased_prefix = all_ff_sector * n_sectors

    # Stride the sample evenly across the whole image so we catch structured
    # regions even when they live deep in the file (common for chip dumps
    # with blank preambles).
    stride = max(1, num_pages // pages_to_sample)

    pages_checked = 0
    matches = 0
    for k in range(pages_to_sample):
        page_idx = k * stride
        if page_idx >= num_pages:
            break
        base = page_idx * total_chunk_size
        data_start = base
        data_end = base + candidate.data_size
        oob_ecc = data[data_end + LINUX_MTD_OOB_ECC_OFFSET : data_end + LINUX_MTD_OOB_ECC_END]
        if len(oob_ecc) != LINUX_MTD_OOB_ECC_LEN:
            break
        page_data = data[data_start:data_end]
        if page_data[: n_sectors * LINUX_MTD_HAMMING_SECTOR_SIZE] == erased_prefix:
            continue
        pages_checked += 1
        all_exact = True
        for s in range(n_sectors):
            sector = page_data[
                s * LINUX_MTD_HAMMING_SECTOR_SIZE : (s + 1) * LINUX_MTD_HAMMING_SECTOR_SIZE
            ]
            expected = _linux_mtd_hamming_ecc_256(sector)
            actual = oob_ecc[s * 3 : s * 3 + 3]
            if actual != expected:
                all_exact = False
                break
        if all_exact:
            matches += 1
    return pages_checked, matches


@dataclass(frozen=True)
class EccExactVerifyHeuristic:
    """
    `GlobalHeuristic` wrapper around `_verify_exact_ecc`.
    """

    spec: HeuristicSpec = HeuristicSpec(
        name="ecc_exact",
        weight=100,
        absolute_min_hits=1,
        relative_min_hit_rate=0.0,
    )

    def evaluate(
        self, data: bytes, candidate: GeometryCandidate, scan: ScanConfig
    ) -> HeuristicEvidence:
        if not scan.ecc_verify_enabled:
            return HeuristicEvidence(self.spec, hits=0, pages_examined=0)
        pages_checked, matches = _verify_exact_ecc(data, candidate, scan.ecc_verify_page_cap)
        return HeuristicEvidence(self.spec, hits=matches, pages_examined=pages_checked)


# Default heuristic list (instantiated once at import time)

DEFAULT_HEURISTICS: List[Heuristic] = [
    EccOnlyHeuristic(),
    Yaffs2PackedTagsHeuristic(),
    SmallPageEccHeuristic(),
    EccExactVerifyHeuristic(),
]
