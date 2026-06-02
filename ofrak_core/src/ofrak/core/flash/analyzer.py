"""
Heuristic OFRAK analyzer: infer `FlashAttributes` for raw NAND dumps tagged as `FlashResource`.
"""

import logging
import math
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from ofrak.component.analyzer import Analyzer
from ofrak.core.flash.flash import (
    FlashAttributes,
    FlashField,
    FlashFieldType,
    FlashResource,
)
from ofrak.core.flash.heuristics import (
    DEFAULT_HEURISTICS,
    GeometryCandidate,
    Heuristic,
    HeuristicEvidence,
    HeuristicSpec,
    ScanConfig,
    evaluate_heuristics,
)
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource

LOGGER = logging.getLogger(__name__)


# Constants

# Standard NAND (data, OOB) geometries. Order matters: earlier entries win on ties.
# (256, 0) is appended last as a fallback for SPI NOR / raw images with no spare area:
# it contributes zero OOB signal, so any geometry with real OOB evidence outranks it.
DEFAULT_GEOMETRIES: Tuple[Tuple[int, int], ...] = (
    # Most Common
    (2048, 64),
    (4096, 128),
    (512, 16),
    (4096, 224),
    (8192, 448),
    (256, 0),
)

# Window size (in bytes) for checking erased / non-erased regions near page boundaries
# during gap-evidence sampling.
ERASED_SENTINEL_WINDOW = 16


# Config


@dataclass
class ScoringWeights:
    """
    Scoring knobs for the tiebreakers that aren't heuristics.

    Per-heuristic weight and noise-floor live on each heuristic's `HeuristicSpec`.

    :param entropy_min_delta_bits: minimum data-minus-OOB entropy delta (bits/byte) required
        before entropy contributes to the tiebreaker
    :param entropy_min_data_entropy_bits: minimum mean data entropy (bits/byte) required
        before entropy contributes to the tiebreaker
    :param entropy_tiebreak_scale: integer multiplier applied to the entropy delta so it can
        be compared in the same ranking vector as heuristic hit counts
    :param gap_relative_min_hit_rate: fractional floor on gap hits per page scanned before the
        gap signal is allowed to contribute
    """

    entropy_min_delta_bits: float = 0.3
    entropy_min_data_entropy_bits: float = 4.0
    entropy_tiebreak_scale: int = 100
    gap_relative_min_hit_rate: float = 0.01


@dataclass
class FlashGeometryHeuristicAnalyzerConfig(ComponentConfig):
    """
    Config for `FlashGeometryHeuristicAnalyzer`.

    To "train" the analyzer on new image families, supply a custom `heuristics` list.

    :param extra_geometries: additional `(data_size, oob_size)` pairs to consider beyond
        `DEFAULT_GEOMETRIES`
    :param scan: tunables for the evidence-collection pass
    :param weights: tiebreaker thresholds for the entropy and gap signals
    :param heuristics: ordered list of heuristics to run against each candidate geometry
    """

    extra_geometries: Tuple[Tuple[int, int], ...] = ()
    scan: ScanConfig = field(default_factory=ScanConfig)
    weights: ScoringWeights = field(default_factory=ScoringWeights)
    heuristics: Sequence[Heuristic] = field(default_factory=lambda: list(DEFAULT_HEURISTICS))

    def geometries(self) -> Tuple[Tuple[int, int], ...]:
        return tuple(list(self.extra_geometries) + list(DEFAULT_GEOMETRIES))


# OFRAK component


class FlashGeometryHeuristicAnalyzer(
    Analyzer[Optional[FlashGeometryHeuristicAnalyzerConfig], Tuple[FlashAttributes, ...]]
):
    """
    Infers `FlashAttributes` for a raw NAND dump tagged as `FlashResource`.

    Ranks each standard `(data_size, oob_size)` geometry that evenly divides the file by
    running a library of heuristics (Linux MTD large-page OOB, YAFFS2 packed tags, small-page
    ECC density, exact Linux MTD Hamming verification) plus entropy and OOB-aligned gap
    tiebreakers.

    The returned `FlashAttributes` describes one data block containing `DATA`
    followed by `SPARE` of the OOB size, so the existing `FlashOobResourceUnpacker`
    preserves the per-block spare region verbatim as a `FlashSpareAreaResource` when
    unpacking (rather than discarding it).

    If no standard geometry evenly divides the file into a power-of-two page count, the
    analyzer logs a warning and returns no attributes rather than raising, so that other
    analyzers (e.g. `BinwalkAnalyzer`) can still run on the same resource.
    """

    targets = (FlashResource,)
    outputs = (FlashAttributes,)

    async def analyze(
        self,
        resource: Resource,
        config: Optional[FlashGeometryHeuristicAnalyzerConfig] = None,
    ) -> Tuple[FlashAttributes, ...]:
        config = config or FlashGeometryHeuristicAnalyzerConfig()
        geometries = config.geometries()
        data = await resource.get_data()

        candidates = enumerate_candidates(len(data), geometries)
        if not candidates:
            LOGGER.warning(
                "No standard NAND geometry matches file size with a power-of-2 page count "
                "(file size: %d bytes). Skipping FlashAttributes inference.",
                len(data),
            )
            return ()

        heuristic_results = [
            run_heuristics(data, c, config.scan, config.heuristics) for c in candidates
        ]
        scored = [score_candidate(e, config.weights, geometries) for e in heuristic_results]
        winner = min(scored, key=lambda s: s.sort_key)
        winning_candidate = winner.evidence.candidate

        return (
            FlashAttributes(
                data_block_format=[
                    FlashField(FlashFieldType.DATA, winning_candidate.data_size),
                    FlashField(FlashFieldType.SPARE, winning_candidate.oob_size),
                ]
            ),
        )


# Pipeline output types


@dataclass
class GeometryEvidence:
    """
    Per-geometry signal counts gathered for a candidate.

    :param candidate: the geometry candidate these counts belong to
    :param pages_scanned: number of pages actually visited during the scan
    :param heuristic_evidence: one `HeuristicEvidence` per configured heuristic
    :param gap_hits: count of OOB-sized 0xFF gaps found between non-erased data regions
    :param mean_data_entropy: mean Shannon entropy (bits/byte) across scanned data regions
    :param mean_oob_entropy: mean Shannon entropy (bits/byte) across scanned OOB regions
    """

    candidate: GeometryCandidate
    pages_scanned: int
    heuristic_evidence: List[HeuristicEvidence]
    gap_hits: int
    mean_data_entropy: float = 0.0
    mean_oob_entropy: float = 0.0

    @property
    def entropy_data_minus_oob(self) -> float:
        return self.mean_data_entropy - self.mean_oob_entropy


@dataclass
class GeometryScore:
    """
    Ranking vector for a single candidate.

    Precedence when comparing candidates:

    1. higher `oob_signal_score` (sum of per-heuristic scores)
    2. higher `entropy_signal_score` (tiebreak: data-minus-OOB entropy delta)
    3. higher `gap_signal_score` (tiebreak: OOB-aligned 0xFF gaps)
    4. lower `preference_index` (earlier-listed geometries win)

    :param evidence: the evidence the scores were computed from
    :param oob_signal_score: sum of per-heuristic scores
    :param entropy_signal_score: scaled data-minus-OOB entropy delta, or 0 when gated out
    :param gap_signal_score: gap-hit count after noise-floor gating
    :param preference_index: position of the geometry in the configured ordered list
    """

    evidence: GeometryEvidence
    oob_signal_score: int
    entropy_signal_score: int
    gap_signal_score: int
    preference_index: int

    @property
    def sort_key(self) -> Tuple[int, int, int, int]:
        return (
            -self.oob_signal_score,
            -self.entropy_signal_score,
            -self.gap_signal_score,
            self.preference_index,
        )


# Pipeline (called from `FlashGeometryHeuristicAnalyzer.analyze`, in order)


def enumerate_candidates(
    file_size: int,
    geometries: Sequence[Tuple[int, int]],
) -> List[GeometryCandidate]:
    """
    Filter `geometries` down to those that evenly divide `file_size` into a power-of-two
    number of pages.

    :param file_size: size of the flash image in bytes
    :param geometries: candidate `(data_size, oob_size)` pairings to consider

    :return: one `GeometryCandidate` per surviving pairing, in input order
    """
    out: List[GeometryCandidate] = []
    for data_size, oob_size in geometries:
        total = data_size + oob_size
        if total <= 0 or file_size % total != 0:
            continue
        pages = file_size // total
        if not _is_power_of_two(pages):
            continue
        out.append(GeometryCandidate(data_size=data_size, oob_size=oob_size, num_pages=pages))
    return out


def run_heuristics(
    data: bytes,
    candidate: GeometryCandidate,
    scan: ScanConfig,
    heuristics: Optional[Sequence[Heuristic]] = None,
) -> GeometryEvidence:
    """
    Gather per-heuristic evidence plus the entropy + gap tiebreak signals.

    :param data: the full flash image bytes
    :param candidate: the candidate geometry to evaluate
    :param scan: tunables for the scan pass
    :param heuristics: heuristics to run; defaults to `DEFAULT_HEURISTICS`

    :return: the aggregated `GeometryEvidence` for `candidate`
    """
    if heuristics is None:
        heuristics = DEFAULT_HEURISTICS

    heuristic_evidence = evaluate_heuristics(data, candidate, scan, heuristics)
    gap_hits, mean_data_entropy, mean_oob_entropy, pages_scanned = _scan_entropy_and_gap(
        data, candidate, scan
    )

    return GeometryEvidence(
        candidate=candidate,
        pages_scanned=pages_scanned,
        heuristic_evidence=heuristic_evidence,
        gap_hits=gap_hits,
        mean_data_entropy=mean_data_entropy,
        mean_oob_entropy=mean_oob_entropy,
    )


def score_candidate(
    evidence: GeometryEvidence,
    weights: ScoringWeights,
    geometries: Sequence[Tuple[int, int]],
) -> GeometryScore:
    """
    Combine per-heuristic evidence and entropy/gap tiebreakers into a ranking vector.

    :param evidence: the `GeometryEvidence` for the candidate
    :param weights: tiebreaker thresholds for the entropy and gap signals
    :param geometries: the ordered list of geometries (used to derive `preference_index`)

    :return: the `GeometryScore` for the candidate
    """
    oob_signal = sum(ev.score() for ev in evidence.heuristic_evidence)

    gap_min_hits = int(evidence.pages_scanned * weights.gap_relative_min_hit_rate)
    gap_signal = evidence.gap_hits if evidence.gap_hits >= gap_min_hits else 0

    # Entropy is a confirmation signal only.
    has_existing_evidence = oob_signal > 0 or evidence.gap_hits > 0
    entropy_signal = 0
    if (
        has_existing_evidence
        and evidence.mean_data_entropy >= weights.entropy_min_data_entropy_bits
        and evidence.entropy_data_minus_oob >= weights.entropy_min_delta_bits
    ):
        entropy_signal = int(evidence.entropy_data_minus_oob * weights.entropy_tiebreak_scale)

    return GeometryScore(
        evidence=evidence,
        oob_signal_score=oob_signal,
        entropy_signal_score=entropy_signal,
        gap_signal_score=gap_signal,
        preference_index=_geometry_preference_index(
            evidence.candidate.data_size, evidence.candidate.oob_size, geometries
        ),
    )


# Private helpers


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def _geometry_preference_index(
    data_size: int,
    oob_size: int,
    geometries: Sequence[Tuple[int, int]],
) -> int:
    try:
        return list(geometries).index((data_size, oob_size))
    except ValueError:
        return len(geometries)


def _shannon_entropy(buf: bytes) -> float:
    """
    Compute Shannon entropy of `buf` in bits/byte (0..8).
    """
    n = len(buf)
    if n == 0:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def _scan_entropy_and_gap(
    data: bytes,
    candidate: GeometryCandidate,
    scan: ScanConfig,
) -> Tuple[int, float, float, int]:
    """
    Single pass collecting entropy aggregates and page-boundary gap hits.

    :param data: the full flash image bytes
    :param candidate: the candidate geometry being measured
    :param scan: tunables for the scan pass

    :return: `(gap_hits, mean_data_entropy, mean_oob_entropy, pages_scanned)`
    """
    gap_hits = 0
    gap_budget = scan.gap_sample_count

    file_len = len(data)
    w = ERASED_SENTINEL_WINDOW
    erased_window = b"\xff" * w
    erased_oob = b"\xff" * candidate.oob_size

    pages_available = file_len // candidate.total_chunk_size
    pages_to_scan = min(scan.oob_scan_cap_pages, pages_available)

    entropy_enabled = scan.entropy_enabled and candidate.oob_size > 0
    data_entropy_sum = 0.0
    oob_entropy_sum = 0.0

    pages_scanned = 0
    for page in range(pages_to_scan):
        base = page * candidate.total_chunk_size
        oob_off = base + candidate.data_size
        if oob_off + candidate.oob_size > file_len:
            break

        if entropy_enabled:
            page_data = data[base:oob_off]
            oob = data[oob_off : oob_off + candidate.oob_size]
            data_entropy_sum += _shannon_entropy(page_data)
            oob_entropy_sum += _shannon_entropy(oob)

        pages_scanned += 1

        # Probe this page boundary for an OOB-sized 0xFF gap between non-erased data.
        # Skip page 0 (needs a previous page for context); only run while within the
        # sampling window and the budget isn't exhausted.
        if page == 0 or page > scan.gap_sample_max_scan or gap_budget <= 0:
            continue

        # Skip pages whose data region looks erased (first + last 16 bytes both 0xFF);
        # these would otherwise waste the gap budget.
        if data[base : base + w] == erased_window and data[oob_off - w : oob_off] == erased_window:
            continue
        gap_budget -= 1

        oob_region = data[oob_off : oob_off + candidate.oob_size]
        if oob_region != erased_oob:
            continue
        data_before = data[oob_off - w : oob_off]
        data_after = data[oob_off + candidate.oob_size : oob_off + candidate.oob_size + w]
        if len(data_before) != w or len(data_after) != w:
            continue
        if data_before == erased_window and data_after == erased_window:
            continue
        gap_hits += 1

    mean_data_entropy = (
        data_entropy_sum / pages_scanned if (entropy_enabled and pages_scanned) else 0.0
    )
    mean_oob_entropy = (
        oob_entropy_sum / pages_scanned if (entropy_enabled and pages_scanned) else 0.0
    )
    return gap_hits, mean_data_entropy, mean_oob_entropy, pages_scanned


# CLI: random-search heuristic weights that best match a labeled image set.
#
#   python -m ofrak.core.flash.analyzer --images-dir DIR --labels LABELS.json
#
# LABELS.json maps filename (relative to --images-dir) to [data_size, oob_size].

if __name__ == "__main__":  # pragma: no cover
    import argparse
    import json
    import random
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images-dir", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=200)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    labels = {name: tuple(v) for name, v in json.loads(args.labels.read_text()).items()}
    geometries = DEFAULT_GEOMETRIES
    default_specs = {h.spec.name: h.spec for h in DEFAULT_HEURISTICS}
    default_weights = ScoringWeights()
    names = list(default_specs)

    # Evidence is independent of weights, so collect it once per image.
    cache = []
    for fname, expected in labels.items():
        data = (args.images_dir / fname).read_bytes()
        evs = [
            run_heuristics(data, c, ScanConfig(), DEFAULT_HEURISTICS)
            for c in enumerate_candidates(len(data), geometries)
        ]
        cache.append((expected, evs))

    def accuracy(specs, weights):  # pragma: no cover
        correct = 0
        for expected, evs in cache:
            if not evs:
                continue
            rescored = [
                score_candidate(
                    GeometryEvidence(
                        e.candidate,
                        e.pages_scanned,
                        [
                            HeuristicEvidence(specs[he.name], he.hits, he.pages_examined)
                            for he in e.heuristic_evidence
                        ],
                        e.gap_hits,
                        e.mean_data_entropy,
                        e.mean_oob_entropy,
                    ),
                    weights,
                    geometries,
                )
                for e in evs
            ]
            win = min(rescored, key=lambda s: s.sort_key).evidence.candidate
            if (win.data_size, win.oob_size) == expected:
                correct += 1
        return correct

    # Normalized L1 distance from defaults, used to tie-break trials with equal accuracy.
    def distance(specs, weights):  # pragma: no cover
        d = 0.0
        for n, s in specs.items():
            ref = default_specs[n].weight
            d += abs(s.weight - ref) / max(abs(ref), 1)
        for attr in (
            "entropy_min_delta_bits",
            "entropy_min_data_entropy_bits",
            "entropy_tiebreak_scale",
            "gap_relative_min_hit_rate",
        ):
            ref = getattr(default_weights, attr)
            d += abs(getattr(weights, attr) - ref) / max(abs(ref), 1e-6)
        return d

    rng = random.Random(args.seed)
    # Seed the leaderboard with defaults (distance 0) so trials must beat them outright.
    best_correct = accuracy(default_specs, default_weights)
    best_dist = 0.0
    best_specs = default_specs
    best_weights = default_weights

    for _ in range(args.trials):
        specs = {n: HeuristicSpec(n, weight=rng.randint(1, 100)) for n in names}
        weights = ScoringWeights(
            entropy_min_delta_bits=rng.uniform(0.0, 1.0),
            entropy_min_data_entropy_bits=rng.uniform(0.0, 8.0),
            entropy_tiebreak_scale=rng.randint(1, 500),
            gap_relative_min_hit_rate=rng.uniform(0.0, 0.1),
        )
        n = accuracy(specs, weights)
        if n < best_correct:
            continue
        d = distance(specs, weights)
        if n > best_correct or d < best_dist:
            best_correct, best_dist, best_specs, best_weights = n, d, specs, weights

    print(
        json.dumps(
            {
                "correct": best_correct,
                "total": len(cache),
                "heuristic_weights": {n: s.weight for n, s in best_specs.items()},
                "scoring_weights": best_weights.__dict__,
            },
            indent=2,
        )
    )
