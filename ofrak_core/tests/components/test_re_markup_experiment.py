"""
This module runs the portable RE markup experiment of re_markup_experiment.py on the committed A/B
pair of builds, and checks that the pair is valid, that the baseline measurements reproduce the
committed baseline report, that the same-binary round trip is lossless, that the transfer to the
other build meets its precision and recall targets, and that the value the feature adds over the
baseline holds by more than Ghidra's run-to-run variance.

Requirements Mapping:
- REQ2.6
- REQ2.7
"""
from typing import Any, Dict

from elftools.elf.elffile import ELFFile

from ofrak import OFRAKContext
from .re_markup_experiment import (
    AFTER_REPORT,
    BASELINE_REPORT,
    BUILD_A,
    BUILD_B,
    CAPTURE_GHIDRA_VERSION,
    PRECISION_TARGET,
    RECALL_FLOOR,
    describe_pair,
    get_ghidra_version,
    load_ground_truth,
    read_json,
    run_after,
    run_feature,
    validate_pair,
    variance_band,
)

BASELINE_METHODS = ("address_keyed_reapply", "symbol_export_reapply")
FEATURE_METHODS = ("anchored_markup", "portable_import")
CONTROL_METHODS = ("serialize_restore", "ofrak_project_replay")
KPIS = ("transfer_recall", "transfer_precision", "comment_recall")
# The fields of the dataset that only depend on the committed files
PAIR_FIELDS = (
    "functions_a",
    "functions_b",
    "shared_function_identities",
    "same_address_fraction",
    "rodata_strings_a",
    "rodata_strings_b",
    "shared_string_fraction",
)

# The experiment takes minutes, so it runs once for all the tests of this module (which run in
# the same pytest-xdist worker, see conftest.py)
_experiment: Dict[str, Any] = dict()


async def _run_experiment(ofrak_context: OFRAKContext, tmp_path_factory) -> Dict[str, Any]:
    if not _experiment:
        work_dir = str(tmp_path_factory.mktemp("re_markup"))
        _experiment.update(await run_after(ofrak_context, live=False, work_dir=work_dir))
    return _experiment


def test_re_markup_pair_is_valid():
    """
    Test that the committed builds are a true A/B pair (REQ2.7).

    This test verifies that:
    - The builds are stripped, so markup cannot come from their own symbols
    - Most functions exist in both builds, but almost none at the same address, and the builds
      share most of their strings
    - The committed reports describe this pair
    """
    for build in (BUILD_A, BUILD_B):
        with open(build.path, "rb") as f:
            assert ELFFile(f).get_section_by_name(".symtab") is None
    pair = describe_pair(load_ground_truth(BUILD_A), load_ground_truth(BUILD_B))
    validate_pair(pair)
    for report in (read_json(BASELINE_REPORT), read_json(AFTER_REPORT)):
        assert {field: report["dataset"][field] for field in PAIR_FIELDS} == pair


async def test_baseline_reproduces_committed_report(
    ghidra_ofrak_context: OFRAKContext, tmp_path_factory
):
    """
    Test the baseline measurements, made with OFRAK's existing mechanisms only, with the feature's
    components present (REQ2.7).

    This test verifies that:
    - The control: markup fully survives a serialize→restore and an OfrakProject replay on the
      same binary
    - Markup re-applied by address to the other build lands almost nowhere, mostly on the wrong
      functions, and nothing reports which functions diverged
    - The measurements are those of the committed baseline report, which was made with the OFRAK
      before the feature, within the variance band
    """
    report = await _run_experiment(ghidra_ofrak_context, tmp_path_factory)
    committed = read_json(BASELINE_REPORT)
    band = variance_band()

    for method in CONTROL_METHODS:
        assert report["same_binary_survival"][method]["survival"] == 1.0
        assert report["same_binary_survival"][method]["misplaced"] == 0
    for method in BASELINE_METHODS:
        measured = report["cross_build_transfer"][method]
        expected = committed["cross_build_transfer"][method]
        assert measured["transfer_recall"] < 0.05
        assert measured["transfer_precision"] < 0.5
        assert not measured["divergence_flagged"]
        for kpi in KPIS:
            assert abs(measured[kpi] - expected[kpi]) <= band, (method, kpi)


async def test_same_binary_round_trip_is_lossless(
    ghidra_ofrak_context: OFRAKContext, tmp_path_factory
):
    """
    Test that portable markup exported from a build and imported onto a fresh analysis of the same
    build restores all of it (REQ2.7).

    This test verifies that:
    - Every analyst name and comment is back on its function
    - No other function gets one of the names
    """
    report = await _run_experiment(ghidra_ofrak_context, tmp_path_factory)
    round_trip = report["feature"]["portable_round_trip"]

    assert round_trip["records"] == report["dataset"]["analyst_named"] > 500
    assert round_trip["names_restored"] == round_trip["records"]
    assert round_trip["comments_restored"] == round_trip["records"]
    assert round_trip["misplaced"] == 0


async def test_cross_build_transfer_meets_targets(
    ghidra_ofrak_context: OFRAKContext, tmp_path_factory
):
    """
    Test the transfer of markup from build A to build B with anchors (#1) and portable markup (#2)
    (REQ2.6, REQ2.7).

    This test verifies that:
    - Both meet the precision target, and mislabel no function absent from B
    - The portable markup import meets the recall floor, and reports every record it did not
      carry over, including every function absent from B
    - The portable markup import of part of the analyst's markup meets the precision target in
      every one of the random subsets, and the recall floor on average
    """
    feature = (await _run_experiment(ghidra_ofrak_context, tmp_path_factory))["feature"]

    for method in FEATURE_METHODS:
        assert feature[method]["transfer_precision"] >= PRECISION_TARGET, method
        assert feature[method]["absent_mislabeled"] == [], method
    portable = feature["portable_import"]
    assert portable["transfer_recall"] >= RECALL_FLOOR
    assert portable["divergence_flagged"]
    assert portable["absent_reported"] == portable["absent_in_b"] > 0
    partial = feature["portable_import_partial"]
    assert partial["precision_min"] >= PRECISION_TARGET
    assert partial["recall_mean"] >= RECALL_FLOOR
    assert partial["absent_mislabeled"] == 0


async def test_value_add_holds(ghidra_ofrak_context: OFRAKContext, tmp_path_factory):
    """
    Test that the feature's cross-build KPIs beat the committed Phase-0 baseline by more than
    Ghidra's run-to-run variance, and have not regressed from the committed after report (REQ2.7).

    This test verifies that:
    - Each feature method's recall and precision exceed the best baseline method's by more than
      the variance band
    - The portable markup import flags every function it could not carry over, which no baseline
      method does
    - Each feature KPI is at least its committed value minus the variance band (only a real
      regression fails; an improvement does not)
    - The same-binary control is unchanged from the baseline report, made without the feature
    """
    report = await _run_experiment(ghidra_ofrak_context, tmp_path_factory)
    baseline = read_json(BASELINE_REPORT)
    after = read_json(AFTER_REPORT)
    band = variance_band()

    for kpi in KPIS:
        best_baseline = max(
            baseline["cross_build_transfer"][method][kpi] for method in BASELINE_METHODS
        )
        for method in FEATURE_METHODS:
            measured = report["feature"][method][kpi]
            assert measured - best_baseline > band, (method, kpi)
            assert measured >= after["feature"][method][kpi] - band, (method, kpi)
    for kpi in ("precision_min", "recall_mean"):
        measured = report["feature"]["portable_import_partial"][kpi]
        assert measured >= after["feature"]["portable_import_partial"][kpi] - band, kpi
    assert not any(
        baseline["cross_build_transfer"][method]["divergence_flagged"]
        for method in BASELINE_METHODS
    )
    assert report["feature"]["portable_import"]["divergence_flagged"]
    for method in CONTROL_METHODS:
        assert (
            report["same_binary_survival"][method]["survival"]
            == baseline["same_binary_survival"][method]["survival"]
        )


async def test_live_analysis_within_variance_band(ghidra_ofrak_context: OFRAKContext, tmp_path):
    """
    Test the feature with Ghidra analyzing both builds from scratch, instead of loading the
    committed captures of its analysis (REQ2.6, REQ2.7).

    This test verifies that:
    - The round trip onto a fresh analysis of the same build is lossless
    - The live KPIs meet the precision target and the recall floor
    - They are no worse than the committed (capture-based) ones beyond the variance band, so the
      captures still represent what the backend produces
    """
    results = await run_feature(ghidra_ofrak_context, live=True, work_dir=str(tmp_path))
    committed = read_json(AFTER_REPORT)["feature"]
    band = variance_band()
    versions = f"Ghidra {get_ghidra_version()}, captures made with {CAPTURE_GHIDRA_VERSION}"

    assert results["portable_round_trip"]["survival"] == 1.0, versions
    assert results["portable_import"]["transfer_recall"] >= RECALL_FLOOR, versions
    assert results["portable_import_partial"]["precision_min"] >= PRECISION_TARGET, versions
    for method in FEATURE_METHODS:
        assert results[method]["transfer_precision"] >= PRECISION_TARGET, (method, versions)
        for kpi in KPIS:
            assert results[method][kpi] >= committed[method][kpi] - band, (method, kpi, versions)
