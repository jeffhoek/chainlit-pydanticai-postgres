"""Unit tests for the composite risk score constants, bands, and SQL generation.

No database. The arithmetic itself lives in Postgres and is covered by
tests/integration/test_risk_view_db.py — what is tested here is everything Python
actually owns: the weight invariant, the band cut-points, the generated DDL matching
the constants it was generated from, and the rationale prose.
"""

import datetime
from decimal import Decimal

import pytest

from rag.risk import (
    BAND_CRITICAL,
    BAND_HIGH,
    BAND_MODERATE,
    CWE_CLASSES,
    CWE_SEVERITY,
    MAX_BATCH,
    MAX_WEIGHT,
    REQUIRED_WEIGHT_TOTAL,
    band,
    build_rationale,
    component_expressions,
    score_expression,
    validate_cve_ids,
    view_ddl,
)


def make_row(**overrides) -> dict:
    """A v_cve_risk row with every component at zero, for targeted overrides."""
    row = {
        "cve_id": "CVE-2021-44228",
        "risk_score": Decimal("0.0"),
        "c_cvss": Decimal("0"),
        "c_epss": Decimal("0"),
        "c_kev": Decimal("0"),
        "c_ransomware": Decimal("0"),
        "c_ssvc": Decimal("0"),
        "c_cwe": Decimal("0"),
        "cvss_score": None,
        "cvss_imputed": False,
        "epss_probability": None,
        "epss_percentile": None,
        "epss_previous_probability": None,
        "epss_previous_scored_at": None,
        "epss_scored_at": None,
        "kev_listed": False,
        "kev_date_added": None,
        "known_ransomware_campaign_use": None,
        "ssvc_exploitation": None,
        "ssvc_automatable": None,
        "ssvc_technical_impact": None,
        "cwe_top": None,
    }
    row.update(overrides)
    return row


# -- Weight invariant --


def test_weights_sum_to_exactly_one():
    """The invariant that keeps the reported score inside 0-100."""
    assert MAX_WEIGHT == REQUIRED_WEIGHT_TOTAL
    assert REQUIRED_WEIGHT_TOTAL == Decimal("1.00")  # noqa: SIM300


# -- Bands --


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "low"),
        (24.9, "low"),
        (25, "moderate"),
        (44.9, "moderate"),
        (45, "high"),
        (64.9, "high"),
        (65, "critical"),
        (100, "critical"),
    ],
)
def test_band_boundaries_are_exact(score, expected):
    assert band(score) == expected


def test_band_accepts_decimal_without_float_rounding():
    assert band(BAND_HIGH) == "high"
    assert band(BAND_HIGH - Decimal("0.1")) == "moderate"
    assert band(BAND_CRITICAL) == "critical"
    assert band(BAND_MODERATE) == "moderate"


def test_non_kev_ceiling_lands_inside_the_high_band():
    """The property the bands were recalibrated for.

    A CVE that is not on KEV can reach at most CVSS + EPSS + automatable + impact +
    top CWE class. If that ceiling ever falls below the high cut-point the
    early-warning population goes invisible again; if it rises above the critical
    cut-point, "critical" stops meaning confirmed exploitation.
    """
    ceiling = (Decimal("0.25") + Decimal("0.30") + Decimal("0.02") + Decimal("0.02") + Decimal("0.05")) * 100
    assert band(ceiling) == "high"


# -- Generated SQL matches the constants --


def test_view_ddl_emits_every_cwe_in_the_map():
    """The guard against the generated SQL and the Python constants drifting."""
    ddl = view_ddl()
    for cwe, severity in CWE_SEVERITY.items():
        assert f"('{cwe}', {severity})" in ddl, f"{cwe} missing from generated VALUES list"


def test_view_ddl_emits_no_cwe_outside_the_map():
    import re

    emitted = set(re.findall(r"\('(CWE-\d+)', ", view_ddl()))
    assert emitted == set(CWE_SEVERITY)


def test_cwe_classes_have_no_duplicate_members():
    """A CWE in two classes would silently take whichever class sorts last."""
    members = [cwe for _, cwes in CWE_CLASSES.values() for cwe in cwes]
    assert len(members) == len(set(members))


def test_catch_all_cwes_stay_neutral():
    """CWE-20 and CWE-264 span everything from XSS to RCE — a tier for either is noise."""
    assert "CWE-20" not in CWE_SEVERITY
    assert "CWE-264" not in CWE_SEVERITY


def test_score_expression_sums_all_six_components():
    expr = score_expression()
    for name in component_expressions():
        assert name in expr
    assert expr.startswith("ROUND(100 * (")


def test_cwe_component_coalesces_to_the_neutral_default():
    """Without the COALESCE an unmapped CWE NULL-poisons the whole sum."""
    assert "COALESCE(cw.severity, 0.5)" in component_expressions()["c_cwe"]


def test_cvss_component_coalesces_v2_then_the_neutral_prior():
    expr = component_expressions()["c_cvss"]
    assert "COALESCE(n.cvss_v31_score, n.cvss_v2_score, 5.0)" in expr


def test_view_ddl_unions_the_kev_and_nvd_universes():
    ddl = view_ddl()
    assert "SELECT cve_id FROM nvd_vulnerabilities\n    UNION\n    SELECT cve_id FROM kev_vulnerabilities" in ddl


def test_view_ddl_concatenates_nvd_and_kev_cwes_rather_than_coalescing():
    """COALESCE(n.cwes, k.cwes) never fires — the NVD array is non-empty, just useless."""
    assert "COALESCE(n.cwes, '{}'::text[]) || COALESCE(k.cwes, '{}'::text[])" in view_ddl()


def test_view_ddl_uses_left_joins_only():
    ddl = view_ddl()
    assert "INNER JOIN" not in ddl
    # The only bare JOIN is inside the lateral, against the inline CWE VALUES list.
    assert ddl.count("JOIN cwe_class cc") == 1


# -- CVE ID validation --


@pytest.mark.parametrize("cve_id", ["CVE-2021-44228", "CVE-1999-0001", "CVE-2026-123456", "CVE-2014-0160"])
def test_validate_accepts_well_formed_ids(cve_id):
    assert validate_cve_ids([cve_id]) is None


@pytest.mark.parametrize(
    "cve_id",
    [
        "cve-2021-44228",
        "CVE-2021-442",
        "CVE-21-44228",
        "CVE-2021-44228; DROP TABLE kev_vulnerabilities",
        "DROP TABLE kev_vulnerabilities",
        "",
        " CVE-2021-44228",
    ],
)
def test_validate_rejects_malformed_ids(cve_id):
    error = validate_cve_ids([cve_id])
    assert error is not None
    assert "malformed" in error


def test_validate_rejects_empty_batch():
    assert "no CVE IDs" in validate_cve_ids([])


def test_validate_rejects_over_cap_batch():
    ids = [f"CVE-2021-{n:05d}" for n in range(MAX_BATCH + 1)]
    error = validate_cve_ids(ids)
    assert error is not None
    assert str(MAX_BATCH) in error


def test_validate_accepts_batch_at_the_cap():
    ids = [f"CVE-2021-{n:05d}" for n in range(MAX_BATCH)]
    assert validate_cve_ids(ids) is None


# -- Rationale --


def test_rationale_orders_clauses_by_contribution():
    row = make_row(
        risk_score=Decimal("87.0"),
        c_cvss=Decimal("0.25"),
        c_epss=Decimal("0.28"),
        c_kev=Decimal("0.20"),
        c_ransomware=Decimal("0.10"),
        c_cwe=Decimal("0.05"),
        cvss_score=Decimal("9.8"),
        epss_probability=Decimal("0.94"),
        epss_percentile=Decimal("0.99"),
        epss_scored_at=datetime.date(2026, 7, 29),
        kev_listed=True,
        kev_date_added=datetime.date(2024, 3, 4),
        known_ransomware_campaign_use="Known",
        cwe_top="CWE-787",
    )
    text = build_rationale(row)
    order = [text.index(fragment) for fragment in ("Listed in KEV", "EPSS 0.94", "CVSS 9.8", "Memory corruption")]
    assert order == sorted(order)
    assert text.startswith("Critical (87).")
    assert "(+30)" in text  # KEV and the ransomware flag share one clause


def test_rationale_reports_the_band_and_rounded_score():
    assert build_rationale(make_row(risk_score=Decimal("45.4"))).startswith("High (45).")
    # The band comes from the exact score, the display from the rounded one — 24.9 is
    # below the moderate cut-point even though it prints as 25.
    assert build_rationale(make_row(risk_score=Decimal("24.9"))).startswith("Low (25).")


def test_points_round_half_up_not_half_to_even():
    """0.245 must read as 25, or the prose stops reconciling against the number."""
    text = build_rationale(make_row(c_cvss=Decimal("0.245"), cvss_score=Decimal("9.8")))
    assert "CVSS 9.8 (+25)." in text


def test_rationale_discloses_an_imputed_cvss():
    text = build_rationale(make_row(c_cvss=Decimal("0.125"), cvss_imputed=True))
    assert "CVSS unassessed" in text
    assert "neutral 5.0 prior" in text


def test_rationale_omits_the_disclaimer_when_cvss_is_measured():
    text = build_rationale(make_row(c_cvss=Decimal("0.25"), cvss_score=Decimal("10.0")))
    assert "unassessed" not in text
    assert "CVSS 10.0 (+25)." in text


def test_rationale_reports_epss_movement_above_the_threshold():
    text = build_rationale(
        make_row(
            c_epss=Decimal("0.234"),
            epss_probability=Decimal("0.78"),
            epss_previous_probability=Decimal("0.31"),
            epss_previous_scored_at=datetime.date(2026, 7, 28),
        )
    )
    assert "EPSS rose 0.31000 → 0.78000 since 2026-07-28" in text


def test_rationale_omits_epss_movement_below_the_threshold():
    text = build_rationale(
        make_row(
            c_epss=Decimal("0.234"),
            epss_probability=Decimal("0.78"),
            epss_previous_probability=Decimal("0.75"),
        )
    )
    assert "rose" not in text


def test_rationale_reports_a_falling_epss_score():
    text = build_rationale(
        make_row(
            c_epss=Decimal("0.09"),
            epss_probability=Decimal("0.30"),
            epss_previous_probability=Decimal("0.90"),
        )
    )
    assert "EPSS fell 0.90000 → 0.30000" in text


def test_rationale_says_a_missing_epss_score_out_loud():
    """A silently absent likelihood signal reads as 'low likelihood'."""
    text = build_rationale(make_row(c_epss=Decimal("0"), epss_probability=None))
    assert "No EPSS score" in text
    assert "not a low likelihood" in text


def test_rationale_drops_signals_that_contributed_nothing():
    text = build_rationale(make_row(c_epss=Decimal("0.03"), epss_probability=Decimal("0.1")))
    assert "Listed in KEV" not in text
    assert "SSVC" not in text


def test_rationale_names_the_ssvc_factors_present():
    text = build_rationale(
        make_row(
            c_ssvc=Decimal("0.10"),
            ssvc_exploitation="active",
            ssvc_automatable="yes",
            ssvc_technical_impact="total",
        )
    )
    assert "SSVC exploitation=active, automatable=yes, technical impact=total (+10)." in text


def test_rationale_omits_the_ransomware_phrase_when_the_flag_is_unknown():
    text = build_rationale(make_row(c_kev=Decimal("0.20"), kev_listed=True, known_ransomware_campaign_use="Unknown"))
    assert "Listed in KEV (+20)." in text
    assert "ransomware" not in text


def test_rationale_notes_an_unrated_weakness_class():
    text = build_rationale(make_row(c_cwe=Decimal("0.025"), cwe_top=None))
    assert "No rated weakness class" in text
