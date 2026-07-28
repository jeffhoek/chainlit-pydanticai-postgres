"""Unit tests for extract_ssvc — flattening CISA-ADP SSVC v2.0.3 factors.

Fixtures mirror the verified live shape of CVE-2021-44228 documented in
plans/ssvc-affected-integration.md: SSVC nests under ``metrics.ssvcV203`` and
``ssvcData.options`` is an array of single-key dicts.
"""

from scripts.nvd_utils import extract_ssvc


def _metrics_with_options(options: list) -> dict:
    """Wrap an options array in the full metrics.ssvcV203 envelope."""
    return {
        "ssvcV203": [
            {
                "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                "ssvcData": {
                    "timestamp": "2025-02-04T14:25:34.416117Z",
                    "id": "CVE-2021-44228",
                    "options": options,
                    "role": "CISA Coordinator",
                    "version": "2.0.3",
                },
            }
        ]
    }


def test_active_record_flattens_all_factors():
    metrics = _metrics_with_options(
        [
            {"exploitation": "active"},
            {"automatable": "yes"},
            {"technicalImpact": "total"},
        ]
    )

    assert extract_ssvc(metrics) == {
        "exploitation": "active",
        "automatable": "yes",
        "technical_impact": "total",
        "decision": None,  # rolled-up CISA decision is absent today
        "version": "2.0.3",
    }


def test_no_ssvc_block_returns_empty_dict():
    # Metrics present (e.g. CVSS only) but no ssvcV203 key.
    assert extract_ssvc({"cvssMetricV31": [{"cvssData": {}}]}) == {}
    assert extract_ssvc({}) == {}
    assert extract_ssvc({"ssvcV203": []}) == {}


def test_decision_present_is_captured_when_nvd_adds_it():
    metrics = _metrics_with_options(
        [
            {"exploitation": "active"},
            {"automatable": "yes"},
            {"technicalImpact": "total"},
            {"decision": "Act"},
        ]
    )

    result = extract_ssvc(metrics)
    assert result["decision"] == "Act"


def test_malformed_options_are_tolerated():
    # options with a non-dict element, a missing factor, and no version.
    metrics = {
        "ssvcV203": [
            {
                "ssvcData": {
                    "options": [
                        {"exploitation": "poc"},
                        "not-a-dict",  # ignored, no crash
                        {},  # empty dict contributes nothing
                    ]
                    # no "version" key
                }
            }
        ]
    }

    assert extract_ssvc(metrics) == {
        "exploitation": "poc",
        "automatable": None,
        "technical_impact": None,
        "decision": None,
        "version": None,
    }


def test_missing_ssvcdata_returns_all_none_factors():
    # Entry present but ssvcData absent entirely.
    assert extract_ssvc({"ssvcV203": [{"source": "x"}]}) == {
        "exploitation": None,
        "automatable": None,
        "technical_impact": None,
        "decision": None,
        "version": None,
    }
