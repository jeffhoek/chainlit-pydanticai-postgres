"""Unit tests for extract_affected_named and build_content's SSVC/affected lines.

Fixtures mirror the verified live shape of CVE-2021-44228 documented in
plans/ssvc-affected-integration.md: SSVC under metrics.ssvcV203, and a top-level
cve.affected block whose affectedData carries vendor/product pairs.
"""

from scripts.nvd_utils import build_content, extract_affected_named


def test_extract_affected_named_flattens_vendor_product():
    affected = [
        {
            "source": "security@apache.org",
            "affectedData": [
                {"vendor": "Apache Software Foundation", "product": "Apache Log4j2"},
            ],
        }
    ]
    assert extract_affected_named(affected) == ["Apache Software Foundation Apache Log4j2"]


def test_extract_affected_named_dedupes_preserving_order():
    affected = [
        {"affectedData": [{"vendor": "V", "product": "B"}, {"vendor": "V", "product": "A"}]},
        {"affectedData": [{"vendor": "V", "product": "B"}]},  # duplicate of first
    ]
    assert extract_affected_named(affected) == ["V B", "V A"]


def test_extract_affected_named_handles_missing_pieces_and_empty():
    # product-only, vendor-only, and empty inputs.
    assert extract_affected_named([{"affectedData": [{"product": "OnlyProduct"}]}]) == ["OnlyProduct"]
    assert extract_affected_named([{"affectedData": [{"vendor": "OnlyVendor"}]}]) == ["OnlyVendor"]
    assert extract_affected_named([]) == []
    assert extract_affected_named([{"affectedData": [{}]}]) == []


def _log4shell(with_ssvc=True, with_affected=True) -> dict:
    cve = {
        "id": "CVE-2021-44228",
        "descriptions": [{"lang": "en", "value": "Log4Shell"}],
        "metrics": {},
    }
    if with_ssvc:
        cve["metrics"]["ssvcV203"] = [
            {
                "ssvcData": {
                    "version": "2.0.3",
                    "options": [
                        {"exploitation": "active"},
                        {"automatable": "yes"},
                        {"technicalImpact": "total"},
                    ],
                }
            }
        ]
    if with_affected:
        cve["affected"] = [
            {
                "source": "security@apache.org",
                "affectedData": [
                    {"vendor": "Apache Software Foundation", "product": "Apache Log4j2"},
                ],
            }
        ]
    return cve


def test_build_content_includes_ssvc_and_affected():
    content = build_content(_log4shell())
    assert "SSVC: exploitation=active, automatable=yes, technicalImpact=total" in content
    assert "Affected: Apache Software Foundation Apache Log4j2" in content


def test_build_content_omits_lines_when_absent():
    content = build_content(_log4shell(with_ssvc=False, with_affected=False))
    assert "SSVC:" not in content
    assert "Affected:" not in content
    # base fields still present
    assert "CVE ID: CVE-2021-44228" in content


def test_build_content_partial_ssvc_lists_only_present_factors():
    cve = _log4shell(with_affected=False)
    # drop automatable + technicalImpact, keep only exploitation
    cve["metrics"]["ssvcV203"][0]["ssvcData"]["options"] = [{"exploitation": "poc"}]
    content = build_content(cve)
    assert "SSVC: exploitation=poc" in content
    assert "automatable" not in content
