"""Shared NVD parsing and extraction utilities.

Used by both load_nvd.py (KEV-scoped) and load_nvd_full.py (full NVD).
"""

import asyncio
import datetime
import random
from email.utils import parsedate_to_datetime

import httpx

# NVD 2.0 is notorious for transient rate-limit / availability errors under load:
# it returns 403 for rate limiting (not 401), plus 429 and 5xx (especially 503)
# during traffic spikes. These are transient and worth retrying; anything else is
# the caller's to handle. See
# https://github.com/dependency-check/DependencyCheck/issues/6758.
NVD_RETRYABLE_STATUS = frozenset({403, 429, 500, 502, 503, 504})
NVD_FETCH_MAX_RETRIES = 8
NVD_BACKOFF_BASE = 5.0  # seconds — first-attempt target before jitter
NVD_BACKOFF_CAP = 120.0  # per-attempt ceiling (also caps a server Retry-After)


def _backoff_seconds(attempt: int) -> float:
    """Capped exponential backoff (base * 2**attempt) with equal jitter.

    Equal jitter keeps each wait at least half the target so backoff still grows
    meaningfully, while the random half spreads out retries from concurrent clients.
    """
    target = min(NVD_BACKOFF_CAP, NVD_BACKOFF_BASE * (2**attempt))
    return target / 2 + random.uniform(0, target / 2)  # noqa: S311 — jitter, not cryptographic


def _retry_after_seconds(resp: httpx.Response) -> float | None:
    """Parse a Retry-After header (delta-seconds or HTTP-date) into seconds, or None."""
    value = resp.headers.get("Retry-After")
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, (when - datetime.datetime.now(datetime.UTC)).total_seconds())


async def nvd_get_with_backoff(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    max_retries: int = NVD_FETCH_MAX_RETRIES,
    log=print,
) -> httpx.Response:
    """GET a URL, retrying NVD's transient 403/429/5xx and transport errors.

    Honors a ``Retry-After`` header when present (capped), otherwise uses capped
    exponential backoff with jitter. Returns the final ``Response`` so the caller
    still handles 404/200 itself; re-raises the last transport error if every
    attempt fails to connect.
    """
    for attempt in range(max_retries):
        last = attempt == max_retries - 1
        try:
            resp = await client.get(url, params=params, headers=headers)
        except httpx.TransportError as e:
            if last:
                raise
            delay = _backoff_seconds(attempt)
            log(f"  NVD {type(e).__name__}; backing off {delay:.0f}s (attempt {attempt + 1}/{max_retries})")
            await asyncio.sleep(delay)
            continue

        if resp.status_code in NVD_RETRYABLE_STATUS and not last:
            retry_after = _retry_after_seconds(resp)
            delay = min(retry_after, NVD_BACKOFF_CAP) if retry_after is not None else _backoff_seconds(attempt)
            log(f"  NVD HTTP {resp.status_code}; backing off {delay:.0f}s (attempt {attempt + 1}/{max_retries})")
            await asyncio.sleep(delay)
            continue
        return resp


def extract_cvss_v31(metrics: dict) -> tuple:
    """Extract CVSS v3.1 score, severity, and vector string."""
    for entry in metrics.get("cvssMetricV31", []):
        data = entry.get("cvssData", {})
        return (
            data.get("baseScore"),
            data.get("baseSeverity"),
            data.get("vectorString"),
        )
    return None, None, None


def extract_cvss_v2(metrics: dict) -> tuple:
    """Extract CVSS v2 score and severity."""
    for entry in metrics.get("cvssMetricV2", []):
        data = entry.get("cvssData", {})
        return data.get("baseScore"), entry.get("baseSeverity")
    return None, None


def extract_ssvc(metrics: dict) -> dict:
    """Flatten CISA-ADP SSVC v2.0.3 factors into a dict of factor -> value.

    SSVC is nested under ``metrics.ssvcV203`` (not a top-level CVE field). Each
    entry's ``ssvcData.options`` is an array of single-key dicts, e.g.
    ``[{"exploitation": "active"}, {"automatable": "yes"}, ...]``; they are merged
    into one flat mapping. Returns ``{}`` when no SSVC block is present. The
    rolled-up ``decision`` (Act/Attend/Track) is usually absent today — see plan.
    """
    for entry in metrics.get("ssvcV203", []):
        data = entry.get("ssvcData", {})
        opts: dict = {}
        for o in data.get("options", []):
            if isinstance(o, dict):
                opts.update(o)
        return {
            "exploitation": opts.get("exploitation"),
            "automatable": opts.get("automatable"),
            "technical_impact": opts.get("technicalImpact"),
            "decision": opts.get("decision"),  # usually absent today
            "version": data.get("version"),
        }
    return {}


def extract_cwes(weaknesses: list) -> list[str]:
    """Extract CWE IDs from weaknesses."""
    cwes = []
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                cwes.append(desc["value"])
    return cwes


def extract_affected_products(configurations: list) -> list[str]:
    """Extract CPE strings from configurations."""
    products = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    products.append(match.get("criteria", ""))
    return products


def extract_affected_named(affected: list) -> list[str]:
    """Extract distinct "vendor product" names from the top-level cve.affected block.

    ``affected`` is the CVE-record-format list (richer than the CPE-based
    ``configurations``); each entry's ``affectedData`` carries vendor/product
    pairs. Returns human-readable names for embedding/search — order-preserving
    and deduped. Used by build_content only; dedicated columns are deferred (Tier 2).
    """
    names: list[str] = []
    for entry in affected or []:
        for item in entry.get("affectedData", []):
            vendor = (item.get("vendor") or "").strip()
            product = (item.get("product") or "").strip()
            name = " ".join(p for p in (vendor, product) if p)
            if name and name not in names:
                names.append(name)
    return names


def extract_description(descriptions: list) -> str:
    """Extract English description."""
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def extract_reference_urls(references: list) -> list[str]:
    """Extract reference URLs."""
    return [ref.get("url", "") for ref in references[:10]]


def parse_date(date_str: str | None) -> datetime.date | None:
    """Parse ISO-8601 date string to date object."""
    if not date_str:
        return None
    return datetime.datetime.fromisoformat(date_str.replace("Z", "+00:00")).date()


def build_content(cve_data: dict) -> str:
    """Build content string for embedding from NVD CVE data."""
    description = extract_description(cve_data.get("descriptions", []))
    metrics = cve_data.get("metrics", {})
    cvss_score, cvss_severity, cvss_vector = extract_cvss_v31(metrics)
    cwes = extract_cwes(cve_data.get("weaknesses", []))
    products = extract_affected_products(cve_data.get("configurations", []))
    ssvc = extract_ssvc(metrics)
    affected_named = extract_affected_named(cve_data.get("affected", []))

    parts = [
        f"CVE ID: {cve_data.get('id', '')}",
        f"Description: {description}",
    ]
    if cvss_score is not None:
        parts.append(f"CVSS v3.1 Score: {cvss_score} ({cvss_severity})")
    if cvss_vector:
        parts.append(f"CVSS Vector: {cvss_vector}")
    if cwes:
        parts.append(f"CWEs: {', '.join(cwes)}")
    if products:
        parts.append(f"Affected Products: {', '.join(products[:5])}")

    ssvc_factors = [
        f"{label}={ssvc[key]}"
        for key, label in (
            ("exploitation", "exploitation"),
            ("automatable", "automatable"),
            ("technical_impact", "technicalImpact"),
            ("decision", "decision"),
        )
        if ssvc.get(key)
    ]
    if ssvc_factors:
        parts.append(f"SSVC: {', '.join(ssvc_factors)}")
    if affected_named:
        parts.append(f"Affected: {', '.join(affected_named[:5])}")

    return "\n".join(parts)
