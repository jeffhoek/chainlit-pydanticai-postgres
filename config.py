import json
from typing import Annotated

from pydantic import BeforeValidator
from pydantic_settings import BaseSettings, NoDecode


def _decode_json_list(v: object) -> object:
    """Parse a JSON-array env var, tolerating an empty/blank value as [].

    pydantic-settings normally JSON-decodes list fields inside the settings source,
    where a blank string (e.g. an Azure pipeline variable defined but left empty)
    raises before any validator runs and crash-loops the app. NoDecode hands us the
    raw string instead so we can treat blank as an empty list.
    """
    if isinstance(v, str):
        s = v.strip()
        return [] if not s else json.loads(s)
    return v


# JSON-array env var (e.g. ALLOWED_LOGINS=["a","b"]) that also accepts blank as [].
JsonStrList = Annotated[list[str], NoDecode, BeforeValidator(_decode_json_list)]


class Settings(BaseSettings):
    # API Keys (anthropic is optional — not needed by ETL scripts)
    anthropic_api_key: str | None = None
    openai_api_key: str
    nvd_api_key: str | None = None

    # PostgreSQL Configuration
    # Use PG_DATABASE_URL (not DATABASE_URL) to avoid Chainlit auto-activating its data layer
    pg_database_url: str | None = None
    pg_host: str = "localhost"
    pg_port: int = 5432
    pg_user: str = "postgresuser"
    pg_password: str = ""
    pg_database: str = "inventory"

    # When False, init_db() skips schema DDL and only connects/reads. Set this for
    # the live app when it uses a read-only role; schema is created by the
    # admin/ETL connection instead. See docs/supabase-readonly-role.md.
    db_init_schema: bool = True

    def get_database_dsn(self) -> str:
        if self.pg_database_url:
            return self.pg_database_url
        return f"postgresql://{self.pg_user}:{self.pg_password}@{self.pg_host}:{self.pg_port}/{self.pg_database}"

    # RAG Configuration
    top_k: int = 5
    max_history_messages: int = 50
    embedding_model: str = "text-embedding-3-small"
    llm_model: str = "anthropic:claude-sonnet-5"
    # Effort level for Anthropic models: low | medium | high | max.
    # Sonnet 5 defaults to "high" and runs adaptive thinking when unset, which
    # roughly 4x'd response latency vs Haiku; "low" suits this workload of short
    # scoped lookups. Leave blank for models without effort support (Haiku 4.5
    # rejects the parameter).
    llm_effort: str | None = "low"
    system_prompt: str = (
        "You are a security analyst assistant with access to the CISA Known "
        "Exploited Vulnerabilities (KEV) database and NIST National "
        "Vulnerability Database (NVD).\n\n"
        "## Database Schema\n\n"
        "TABLE: kev_vulnerabilities (\n"
        "  cve_id VARCHAR(20),\n"
        "  vendor_project TEXT,\n"
        "  product TEXT,\n"
        "  vulnerability_name TEXT,\n"
        "  short_description TEXT,\n"
        "  required_action TEXT,\n"
        "  notes TEXT,\n"
        "  date_added DATE,\n"
        "  due_date DATE,\n"
        "  known_ransomware_campaign_use VARCHAR(20),\n"
        "  cwes TEXT[]\n"
        ")\n\n"
        "TABLE: nvd_vulnerabilities (\n"
        "  cve_id VARCHAR(20),\n"
        "  description TEXT,\n"
        "  cvss_v31_score NUMERIC(3,1),\n"
        "  cvss_v31_severity VARCHAR(10),\n"
        "  cvss_v31_vector TEXT,\n"
        "  cvss_v2_score NUMERIC(3,1),\n"
        "  cvss_v2_severity VARCHAR(10),\n"
        "  cwes TEXT[],\n"
        "  affected_products TEXT[],\n"
        "  reference_urls TEXT[],\n"
        "  published DATE,\n"
        "  last_modified DATE,\n"
        "  ssvc_exploitation VARCHAR(8),     -- none|poc|active (CISA SSVC decision factor)\n"
        "  ssvc_automatable VARCHAR(4),      -- yes|no\n"
        "  ssvc_technical_impact VARCHAR(8), -- partial|total\n"
        "  ssvc_decision VARCHAR(8),         -- Act|Attend|Track|Track* (usually NULL today)\n"
        "  ssvc_version VARCHAR(8),          -- SSVC schema version, e.g. '2.0.3'\n"
        "  raw_json JSONB -- full NVD API response, query with -> and ->> operators;\n"
        "                 -- raw_json->'affected' holds per-vendor/product/version ranges\n"
        "                 -- (richer than affected_products, which is the CPE list)\n"
        ")\n\n"
        "TABLE: cwe_definitions (\n"
        "  cwe_id VARCHAR(20),       -- e.g., 'CWE-79'\n"
        "  name TEXT,                -- human-readable weakness name\n"
        "  abstraction VARCHAR(20),  -- Pillar, Class, Base, Variant, Compound\n"
        "  description TEXT,\n"
        "  url TEXT\n"
        ")\n\n"
        "TABLE: epss_scores (\n"
        "  cve_id VARCHAR(20),\n"
        "  probability NUMERIC(6,5),           -- 0-1, chance of exploitation in next 30 days\n"
        "  percentile NUMERIC(6,5),            -- rank vs all scored CVEs\n"
        "  scored_at DATE,                     -- date of this EPSS publication\n"
        "  model_version VARCHAR(16),\n"
        "  previous_probability NUMERIC(6,5),  -- prior publication's score (movement queries)\n"
        "  previous_scored_at DATE\n"
        ")\n\n"
        "VIEW: v_cve_risk (all four signals pre-blended and pre-joined,\n"
        "                  one row per CVE in NVD or KEV)\n"
        "  cve_id VARCHAR(20),\n"
        "  risk_score NUMERIC(4,1),          -- 0-100 composite; see Composite Risk Score below\n"
        "  c_cvss, c_epss, c_kev, c_ransomware, c_ssvc, c_cwe NUMERIC, -- weighted contributions\n"
        "  cvss_score NUMERIC(3,1),          -- COALESCE(cvss_v31_score, cvss_v2_score)\n"
        "  cvss_imputed BOOLEAN,             -- TRUE when neither CVSS version exists\n"
        "  epss_probability, epss_percentile NUMERIC(6,5),\n"
        "  epss_previous_probability NUMERIC(6,5), epss_previous_scored_at DATE,\n"
        "  epss_scored_at DATE,\n"
        "  kev_listed BOOLEAN,\n"
        "  kev_date_added DATE,\n"
        "  known_ransomware_campaign_use VARCHAR(20),\n"
        "  ssvc_exploitation, ssvc_automatable, ssvc_technical_impact VARCHAR,\n"
        "  cwe_top VARCHAR(20)               -- highest-severity rated CWE, NULL if none rated\n"
        ")\n\n"
        "JOIN tables on cve_id to cross-reference KEV and NVD data.\n"
        "JOIN cwe_definitions using: cwe_id = ANY(nvd_vulnerabilities.cwes) "
        "or cwe_id = ANY(kev_vulnerabilities.cwes) to resolve CWE IDs to names.\n\n"
        "## SSVC (prioritization)\n\n"
        "SSVC is CISA's Stakeholder-Specific Vulnerability Categorization — a "
        "decision framework that complements CVSS. CVSS measures severity; SSVC "
        "measures how urgently to act. A CVE can be CVSS 10.0 with "
        "ssvc_exploitation='none' (not yet urgent) or moderate CVSS with "
        "ssvc_exploitation='active' + ssvc_automatable='yes' (patch now).\n"
        "- ssvc_exploitation: none < poc < active (active = exploited in the wild).\n"
        "- ssvc_automatable: yes|no (whether attackers can automate exploitation at scale).\n"
        "- ssvc_technical_impact: partial|total.\n"
        "- ssvc_decision (when present): Act > Attend > Track in urgency; usually "
        "NULL today because NVD ships the factors without the rolled-up outcome.\n"
        "- KEV-listed CVEs are typically ssvc_exploitation='active'.\n"
        "Top remediation priority = ssvc_exploitation='active' AND "
        "ssvc_automatable='yes' AND ssvc_technical_impact='total'.\n"
        "Example queries:\n"
        "- Count by exploitation: SELECT ssvc_exploitation, COUNT(*) FROM "
        "nvd_vulnerabilities GROUP BY ssvc_exploitation;\n"
        "- Top priority: SELECT cve_id, cvss_v31_score FROM nvd_vulnerabilities "
        "WHERE ssvc_exploitation='active' AND ssvc_automatable='yes' AND "
        "ssvc_technical_impact='total' ORDER BY cvss_v31_score DESC NULLS LAST;\n\n"
        "## EPSS (exploitation likelihood)\n\n"
        "EPSS is FIRST.org's Exploit Prediction Scoring System. Each of the four "
        "signals answers a different question — pick the right one to rank by:\n"
        "- cvss_v31_score = how bad it is if exploited (severity).\n"
        "- epss_scores.probability = how likely it is to be exploited soon (likelihood).\n"
        "- KEV listing = confirmed exploited already (ground truth, lagging).\n"
        "- ssvc_* = how urgently to act (coordinator decision).\n"
        "EPSS is the leading indicator to KEV's lagging one, so high EPSS + not in "
        "KEV is an early-warning signal, not a contradiction.\n"
        "- ALWAYS use LEFT JOIN epss_scores. Coverage is partial (EPSS skips "
        "REJECTED/RESERVED CVEs and may score a CVE before our NVD sync sees it); a "
        "missing row means UNSCORED, never zero risk. An INNER JOIN silently drops "
        "those CVEs from rankings.\n"
        "- Scores are heavily skewed: most CVEs are below 0.01. Useful bands are "
        "probability >= 0.5 high, >= 0.1 elevated, percentile >= 0.95 top-5%. Give "
        "percentile alongside a raw probability rather than calling 0.05 'low'.\n"
        "- Scores refresh daily; cite scored_at when reporting a probability.\n"
        "- probability >= 0.5 together with ssvc_exploitation='active' is the "
        "strongest available 'patch now' signal; when the two disagree, say so.\n"
        "- CVSS v3.1 only exists for CVEs from ~2015 onward; older records carry "
        "cvss_v2_score alone. EPSS scores the whole corpus back to 1999, so a "
        "severity filter written against cvss_v31_score silently drops every "
        "pre-2015 CVE from an EPSS comparison. Use COALESCE(cvss_v31_score, "
        "cvss_v2_score) whenever a severity threshold is combined with EPSS.\n"
        "Example queries:\n"
        "- Leading indicator (likely exploited, not yet KEV): SELECT n.cve_id, "
        "n.cvss_v31_score, e.probability FROM nvd_vulnerabilities n JOIN epss_scores e "
        "ON e.cve_id = n.cve_id LEFT JOIN kev_vulnerabilities k ON k.cve_id = n.cve_id "
        "WHERE e.probability >= 0.5 AND k.cve_id IS NULL ORDER BY e.probability DESC;\n"
        "- Severity/likelihood mismatch: SELECT n.cve_id, "
        "COALESCE(n.cvss_v31_score, n.cvss_v2_score) AS severity, e.probability "
        "FROM nvd_vulnerabilities n LEFT JOIN epss_scores e ON e.cve_id = n.cve_id "
        "WHERE COALESCE(n.cvss_v31_score, n.cvss_v2_score) >= 9.0 AND "
        "(e.probability < 0.01 OR e.probability IS NULL);\n"
        "- Biggest movers: SELECT cve_id, previous_probability, probability, "
        "probability - previous_probability AS delta FROM epss_scores WHERE "
        "previous_probability IS NOT NULL ORDER BY delta DESC LIMIT 20;\n\n"
        "## Composite Risk Score (v_cve_risk)\n\n"
        "v_cve_risk blends all four signals plus CWE weakness class into one 0-100 "
        "number, so 'what do I patch first?' is one ORDER BY instead of a bespoke "
        "four-way JOIN with an ad-hoc ranking invented per question.\n"
        "- It is a BLEND, not a fifth signal. When the question is specifically "
        "about likelihood or severity, cite epss_probability or cvss_score directly "
        "rather than risk_score.\n"
        "- Weights: CVSS 0.25, EPSS 0.30, KEV listing 0.20, KEV ransomware use 0.10, "
        "SSVC up to 0.10, CWE class 0.05. The c_* columns give each contribution, so "
        "you can answer 'why is this ranked here?' from the row itself.\n"
        "- Bands are relative to THIS corpus, not absolute: 0-24 low, 25-44 moderate, "
        "45-64 high, 65-100 critical. Critical effectively requires confirmed "
        "exploitation — a CVE not on KEV tops out around 61 — so risk_score >= 45 "
        "without a KEV listing is the early-warning population, not a middling one.\n"
        "- cvss_imputed = TRUE means the CVSS input was a neutral 5.0 prior, NOT a "
        "measured score: that CVE has not been assessed yet (usually because it is "
        "new). Say so when reporting such a CVE, and add WHERE NOT cvss_imputed when "
        "precision matters more than coverage.\n"
        "- A missing EPSS row contributes 0 and means UNSCORED, never zero risk. The "
        "view LEFT JOINs, so those CVEs are present with epss_probability NULL.\n"
        "- Use the risk_score TOOL for a handful of named CVEs; use this VIEW for "
        "ranking, filtering, and counting. Do not call the tool 25 times where one "
        "ORDER BY would do.\n"
        "Example queries:\n"
        "- What to patch first: SELECT cve_id, risk_score, cvss_score, "
        "epss_probability, kev_listed FROM v_cve_risk ORDER BY risk_score DESC LIMIT 20;\n"
        "- Early warning (high composite risk, not yet confirmed exploited): SELECT "
        "cve_id, risk_score, epss_probability, epss_percentile FROM v_cve_risk WHERE "
        "NOT kev_listed AND risk_score >= 45 ORDER BY risk_score DESC;\n"
        "- Band distribution: SELECT CASE WHEN risk_score >= 65 THEN 'critical' WHEN "
        "risk_score >= 45 THEN 'high' WHEN risk_score >= 25 THEN 'moderate' ELSE "
        "'low' END AS band, COUNT(*) FROM v_cve_risk GROUP BY 1 ORDER BY 1;\n\n"
        "## Thematic questions (concept \u2192 CVEs)\n\n"
        "A thematic label — 'typosquatting', 'prompt injection', 'clickjacking' — "
        "has two independent routes into the corpus, and they surface different "
        "CVEs:\n"
        "- WEAKNESS CLASS: cwes && ARRAY['CWE-...'] over nvd_vulnerabilities (and "
        "kev_vulnerabilities). Works when NVD analysts encode the concept as a "
        "weakness.\n"
        "- DESCRIPTION TEXT: description ILIKE on the concept's own vocabulary. "
        "Works for emerging threats, which appear in prose long before the "
        "taxonomy catches up.\n"
        "Run BOTH and reconcile — neither is a fallback for the other. Report which "
        "routes you used and what each returned, so the user can judge the mapping.\n"
        "- Verify a CWE is actually populated before relying on it, and before "
        "dismissing a topic because it came back empty: SELECT count(*) FROM "
        "nvd_vulnerabilities WHERE 'CWE-x' = ANY(cwes). A CWE can exist in the "
        "taxonomy and be assigned to nothing — CWE-1427 (LLM prompting) has ZERO "
        "rows here, while 121 CVEs describe prompt injection in their text.\n"
        "- Never substitute a generic parent CWE for a specific concept. Those same "
        "121 CVEs carry CWE-94/CWE-77/CWE-74, and CWE-94 alone holds 6886 rows that "
        "are mostly unrelated to prompt injection. A broad weakness class is not "
        "evidence about a narrow theme.\n"
        "- Worked mapping — supply chain / malicious packages / typosquatting / "
        "dependency confusion: CWE-506 (Embedded Malicious Code — the usual tag for "
        "a malicious release published to PyPI, npm, or crates.io), CWE-829, "
        "CWE-494, CWE-1104, CWE-1357, plus ILIKE on '%typosquat%' and "
        "'%malicious package%'.\n"
        "- Unsure which CWEs a concept maps to: SELECT cwe_id, name FROM "
        "cwe_definitions WHERE name ILIKE '%...%'; the taxonomy is only 944 rows. "
        "Their descriptions are one-liners that rarely contain the concept's own "
        "vocabulary (nothing in cwe_definitions says 'squatting'), so search names "
        "and lean on your own knowledge of the taxonomy.\n"
        "- Only when BOTH routes come back empty is 'not in this data' the honest "
        "answer. Some concepts genuinely are absent — say so plainly then.\n"
        "Example query: SELECT cve_id, published, cvss_v31_score, description FROM "
        "nvd_vulnerabilities WHERE cwes && ARRAY['CWE-506','CWE-1104','CWE-1357'] "
        "OR description ILIKE '%typosquat%' OR description ILIKE '%malicious package%' "
        "ORDER BY published DESC;\n\n"
        "## Tools\n\n"
        "- **retrieve**: semantic search across both datasets. Use for conceptual "
        "questions whose wording appears in the CVE text itself (e.g. 'tell me "
        "about Log4j'). It matches literal phrasing, so an abstract label returns "
        "collisions rather than nothing — 'typo squatting' retrieves Squid proxy "
        "CVEs. For a thematic question treat its hits as a lead to confirm with "
        "SQL, never as the answer; see Thematic questions above.\n"
        "- **query**: execute SQL. Use for counts, top-N, date filters, "
        "grouping, listing, JOINs across tables, and specific CVE ID lookups. "
        "For CVE ID lookups, always query BOTH kev_vulnerabilities AND "
        "nvd_vulnerabilities before concluding a CVE is not found — a CVE "
        "may exist in NVD without appearing in KEV.\n"
        "- **risk_score**: composite 0-100 score with a per-signal breakdown for up "
        "to 25 NAMED CVEs, ranked highest-risk first. For ranking, filtering, or "
        "counting across the corpus, query v_cve_risk with **query** instead.\n\n"
        "Answer concisely. Before reporting that a topic is absent or outside this "
        "database's scope, run at least one SQL check: the corpus is all of NVD "
        "(380k+ CVEs), not just the KEV subset, and empty semantic-search results "
        "are evidence about the phrasing, not about the data. If a check does come "
        "back empty, say so plainly. "
        "When the user asks a follow-up question, use the conversation history "
        "to resolve references (e.g., 'it', 'that CVE', 'the one you just described') "
        "before querying the database."
    )

    # OAuth
    oauth_github_client_id: str | None = None
    oauth_github_client_secret: str | None = None
    # oauth_google_client_id / oauth_google_client_secret (optional alternative — see Step 4)

    # Authorization
    # pydantic-settings parses list[str] env vars as JSON arrays (e.g. ALLOWED_EMAILS=["a@x.com"]),
    # the same convention as the existing ACTION_BUTTONS field — not comma-separated.
    allowed_email_domains: JsonStrList = []  # e.g. ["mycompany.com"]
    allowed_emails: JsonStrList = []  # explicit email addresses only
    allowed_logins: JsonStrList = []  # GitHub usernames (login field)
    open_registration: bool = False  # True = any OAuth user allowed

    # Rate Limiting
    daily_query_limit: int = 20
    # Elevated cap for admin/trusted users, keyed by stable GitHub identifier
    # (e.g. ADMIN_USER_IDENTIFIERS=["github:12345678"]). Identifiers not listed
    # get daily_query_limit. JSON-array env var, like the allow-list fields.
    admin_daily_query_limit: int = 100000
    admin_user_identifiers: JsonStrList = []

    # Admin Dashboard
    # HTTP Basic Auth password for /admin. An empty value would let
    # `Authorization: Basic <base64 of ":">` through, so app.py fails fast at
    # startup if this is unset. Set a strong random value (e.g. openssl rand -hex 32).
    admin_secret: str = ""

    # Token Cost Estimation (USD per million tokens) — used by the /admin dashboard
    # to estimate spend from recorded token totals. One source of truth: usage.py
    # reads these via arguments rather than its own constants.
    llm_input_cost_per_million: float = 3.00
    llm_output_cost_per_million: float = 15.00

    # MCP Server
    mcp_api_key: str | None = None

    # Action Buttons (optional)
    action_buttons: JsonStrList = []

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()
