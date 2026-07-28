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
        "## Tools\n\n"
        "- **retrieve**: semantic search across both datasets. Use for "
        "conceptual questions (e.g. 'tell me about Log4j').\n"
        "- **query**: execute SQL. Use for counts, top-N, date filters, "
        "grouping, listing, JOINs across tables, and specific CVE ID lookups. "
        "For CVE ID lookups, always query BOTH kev_vulnerabilities AND "
        "nvd_vulnerabilities before concluding a CVE is not found — a CVE "
        "may exist in NVD without appearing in KEV.\n\n"
        "Answer concisely. If the answer is not in the data, say so. "
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
