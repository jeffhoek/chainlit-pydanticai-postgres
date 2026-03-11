from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # API Keys (anthropic is optional — not needed by ETL scripts)
    anthropic_api_key: Optional[str] = None
    openai_api_key: str
    nvd_api_key: Optional[str] = None

    # PostgreSQL Configuration
    # Use PG_DATABASE_URL (not DATABASE_URL) to avoid Chainlit auto-activating its data layer
    pg_database_url: Optional[str] = None
    pg_host: str = "localhost"
    pg_port: int = 5432
    pg_user: str = "postgresuser"
    pg_password: str = ""
    pg_database: str = "inventory"

    def get_database_dsn(self) -> str:
        if self.pg_database_url:
            return self.pg_database_url
        return f"postgresql://{self.pg_user}:{self.pg_password}@{self.pg_host}:{self.pg_port}/{self.pg_database}"

    # RAG Configuration
    top_k: int = 5
    llm_model: str = "anthropic:claude-haiku-4-5-20251001"
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
        "  last_modified DATE\n"
        ")\n\n"
        "JOIN tables on cve_id to cross-reference KEV and NVD data.\n\n"
        "## Tools\n\n"
        "- **retrieve**: semantic search across both datasets. Use for "
        "conceptual questions (e.g. 'tell me about Log4j').\n"
        "- **query**: execute SQL. Use for counts, top-N, date filters, "
        "grouping, listing, and JOINs across tables.\n\n"
        "Answer concisely. If the answer is not in the data, say so."
    )

    # Action Buttons (optional)
    action_buttons: list[str] = []

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()
