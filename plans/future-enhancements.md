# Future Enhancements

Potential improvements and feature additions for the vulnerability research
chatbot, organized by production priority. High-priority items signal that the
system is designed to operate reliably, securely, and measurably — not just
demo-able. Medium items are either actively in flight or deliver meaningful
engineering value once the core is solid. Nice-to-have items expand reach and
polish but are not the difference between a toy and a product. The Recently
Shipped section at the top records items that have graduated into production.

## Recently Shipped

Items that have graduated from this list into production. Kept here briefly for
context on what the remaining work builds on.

### Per-User GitHub OAuth ✅ *(PRs [#85](https://github.com/jeffhoek/vulncopilot/pull/85), [#86](https://github.com/jeffhoek/vulncopilot/pull/86))*

Replaced the single shared username/password with per-user GitHub OAuth and a
login allow-list, so access is tied to real identities. This is the identity
foundation the remaining Role-Based Access Control work (tiered permissions,
below) builds on. See [public-access-plan.md](public-access-plan.md).

### Per-User Daily Rate Limiting ✅ *(PR [#88](https://github.com/jeffhoek/vulncopilot/pull/88))*

Atomic per-user daily query caps tracked in Postgres (`user_usage`), with an
elevated limit override for admins. Closes the public-abuse window that OAuth
alone left open.

### Admin Usage & Cost Dashboard ✅ *(PR [#91](https://github.com/jeffhoek/vulncopilot/pull/91))*

A `/admin` page (HTTP Basic Auth) showing per-user query volume, token usage,
and estimated LLM cost. Partially satisfies **Cost Tracking** below — the
remaining gap is per-query attribution rather than per-user/day aggregates.

### Automated ETL Scheduling ✅

KEV and NVD loaders now run unattended on a cron schedule via an **Azure
Container Apps Job** (`job-vulncopilot-etl-<env>`), reusing the app image and
pulling secrets from Key Vault via managed identity. Cadence is set by
`etlCronExpression` in `infra/parameters.dev.bicepparam`. See
[Scheduled ETL Refresh](../docs/deploy-azure-app-service.md#scheduled-etl-refresh-container-apps-job).
The remaining gap is the **data freshness indicator** in the UI / API
responses ("KEV last synced: 4 hours ago") — the scheduling half is done; the
surfacing half is not.

### SSVC Integration ✅ *(PR [#126](https://github.com/jeffhoek/vulncopilot/pull/126); plan: [ssvc-affected-integration.md](ssvc-affected-integration.md))*

NVD began publishing CISA-ADP **SSVC** (Stakeholder-Specific Vulnerability
Categorization) decision factors and CVE-Record-Format **affected** data inside
the CVE API as of **2026-06-17**. SSVC answers *"how urgently should I act?"* —
the three CISA factors `exploitation` (none/poc/active), `automatable` (yes/no),
and `technicalImpact` (partial/total) — and complements CVSS the same way EPSS
does: severity is not the same as priority.

Shipped through Tier 1: the SSVC factors are promoted to typed, indexed columns
on `nvd_vulnerabilities`, wired into both NVD loaders (with a `--backfill-ssvc`
mode to populate them from existing `raw_json`), surfaced alongside affected
vendor/product in the embedded `content`, and taught to the agent via the system
prompt plus SSVC quick-query buttons (PR
[#130](https://github.com/jeffhoek/vulncopilot/pull/130)). This unlocks the
"active + automatable + total technical impact = top remediation priority"
ranking and gives the Composite Risk Score and retrieval scoring a second
prioritization signal to blend alongside EPSS. Remaining follow-on is **Tier 2**
— promoting `affected` vendor/product/version *ranges* to structured columns.

### EPSS Score Ingestion ✅ *(PR [#133](https://github.com/jeffhoek/vulncopilot/pull/133); plan: [epss-score-integration.md](epss-score-integration.md); docs: [epss-integration.md](../docs/epss-integration.md))*

Loads the [Exploit Prediction Scoring System](https://www.first.org/epss/) daily
feed from FIRST.org into an `epss_scores` table keyed by CVE ID. EPSS gives
each CVE a probability (0.0–1.0) that it will be exploited in the wild within
the next 30 days, plus a percentile rank against all scored CVEs. It fills the
gap between CVSS ("how bad if exploited") and KEV ("confirmed exploited now"):
a CVSS 9.8 with EPSS 0.001 is likely noise, while a CVSS 6.5 with EPSS 0.95
deserves attention this week.

Shipped: `scripts/load_epss.py` bulk-loads the daily feed (**353,212 rows in
~2.3s** via a temp-staging COPY + upsert) and runs as a third step in
`run_etl.py`; the agent learned the table, a four-signal primer
(severity/likelihood/confirmed/urgency), the mandatory `LEFT JOIN`, and the
score-distribution bands via the system prompt, MCP docstring, and three EPSS
quick-query buttons. This unlocks the leading-indicator query — "high-EPSS CVEs
that aren't on KEV yet" — and gives the Composite Risk Score its load-bearing
input.

Notes worth carrying forward:

- **Source moved**: the long-documented `epss.cyentia.com` host now only
  redirects to `epss.empiricalsecurity.com`, and `-current` redirects again to a
  dated file. httpx needs explicit `follow_redirects=True`.
- **Separate table, not columns on `nvd_vulnerabilities`** — EPSS republishes
  every score daily, and under MVCC that would rewrite each row's `raw_json` and
  1536-dim `embedding` (plus HNSW maintenance) ~353k times a day.
- **Deferred**: `epss_scores_history` (129M rows/year — `previous_probability`
  covers "what moved" at zero cost) and surfacing EPSS in `retrieve` result
  cards, which needs a `vector_store.search` signature change.

### Composite Risk Score ✅ *(plan: [composite-risk-score.md](composite-risk-score.md); docs: [risk-scoring.md](../docs/risk-scoring.md))*

Blends all four prioritization signals — CVSS severity, EPSS likelihood, KEV
confirmed exploitation, SSVC urgency — plus CWE weakness class as a 0.05
tiebreaker into one 0–100 number with a per-signal breakdown. Turns *"what do I
patch first?"* from a bespoke four-way JOIN with a ranking invented per turn into
`SELECT cve_id, risk_score FROM v_cve_risk ORDER BY risk_score DESC`.

Shipped: a `v_cve_risk` view (one row per CVE in NVD **or** KEV, six `c_*`
contribution columns beside the score) and a `risk_score(cve_ids)` tool on both
the agent and the MCP server, taking up to 25 IDs and returning score, band,
components, and a prose rationale; plus the system-prompt primer, MCP docstring,
and three quick-query buttons.

Notes worth carrying forward:

- **One source of truth, in SQL.** `rag/risk.py` owns the constants and
  *generates* the view DDL from them; the arithmetic runs only in Postgres. The
  obvious "view plus a Python blender" design is two implementations that drift
  on the first weight edit, and CI never notices because the Python one still
  passes its own tests.
- **The bands were the real finding.** `ssvc_exploitation='active'` is a KEV
  alias (the two sets differ by 6 rows in 371k), so a non-KEV CVE tops out at
  **61**. The originally sketched 70/85 cut-points made "high" unreachable off
  KEV, which defeats the "high-EPSS, not yet on KEV" query. Recalibrated to
  25/45/65, which puts ~1,874 non-KEV CVEs in the high band.
- **Missing CVSS is imputed, not zeroed.** 25,727 rows have no CVSS at all and
  40% of those were published in 2025+; a neutral 5.0 prior with `cvss_imputed`
  exposed beats making the ranking blind to the newest records.
- **CWEs are concatenated across NVD and KEV, not coalesced** — ~93 KEV CVEs
  hold real weakness IDs in KEV while NVD has only `NVD-CWE-*` placeholders, and
  a COALESCE never fires because the NVD array is non-empty, just useless.
- **Deferred**: materializing the view (only if measurement shows the plain one
  is too slow — same object name, so it's a rollout change), learned weights
  (needs the Langfuse usage data this ships the instrumentation for), and risk
  scores in `retrieve` result cards (same `vector_store.search` signature change
  already deferred for EPSS — do both at once).

**Unblocks**: Software Inventory Matching (rank only the CVEs that apply),
Alerting (threshold on risk band rather than raw CVSS), and Retrieval Scoring
Beyond Vector Similarity (reuse `v_cve_risk` as the ranking weight).

## High Priority — Production-Readiness

### Software Inventory Matching

Let users paste or upload a dependency manifest (`composer.lock`,
`package-lock.json`, `requirements.txt`, `Gemfile.lock`, SPDX/CycloneDX SBOM,
or a plain CPE list) and persist the parsed package + version list per user.
On each refresh, join the inventory against KEV and NVD on CPE/PURL to
produce a personalized "what's wrong with my stack" view. Pair with the
Composite Risk Score to rank only the CVEs that actually apply.

- **Schema**: `user_inventories(id, user_id, name, source_format, parsed_at)`
  + `inventory_items(inventory_id, ecosystem, package, version, cpe, purl)`.
- **Matching**: NVD configurations already contain CPE match strings; for
  package ecosystems, supplement with OSV or GHSA (see Additional Data
  Sources). Start with exact version matching; add range matching second.
- **Tool surface**: a `match_inventory(inventory_id)` tool that returns the
  joined CVE list, optionally filtered by KEV / EPSS threshold / risk band.
- **Unlocks**: "Of the 4,200 CVEs added this quarter, which 12 affect my
  stack and are on KEV?" — the question this project can't answer today
  without external tooling.

This is the feature that turns the project from "ask about CVEs in general"
into "tell me what's wrong with *my* environment," and pairs naturally with
Alerting (filter notifications to inventory matches only) and the Composite
Risk Score (rank what's worth patching first).

### Alerting & Notifications

Subscribe to alerts when new KEV entries match specific criteria such as vendor,
product, or severity threshold.

### Evaluation Framework *(in flight: PR [#65](https://github.com/jeffhoek/vulncopilot/pull/65))*

Build a test suite of question/answer pairs to systematically measure and track
retrieval quality and agent accuracy over time. Approach in two phases:

- **Offline evals in-repo**: unit-test-style assertions using
  [Ragas](https://ragas.io/) or [autoevals](https://github.com/brainlid/autoevals)
  measuring context recall, answer correctness, and faithfulness via
  LLM-as-judge. Run in CI against a fixed golden dataset.
- **Online evals via Logfire**: once the offline baseline is established,
  sample production queries and score grounding and domain relevance directly
  in Logfire to catch regressions in live traffic.

### Persistent Conversation History

Store chat history in the database so users can resume previous conversations
across sessions.

### Cost Tracking

Monitor LLM token usage and embedding API costs on a per-query basis to manage
operational expenses. The Admin Usage & Cost Dashboard (see Recently Shipped)
already covers per-user/day token totals and estimated cost; the remaining work
is *per-query* attribution and embedding-call cost, plus surfacing it outside
the admin page.

### User Feedback Loop

Let users rate responses (thumbs up/down) to build a signal for prompt tuning
and retrieval optimization.

## Medium Priority — In-Flight or High-Value

### Role-Based Access Control — Permission Tiers

The OAuth identity foundation and admin gate already shipped (see Recently
Shipped); what remains is graduating from a binary user/admin split to real
permission *levels* — e.g. read-only analyst, power user, and admin (who can
trigger data loads or manage configuration). Now a smaller, additive change on
top of the existing `oauth_callback` and admin checks rather than a from-scratch
auth effort, which is why it drops from High to Medium.

### OWASP Top 10 (2025) Integration

Ingest the OWASP Top 10:2025 web app risk categories as a curated taxonomy
layer that bridges existing CWE data to practitioner-facing remediation
guidance. The load-bearing piece is the **CWE-to-category mapping table**:
it lets the agent answer category-framed counting and aggregation
questions via SQL JOINs through the existing `cwes TEXT[]` columns on KEV
and NVD. The category prose (description, "How to Prevent," example
scenarios) is a secondary asset, embedded for semantic retrieval on
prose-heavy questions.

**Two execution paths**

1. **SQL via mapping table** — for "how many," "which," "list," "group by"
   questions. The agent uses `OWASP category → CWE → CVE (NVD) → KEV`
   JOINs. No retrieval needed; the OWASP IDs are taught in the system
   prompt as a fixed enumeration of 10.
2. **Retrieval over OWASP prose** — for "what is X," "how do we prevent
   Y," or fuzzy framings ("session hijacking" → A07). Embeddings on the
   description + prevention + examples earn their keep here.

Most useful answers blend both: SQL produces the linkage and counts,
retrieval (or a direct SELECT once the category id is known) supplies the
remediation prose.

**Key points**

- **Schema**: `owasp_top10_categories` (id, name, description, prevention,
  examples, url, list_type, embedding) + `owasp_cwe_mapping` (owasp_id,
  cwe_id). The mapping table is the integration's center of gravity; the
  embedding column is additive for prose retrieval.
- **Sourcing**: pull from https://owasp.org/Top10/2025/ — 10 stable,
  well-structured pages, each with a "List of Mapped CWEs" section.
  Either (a) hand-curate a JSON in `data/` (simplest given 10 rows that
  change every ~3 years) or (b) parse the canonical markdown from the
  [OWASP/Top10 GitHub repo](https://github.com/OWASP/Top10) (structured,
  version-controlled, easy to re-run on new releases). Unlike the
  deprioritized reference-URL effort, this is 10 known cooperative pages.
- **Tool surface**: extend `retrieve()` to include OWASP rows alongside
  KEV/NVD. Update the system prompt to list the 10 category IDs and
  include example JOIN patterns through `owasp_cwe_mapping`.
- **Mapping precision**: start with OWASP's official CWE mappings (~248
  CWEs total). Resist transitively expanding via CWE parent/child
  relationships in v1 — adds recall but editorializes past OWASP's
  framing.
- **Future extension**: same schema accommodates the OWASP Top 10 for LLM
  Applications (2025) via the `list_type` column. Worth adding once the
  web list pattern is proven; the LLM list is standalone (no meaningful
  CVE bridge) but is self-applicable to this RAG app and timely.

**Example queries this unlocks** (path = SQL / retrieval / both)

- *(SQL)* "How many actively exploited (KEV) CVEs fall under Broken Access
  Control?"
- *(SQL)* "Which OWASP 2025 category has the most KEV entries in the last
  90 days?"
- *(both)* "For CVE-2024-XXXX, what does OWASP recommend for prevention?"
  — SQL traces CVE → CWE → category; SELECT/retrieval pulls the prose.
- *(both)* "Summarize KEV trends grouped by OWASP category."
- *(retrieval + SQL)* "What is Software Supply Chain Failures and which
  recent CVEs are examples?"

This is the curated alternative to the broad reference URL scraping effort
below — same goal (surface remediation context next to CVE data) at a
fraction of the operational cost.

### STIG / IAVA Compliance Data *(plan: [stig-iava-integration.md](stig-iava-integration.md))*

Ingest DISA IAVA mandatory-remediation orders and STIG check findings,
cross-referenced with KEV/NVD CVEs and the CWE taxonomy. The full plan is
phased:

- **Phase 1 — IAVA (the high-value, low-cost part)**: a new `iava_entries`
  table joined to KEV/NVD on `cve_id`, a `load_iava.py` loader, and a
  `lookup_compliance(cve_id)` tool. Answers "which of our unpatched CVEs carry
  mandatory DoD remediation orders?" — a question no current tool handles.
- **Phase 2 — STIG findings**: per-product XCCDF ZIP parsing (no bulk
  download), CVE/CCI/CWE cross-refs. Meaningfully more loader complexity.
- **Phase 3 — CCI → NIST 800-53 mapping**: closes the RMF loop (CVE → IAVA →
  STIG → CCI → control).

Kept at Medium rather than High because its value is **audience-specific** — it
matters a lot to DoD/federal users and little to everyone else, unlike EPSS and
SSVC which are universal CVE signals. If the target audience shifts toward
federal/compliance, Phase 1 alone is cheap enough to justify promoting.
See [stig-iava-integration.md](stig-iava-integration.md) for the full plan.

### Hybrid Search with BM25

Combine vector similarity with PostgreSQL full-text search (`tsvector`) to
improve keyword matching alongside semantic understanding.

### Reranking

Add a cross-encoder reranker after initial vector retrieval to improve result
relevance, especially for ambiguous or broad queries.

### Query Routing

Automatically determine whether a user question is best served by semantic
search, direct SQL, or a combination of both.

### Retrieval Scoring Beyond Vector Similarity

Weight retrieval results using domain-specific signals in addition to cosine
similarity, so that higher-priority vulnerabilities surface first regardless of
query phrasing:

- **KEV status** — known-exploited CVEs rank above non-KEV results at equal
  similarity
- **EPSS score** — now ingested (see Recently Shipped), use `probability` as a
  retrieval weight via a `LEFT JOIN epss_scores`
- **SSVC factors** — now ingested (see Recently Shipped), boost
  `exploitation=active` / `automatable=yes` records as a triage signal
- **Recency** — `date_added` to KEV or NVD publish date as a decay factor
- **User feedback** — upvoted CVEs gain a small boost (ties into User Feedback
  Loop)
- **Top-K tuning** — as more datasets are added (STIG/IAVA, OWASP, GitHub
  advisories), increase top-K and rely on Reranking to maintain precision

Implementable as a weighted scoring expression in pgvector alongside the
existing similarity query.

### REST API Endpoint

Provide a programmatic API for other security tools (SIEM, SOAR, ticketing
systems) to query the vulnerability knowledge base.

### Semantic Caching

Cache embeddings and responses for near-duplicate queries so repeated or similar
questions skip the LLM call entirely. Reduces latency and token costs
meaningfully in multi-user deployments, and complements Cost Tracking by
lowering the baseline spend.

## Nice-to-Have — Cool Features

### Reference URL Content Scraping *(deprioritized; PR #45 stalled)*

NVD stores up to ten `reference_urls` per CVE pointing to vendor advisories,
patch notes, proof-of-concept write-ups, and security blog posts. The original
intent was to scrape those pages into a dedicated `cve_references` table with
embeddings so RAG retrieval could surface remediation snippets alongside core
CVE data.

Deprioritized because scraping thousands of unknown pages turned out to be a
high-cost, low-signal effort — redirects, paywalls, dead links, robots.txt
constraints, and inconsistent content quality made the value uncertain. The
OWASP Top 10 (2025) integration above covers the core remediation-guidance
need at a tiny fraction of the operational complexity. Revisit only if a
specific question class proves OWASP + STIG/IAVA isn't enough.

If revisited, considerations:

- Filter low-value URLs at ingest time (dead links, paywalled pages, NVD
  self-referential links, social media)
- Summarize long pages with an LLM call before embedding to keep chunk quality
  high
- Respect `robots.txt` and rate-limit scraping to avoid being blocked by vendor
  sites
- Re-scrape on a schedule so content stays current as advisories are updated

### Multi-Agent Architecture

Introduce specialized agents for different tasks (triage, reporting, trend
analysis) orchestrated by a router agent that delegates based on query intent.
Only justified if Query Routing proves insufficient — smart dispatch within a
single agent should be the first attempt.

### Charting & Visualization Tool

Give the agent a tool to generate charts and graphs, such as vulnerabilities by
severity over time, top affected vendors, or ransomware campaign trends.

### Export Tool

Generate downloadable PDF or CSV reports from query results for sharing with
stakeholders who don't use the chatbot directly.

### Slack & Teams Integration

Expose the chatbot in messaging platforms so analysts can query vulnerability
data without leaving their primary communication tool. Downstream of the REST
API — build the API first and Slack/Teams become thin wrappers around it.

### Streaming Citations

Display source CVE IDs inline as the agent responds, linked directly to NVD and
KEV detail pages for verification.

### Additional Data Sources

Ingest supplementary vulnerability intelligence such as:

- **OSV / GitHub Security Advisories** — package-ecosystem coverage that NVD
  lags on; also unlocks PURL-based matching for Software Inventory Matching
- **MITRE ATT&CK** — technique mapping as a second taxonomy axis alongside CWE
- **Exploit-DB** — proof-of-concept exploit availability
- **Vendor-specific advisories** — Microsoft, Cisco, Adobe, etc.
