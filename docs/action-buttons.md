# Configurable Chainlit Action Buttons

## Overview

The RAG chatbot supports configurable action buttons on the welcome message. These provide users with quick-access "suggested question" shortcuts — useful for domain-specific deployments where common queries are known in advance.

**Behavior:** Buttons appear on the "Ready!" welcome message. Clicking a button sends that button's label text as a RAG query to the agent (same as typing and submitting the message).

## Configuration

Set `ACTION_BUTTONS` to a JSON array of label strings. Any number of buttons is supported. Unset or empty means no buttons render.

### `.env` / environment variables

```env
ACTION_BUTTONS=["List the 10 newest KEV entries by date_added","CVE-2021-44228 (Log4Shell)","Top 10 AI-related CVEs in 2026 by CVSS score","Anthropic Claude vulns","LLM prompt injection vulns","Which weakness types appear most in KEV?"]
```

### Kubernetes ConfigMap (`k8s/configmap.yaml`)

```yaml
data:
  ACTION_BUTTONS: '["List the 10 newest KEV entries by date_added","CVE-2021-44228 (Log4Shell)","Top 10 AI-related CVEs in 2026 by CVSS score","Anthropic Claude vulns","LLM prompt injection vulns","Which weakness types appear most in KEV?"]'
```

Note: quotes around the value are required in YAML because JSON brackets would otherwise be misinterpreted.

### Designing good buttons

Good buttons exercise the full range of what the agent can do. Aim for a mix that covers:

| Pattern | Example button | Why |
|---|---|---|
| SQL → KEV | `"List the 10 newest KEV entries by date_added"` | Date-sorted query against `kev_vulnerabilities`. Naming the `date_added` column anchors the query to SQL — a vaguer phrasing like `"Latest KEV additions"` can get routed to `retrieve` (semantic search), which returns the same static top-k every time instead of the newest rows. |
| SQL → NVD | `"Top 10 AI-related CVEs in 2026 by CVSS score"` | CVSS + date filter against `nvd_vulnerabilities` |
| SQL → CWE join | `"Which weakness types appear most in KEV?"` | Joins `kev_vulnerabilities` → `cwe_definitions` |
| SQL → landmark CVE | `"CVE-2021-44228 (Log4Shell)"` | Direct CVE lookup. The parenthetical nickname keeps the label recognizable and gives the agent routing context — a bare product/vendor name with no vuln wording (e.g. `"Anthropic Claude"`) can be misread as a question about the assistant itself and refused. Prefer `"Anthropic Claude vulns"`. |
| SQL → specific CVE with URLs | `"Reference URLs for CVE-2025-53770 (SharePoint ToolShell)"` | Fetches `reference_urls` from `nvd_vulnerabilities` |
| Semantic search | `"LLM prompt injection vulns"` | Triggers the `retrieve` tool via embedding similarity |
| SQL → SSVC prioritization | `"Top actively-exploited, automatable, total-impact CVEs"` | Filters `nvd_vulnerabilities` on the SSVC columns (`ssvc_exploitation`/`ssvc_automatable`/`ssvc_technical_impact`) — CISA's "patch now" set — ordered by CVSS |
| SQL → SSVC vs CVSS | `"CVSS 10.0 CVEs not yet exploited (SSVC none)"` | Demonstrates severity ≠ urgency: a max CVSS score with `ssvc_exploitation='none'` isn't top priority yet |

Buttons that mention URLs (e.g. "Reference URLs for …") explicitly signal to the agent to select `reference_urls` from NVD, which it may otherwise omit.

Test semantic phrasings against real retrieval before shipping them: embedding search matches on literal wording, so a thematic label like `"Supply chain attack vulns"` returns keyword collisions (Oracle's "Supply Chain Products Suite") rather than SolarWinds-style incidents. Landmark CVEs (Log4Shell, EternalBlue, MOVEit, ToolShell) make reliable buttons because a CVE ID always resolves via SQL.

## Implementation Details

- pydantic-settings v2 parses `list[str]` from a JSON array string automatically — no custom validator needed
- All buttons share the action name `"quick_query"` — one `@cl.action_callback` handles all of them
- The button label text IS the query (`payload={"query": label}`), keeping label and behavior in sync
- If `ACTION_BUTTONS` is unset, `actions=[]` is passed and no buttons render (backward compatible)

## Verification

1. Set `ACTION_BUTTONS='["What is this about?","Give me a summary"]'` in `.env`, run `uv run chainlit run app.py`
2. Confirm both buttons appear on the "Ready!" message and after each response
3. Remove `ACTION_BUTTONS` — confirm no buttons render and no errors
4. Test with a single-item list and a 6+ item list to confirm no artificial limit
