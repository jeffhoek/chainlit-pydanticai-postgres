# Configurable Chainlit Action Buttons

## Overview

The RAG chatbot supports configurable action buttons on the welcome message. These provide users with quick-access "suggested question" shortcuts — useful for domain-specific deployments where common queries are known in advance.

**Behavior:** Buttons appear on the "Ready!" welcome message. Clicking a button sends that button's label text as a RAG query to the agent (same as typing and submitting the message).

## Configuration

Set `ACTION_BUTTONS` to a JSON array of label strings. Any number of buttons is supported. Unset or empty means no buttons render.

### `.env` / environment variables

```env
ACTION_BUTTONS=["What topics are covered?","Give me a summary","What are the key points?"]
```

### Kubernetes ConfigMap (`k8s/configmap.yaml`)

```yaml
data:
  ACTION_BUTTONS: '["What topics are covered?","Give me a summary","What are the key points?"]'
```

Note: quotes around the value are required in YAML because JSON brackets would otherwise be misinterpreted.

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
