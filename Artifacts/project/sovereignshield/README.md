---
title: SovereignShield
emoji: 🛡️
colorFrom: indigo
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
license: mit
---

# SovereignShield — Compliance Remediation

Sovereign cloud compliance app: OPA evaluate → Planner → Worker → Reviewer → RAG/Supabase.

## Secrets (Space Settings)

Add these in **Settings → Repository secrets**:

| Secret | Description |
|--------|-------------|
| `ANTHROPIC_API_KEY` | Claude API key for Planner/Worker/Reviewer agents |
| `SUPABASE_URL` | Supabase project URL |
| `SUPABASE_ANON_KEY` | Supabase anon/service key |

Optional: `HF_TOKEN` for higher Hub rate limits.

## Run locally

```bash
pip install -r requirements.txt
shiny run app.py --reload
```
