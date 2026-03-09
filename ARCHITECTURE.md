# SovereignShield — Architecture

## Purpose

SovereignShield is a Shiny for Python sovereign cloud compliance app. It ingests Terraform state, evaluates resources against OPA policies, and provides AI-assisted remediation via agents and RAG.

---

## Component Map

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SovereignShield (Shiny App)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  app.py (main)                                                              │
│    ├── CloudResource dataclass (typed)                                      │
│    ├── core/tf_parser.py — parse .tfstate JSON → list[CloudResource]        │
│    ├── core/opa_eval.py — OPA policy evaluation                             │
│    ├── agents/ — AI orchestration (Anthropic)                               │
│    ├── rag/ — embedding + retrieval for context                             │
│    └── policies/ — OPA Rego policies                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Module Reference

| Module | Role |
|--------|------|
| `app.py` | Main Shiny UI + server, CloudResource dataclass |
| `core/tf_parser.py` | Terraform state parser — `parse_tfstate(path)`, `parse_tfstate_dict(state)` |
| `core/opa_eval.py` | OPA evaluation against policies |
| `agents/` | AI agents (remediation, analysis) |
| `rag/` | RAG pipeline for policy/docs context |
| `policies/` | OPA Rego files |

---

## Data Flow

```
.tfstate JSON → tf_parser → list[CloudResource]
                                   │
                                   ├──► OPA eval → violations
                                   ├──► RAG → context for agents
                                   └──► Supabase agent_interactions
```
