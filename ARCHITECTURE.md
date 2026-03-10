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

## Module Inventory

| Module | Role |
|--------|------|
| `app.py` | Main Shiny UI + server, CloudResource dataclass |
| `core/tf_parser.py` | Terraform state parser — `parse_tfstate(path)`, `parse_tfstate_dict(state)` |
| `core/opa_eval.py` | OPA evaluation against policies |
| `core/charts.py` | Plotnine chart generators: heatmap_data, mttr_trend_data, donut_data, kb_growth_data, compliance_heatmap, mttr_trend, violation_donut, kb_growth |
| `core/audit_db.py` | Supabase agent_interactions + local fallback |
| `agents/` | AI agents (remediation, analysis) |
| `rag/` | RAG pipeline for policy/docs context |
| `policies/` | OPA Rego files |
| `assets/` | Base64 QR code files for portfolio app cards |

---

## UI Layer

| Tab | Content |
|-----|---------|
| Tab 1 Catalogue | 5 columns, color-coded rows, violation detail panel |
| Tab 2 Agent Loop | 5 OPA checks, HCL diff view, MTTR timer, severity |
| Tab 3 Intelligence | Live Supabase KPIs, heatmap, trend, donut charts |
| Tab 4 Analytics | 4-KPI row, 2×2 chart grid, CSV export, refresh |
| Tab 5 About | Compliance/cloud branding, portfolio QR codes 2×2 grid |
| Tab 6 Services | Three service tiers, Gold CTA contact button |

---

## Data Flow

```
.tfstate JSON → tf_parser → list[CloudResource]
                                   │
                                   ├──► OPA eval → violations
                                   ├──► RAG → context for agents
                                   └──► Supabase agent_interactions
```

---

## Supabase Schema

Table: `agent_interactions`

| Column | Type | Notes |
|--------|------|-------|
| task_id | TEXT | PK |
| timestamp | TIMESTAMPTZ | |
| violation_type | TEXT | |
| resource_id | TEXT | |
| planner_output | TEXT | |
| worker_output | TEXT | |
| reviewer_verdict | TEXT | APPROVED, NEEDS_REVISION, REJECTED |
| reviewer_notes | TEXT | |
| is_compliant | BOOLEAN | |
| mttr_seconds | NUMERIC | |
| tokens_used | INTEGER | |
| rag_hit | BOOLEAN | |
| severity | TEXT | CHECK (HIGH\|MEDIUM\|LOW\|INFO) |

---

## Sprint History

- **Sprint 1 completed:** March 2026  
  Features: charts module, catalogue colors + violation detail, HCL diff + MTTR timer, live Intelligence KPIs, Analytics tab, About + Services pages, cross-app QR codes
