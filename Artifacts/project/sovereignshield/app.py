"""
SovereignShield — Shiny for Python sovereign cloud compliance app.
Real agent loop: OPA evaluate → Planner → Worker → Reviewer → RAG/Supabase.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from datetime import datetime
from typing import Any

# Graceful import fallback — run with simulated data if any module fails
_USE_REAL_MODULES = True
try:
    from project.sovereignshield.core.opa_eval import evaluate
    from project.sovereignshield.core.audit_db import db
    from project.sovereignshield.agents.planner import planner
    from project.sovereignshield.agents.worker import worker
    from project.sovereignshield.agents.reviewer import reviewer
    from project.sovereignshield.rag.retriever import embed_and_store, retrieve_similar
except ImportError:
    _USE_REAL_MODULES = False
    evaluate = None  # type: ignore[assignment]
    db = None  # type: ignore[assignment]
    planner = None  # type: ignore[assignment]
    worker = None  # type: ignore[assignment]
    reviewer = None  # type: ignore[assignment]
    embed_and_store = None  # type: ignore[assignment]
    retrieve_similar = None  # type: ignore[assignment]

try:
    from shiny import App, reactive, render, ui
except ImportError:
    raise ImportError("shiny is required. Run: pip install shiny")

from project.sovereignshield.models import CloudResource

# Full 5-resource catalogue
RESOURCES: list[CloudResource] = [
    CloudResource(
        resource_id="s3-phi-claims-001",
        resource_type="aws_s3_bucket",
        region="us-east-1",
        encryption_enabled=True,
        cmk_key_id="arn:aws:kms:us-east-1:123456789:key/abc-001",
        is_public=False,
        tags={"DataClass": "PHI", "Environment": "prod"},
    ),
    CloudResource(
        resource_id="s3-staging-analytics",
        resource_type="aws_s3_bucket",
        region="eu-central-1",
        encryption_enabled=False,
        cmk_key_id=None,
        is_public=False,
        tags={"Environment": "staging"},
    ),
    CloudResource(
        resource_id="rds-member-records",
        resource_type="aws_db_instance",
        region="us-east-1",
        encryption_enabled=True,
        cmk_key_id="arn:aws:kms:us-east-1:123456789:key/abc-002",
        is_public=False,
        tags={"DataClass": "PHI", "Environment": "prod"},
    ),
    CloudResource(
        resource_id="rds-dev-sandbox",
        resource_type="aws_db_instance",
        region="us-west-2",
        encryption_enabled=False,
        cmk_key_id=None,
        is_public=True,
        tags={"Environment": "dev"},
    ),
    CloudResource(
        resource_id="lambda-eligibility",
        resource_type="aws_lambda_function",
        region="us-east-1",
        encryption_enabled=True,
        cmk_key_id="arn:aws:kms:us-east-1:123456789:key/abc-003",
        is_public=False,
        tags={"DataClass": "PHI", "Environment": "prod"},
    ),
]

# Seed events for System Intelligence fallback when db is unavailable
_SEED_EVENTS: list[dict[str, Any]] = [
    {
        "task_id": "seed-001",
        "timestamp": "2025-03-09T12:00:00",
        "violation_type": "data_residency",
        "resource_id": "s3-staging-analytics",
        "planner_output": "Add CMK encryption and region constraint",
        "worker_output": "resource \"aws_s3_bucket_server_side_encryption_configuration\" ...",
        "reviewer_verdict": "APPROVED",
        "reviewer_notes": "Compliant",
        "is_compliant": True,
        "mttr_seconds": 4.2,
        "tokens_used": 646,
        "rag_hit": False,
    },
]


def _effective_log(limit: int = 10) -> list[dict[str, Any]]:
    """Fetch recent events: db.fetch_recent(limit) with local fallback to _SEED_EVENTS."""
    if _USE_REAL_MODULES and db is not None:
        return db.fetch_recent(limit)
    return list(_SEED_EVENTS)[:limit]


def _run_agents(resource_id: str, violation_type: str) -> dict[str, Any]:
    """
    Run real agent loop: evaluate → planner → worker → reviewer.
    Returns dict with trace, verdict, checks_passed, checks_failed, etc.
    """
    if not _USE_REAL_MODULES or evaluate is None or planner is None or worker is None or reviewer is None:
        return {
            "trace": "  [Simulated] Region check: ✓\n  [Simulated] CMK check: ✓\n  [Simulated] PHI tag: ✗\n",
            "verdict": "NEEDS_REVISION",
            "checks_passed": ["Region check", "CMK check"],
            "checks_failed": ["PHI DataClass tag missing"],
            "result": None,
            "plan": None,
            "work": None,
        }

    violations = evaluate(RESOURCES)
    selected = next(
        (
            v
            for v in violations
            if str(v.get("resource_id", "")) == resource_id
            and str(v.get("violation_type", "")) == violation_type
        ),
        None,
    )
    if not selected:
        return {
            "trace": "  No matching violation found.\n",
            "verdict": "REJECTED",
            "checks_passed": [],
            "checks_failed": ["Violation not found"],
            "result": None,
            "plan": None,
            "work": None,
        }

    t0 = datetime.now()
    plan = planner.run(selected)
    work = worker.run(plan)
    result = reviewer.run(plan, work, started_at=t0)

    # Dynamic waterfall trace from result.checks_passed / checks_failed
    trace = ""
    for check in result.checks_passed:
        trace += f"  ✓ {check}\n"
    for check in result.checks_failed:
        trace += f"  ✗ {check}\n"
    if not trace:
        trace = "  (no checks reported)\n"

    # On APPROVED: embed fix into RAG
    if result.verdict == "APPROVED" and embed_and_store is not None:
        detail = selected.get("detail") or (
            f"{selected.get('violation_type', '')} {selected.get('resource_id', '')} "
            f"{selected.get('regulation_cited', '')}"
        )
        embed_and_store(
            detail,
            work.hcl_code,
            {
                "regulatory_context": str(selected.get("regulation_cited", "")),
                "confidence_score": "0.95",
            },
        )

    # Persist to Supabase via audit_db
    event: dict[str, Any] = {
        "task_id": plan.task_id,
        "timestamp": datetime.now().isoformat(),
        "violation_type": plan.violation_type,
        "resource_id": plan.resource_id,
        "planner_output": plan.fix_strategy,
        "worker_output": work.hcl_code,
        "reviewer_verdict": result.verdict,
        "reviewer_notes": result.notes,
        "is_compliant": result.is_compliant,
        "mttr_seconds": result.mttr_seconds,
        "tokens_used": plan.tokens_used + work.tokens_used + result.tokens_used,
        "rag_hit": plan.rag_hit,
    }
    if db is not None:
        db.insert(event)

    return {
        "trace": trace,
        "verdict": result.verdict,
        "checks_passed": result.checks_passed,
        "checks_failed": result.checks_failed,
        "result": result,
        "plan": plan,
        "work": work,
    }


# ── UI ──────────────────────────────────────────────────────────────────────

_CSS = """
.metric-card { padding: 16px; border-radius: 8px; margin-bottom: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); background: #f8f9fa; }
.trace-box { font-family: ui-monospace, monospace; font-size: 13px; white-space: pre-wrap; background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 6px; }
.verdict-approved { color: #28a745; font-weight: bold; }
.verdict-revision { color: #ffc107; font-weight: bold; }
.verdict-rejected { color: #dc3545; font-weight: bold; }
"""

app_ui = ui.page_fluid(
    ui.tags.head(ui.tags.style(_CSS)),
    ui.panel_title("SovereignShield — Compliance Remediation"),
    ui.navset_card_pill(
        ui.nav_panel(
            "Catalogue",
            ui.card(
                ui.card_header("Resources"),
                ui.output_table("catalogue_table"),
            ),
        ),
        ui.nav_panel(
            "Agent Loop",
            ui.layout_sidebar(
                ui.sidebar(
                    ui.h5("Run remediation"),
                    ui.input_select(
                        "violation_select",
                        "Violation",
                        choices={"s3-staging-analytics|data_residency": "s3-staging-analytics / data_residency"},  # updated by server
                    ),
                    ui.input_action_button("run_btn", "Run", class_="btn-primary"),
                    title="Controls",
                    width=280,
                ),
                ui.card(
                    ui.card_header("Waterfall trace"),
                    ui.output_text("trace_output"),
                    ui.output_text("verdict_output"),
                ),
            ),
        ),
        ui.nav_panel(
            "Intelligence",
            ui.layout_sidebar(
                ui.sidebar(
                    ui.input_action_button("refresh_btn", "Refresh"),
                    title="System",
                    width=200,
                ),
                ui.row(
                    ui.column(4, ui.output_ui("kpi_mttr")),
                    ui.column(4, ui.output_ui("kpi_rag")),
                    ui.column(4, ui.output_ui("kpi_kb")),
                ),
                ui.card(
                    ui.card_header("Recent events"),
                    ui.output_table("intel_table"),
                ),
            ),
        ),
    ),
)


def server(input: Any, output: Any, session: Any) -> None:
    # Violation choices from evaluate(RESOURCES)
    violations = (
        evaluate(RESOURCES) if _USE_REAL_MODULES and evaluate else []
    )
    if not violations:
        violations = [
            {
                "resource_id": "s3-staging-analytics",
                "violation_type": "data_residency",
                "severity": "HIGH",
            }
        ]
    # Shiny select: value -> label (user sees label, gets value)
    choices = {
        f"{v.get('resource_id', '')}|{v.get('violation_type', '')}": f"{v.get('resource_id', '')} / {v.get('violation_type', '')}"
        for v in violations
    }
    if not choices:
        choices = {"s3-staging-analytics|data_residency": "s3-staging-analytics / data_residency"}

    @reactive.effect
    def _update_violation_choices() -> None:
        ui.update_select("violation_select", choices=choices)

    agent_result: reactive.Value[dict[str, Any] | None] = reactive.Value(None)

    @reactive.effect
    @reactive.event(input.run_btn)
    def _on_run() -> None:
        sel = input.violation_select()
        if not sel:
            return
        parts = str(sel).split("|", 1)
        rid = parts[0] if len(parts) > 0 else ""
        vtype = parts[1] if len(parts) > 1 else ""
        out = _run_agents(rid, vtype)
        agent_result.set(out)

    @render.table
    def catalogue_table() -> Any:
        import pandas as pd
        rows = [
            {
                "resource_id": r.resource_id,
                "resource_type": r.resource_type,
                "region": r.region,
                "encryption_enabled": r.encryption_enabled,
                "is_public": r.is_public,
            }
            for r in RESOURCES
        ]
        return pd.DataFrame(rows)

    @render.text
    def trace_output() -> str:
        r = agent_result()
        if r is None:
            return "Click Run to execute the agent loop."
        return r.get("trace", "")

    @render.text
    def verdict_output() -> str:
        r = agent_result()
        if r is None:
            return ""
        v = r.get("verdict", "")
        return f"Verdict: {v}"

    # KPI tiles — depend on refresh_trigger so they update when Refresh clicked
    refresh_trigger: reactive.Value[int] = reactive.Value(0)

    @reactive.effect
    @reactive.event(input.refresh_btn)
    def _refresh_intel() -> None:
        refresh_trigger.set(refresh_trigger() + 1)

    @reactive.calc
    def _kpi_values() -> tuple[float, float, int]:
        refresh_trigger()
        if _USE_REAL_MODULES and db is not None:
            return (db.avg_mttr(), db.rag_hit_rate(), db.kb_count())
        return (0.0, 0.0, 0)

    @render.ui
    def kpi_mttr() -> Any:
        avg = _kpi_values()[0]
        return ui.div(
            ui.h5("Avg MTTR"),
            ui.p(f"{avg:.2f}s", class_="mb-0"),
            class_="metric-card",
        )

    @render.ui
    def kpi_rag() -> Any:
        rate = _kpi_values()[1]
        return ui.div(
            ui.h5("RAG hit rate"),
            ui.p(f"{rate:.1%}", class_="mb-0"),
            class_="metric-card",
        )

    @render.ui
    def kpi_kb() -> Any:
        cnt = _kpi_values()[2]
        return ui.div(
            ui.h5("KB count"),
            ui.p(str(cnt), class_="mb-0"),
            class_="metric-card",
        )

    @render.table
    def intel_table() -> Any:
        import pandas as pd
        refresh_trigger()  # depend on refresh so table updates when Refresh clicked
        rows = _effective_log(10)
        if not rows:
            return pd.DataFrame(columns=["task_id", "timestamp", "resource_id", "reviewer_verdict"])
        df = pd.DataFrame(rows)
        cols = ["task_id", "timestamp", "resource_id", "violation_type", "reviewer_verdict"]
        for c in cols:
            if c not in df.columns:
                df[c] = ""
        return df[[c for c in cols if c in df.columns]]


app = App(app_ui, server, debug=True)
