"""
SovereignShield — Shiny for Python sovereign cloud compliance app.
Real agent loop: OPA evaluate → Planner → Worker → Reviewer → RAG/Supabase.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from datetime import datetime

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
    evaluate = None
    db = None
    planner = None
    worker = None
    reviewer = None
    embed_and_store = None
    retrieve_similar = None

try:
    from shiny import App, reactive, render, ui
except ImportError:
    raise ImportError("shiny is required. Run: pip install shiny")

from project.sovereignshield.models import CloudResource

# Full 5-resource catalogue


def parse_terraform(file_path: str) -> list[dict[str, Any]]:
    """
    Parse Terraform .tf or .tfstate file and extract resources.
    Returns list of dicts with keys: resource_id, resource_type, region, encryption_enabled, is_public, tags.
    Falls back to empty list if parsing fails (caller uses RESOURCES when empty).
    """
    result: list[dict[str, Any]] = []
    path = Path(file_path)
    if not path.exists():
        return []
    try:
        suffix = path.suffix.lower()
        if suffix in (".tfstate", ".json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            resources = data.get("resources") or []
            for r in resources:
                res_type = str(r.get("type", ""))
                res_name = str(r.get("name", ""))
                resource_id = f"{res_type}-{res_name}".replace("aws_", "").replace("_", "-") if res_type and res_name else res_name or res_type
                instances = r.get("instances") or []
                region = ""
                tags: dict[str, str] = {}
                if instances:
                    attrs = instances[0].get("attributes") or {}
                    region = str(attrs.get("region") or attrs.get("region_name") or "")
                    if not region and attrs.get("availability_zone"):
                        az = str(attrs["availability_zone"])
                        match = re.match(r"^([a-z]+-[a-z]+-\d+)", az)
                        region = match.group(1) if match else "us-east-1"
                    raw_tags = attrs.get("tags") or {}
                    if isinstance(raw_tags, dict):
                        tags = {str(k): str(v) for k, v in raw_tags.items()}
                if not region:
                    region = "us-east-1"
                result.append({
                    "resource_id": resource_id or f"resource-{len(result)}",
                    "resource_type": res_type,
                    "region": region,
                    "encryption_enabled": False,
                    "is_public": False,
                    "tags": tags,
                })
        elif suffix == ".tf":
            content = path.read_text(encoding="utf-8")
            pattern = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE)
            for m in pattern.finditer(content):
                res_type = m.group(1).strip()
                res_name = m.group(2).strip()
                resource_id = f"{res_type}-{res_name}".replace("aws_", "").replace("_", "-") if res_type and res_name else res_name or res_type
                result.append({
                    "resource_id": resource_id or f"resource-{len(result)}",
                    "resource_type": res_type,
                    "region": "us-east-1",
                    "encryption_enabled": False,
                    "is_public": False,
                    "tags": {},
                })
    except Exception:
        return []
    return result


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
        result = db.fetch_recent(limit)
        return cast(list[dict[str, Any]], result)
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

    violations = evaluate(resources)
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


@dataclass
class _PortfolioApp:
    name: str
    description: str
    url: str
    qr_file: str


_PORTFOLIO_APPS: list[_PortfolioApp] = [
    _PortfolioApp("AuditShield Live", "RADV Audit Defense Platform", "https://huggingface.co/spaces/rreichert/auditshield-live", "QR_AuditShield_Live.b64.txt"),
    _PortfolioApp("StarGuard Desktop", "MA Intelligence Platform", "https://rreichert-starguard-desktop.hf.space", "QR_StarGuard_Desktop.b64.txt"),
    _PortfolioApp("StarGuard Mobile", "MA Intelligence on Mobile", "https://rreichert-starguardai.hf.space", "QR_Mobile_Tiny_Sized.b64.txt"),
    _PortfolioApp("SovereignShield Mobile", "Sovereign Cloud Compliance", "https://rreichert-sovereignshield-mobile.hf.space", "QR_SovereignShield_Mobile.b64.txt"),
]


def _load_avatar() -> str:
    """Load avatar from assets/avatar.b64.txt as data URI."""
    try:
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        path = os.path.join(assets_dir, "avatar.b64.txt")
        with open(path, "r") as f:
            data = f.read().strip().replace("\n", "").replace("\r", "")
        if not data.startswith("data:"):
            data = f"data:image/png;base64,{data}"
        return data
    except Exception:
        return ""


_AVATAR_SRC: str = _load_avatar()


def _load_qr(filename: str) -> str:
    """Load base64 image from assets/*.b64.txt. Handles whitespace, newlines, JPEG vs PNG."""
    try:
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        path = os.path.join(assets_dir, filename)
        with open(path, "r") as f:
            raw = f.read().strip().replace("\n", "").replace("\r", "")
        if raw.startswith("data:"):
            return raw
        # JPEG base64 starts with /9j/; PNG with iVBORw0KGgo
        mime = "image/jpeg" if raw.startswith("/9j/") else "image/png"
        return f"data:{mime};base64,{raw}"
    except Exception:
        return ""


def _footer() -> Any:
    """Synthetic data disclaimer footer for all tabs."""
    return ui.div(
        ui.hr(style="margin: 24px 0 8px 0; border-color: #dee2e6;"),
        ui.p(
            "© 2026 Robert Reichert | Sovereign Cloud & AI. "
            "All data shown is synthetic and generated for demonstration purposes only. "
            "No real patient, member, or infrastructure data is used.",
            style="font-size: 12px; color: #6c757d; text-align: center; padding: 16px; line-height: 1.5;",
        ),
        style="width: 100%;",
    )


def _about_ui() -> Any:
    """Tab 4: About + Services — matches mobile content."""
    return ui.div(
        ui.card(
            ui.card_header("Robert Reichert"),
            (
                ui.div(
                    ui.tags.img(
                        src=_AVATAR_SRC,
                        style="width:96px;height:96px;border-radius:50%;object-fit:cover;"
                              "object-position:center top;border:3px solid #4A3E8F;"
                              "display:block;margin:0 auto 12px auto;",
                    ),
                    style="text-align: center;",
                )
                if _AVATAR_SRC
                else ui.div("RR", style="width:72px;height:72px;border-radius:50%;background:#4A3E8F;color:white;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:1.5rem;margin:0 auto 12px;")
            ),
            ui.p("Principal, Sovereign Cloud & AI", style="text-align: center; color: #666; margin-bottom: 8px;"),
            ui.div(
                ui.span("Cloud Compliance", class_="badge bg-secondary", style="margin: 4px;"),
                ui.span("Agentic AI", class_="badge bg-secondary", style="margin: 4px;"),
                ui.span("Healthcare Analytics", class_="badge bg-secondary", style="margin: 4px;"),
                style="display: flex; flex-wrap: wrap; justify-content: center; gap: 4px; margin-bottom: 12px;",
            ),
            ui.div(
                ui.a("reichert.starguardai@email.com", href="mailto:reichert.starguardai@email.com", style="margin: 0 8px;"),
                ui.a("LinkedIn", href="https://www.linkedin.com/in/robertreichert-healthcareai/", style="margin: 0 8px;"),
                ui.span("+1 (480) 767-1337", style="margin: 0 8px;"),
                style="text-align: center; font-size: 14px; margin-bottom: 12px;",
            ),
            ui.div("Available March 2026", style="display: inline-block; background: #D4AF37; color: black; padding: 8px 12px; border-radius: 999px; font-weight: 600; text-align: center;"),
        ),
        ui.h5("Portfolio Apps", style="margin-top: 16px; margin-bottom: 12px;"),
        ui.div(
            *[
                ui.card(
                    ui.div(app.name, style="font-weight: 600; margin-bottom: 4px;"),
                    ui.div(app.description, style="font-size: 13px; color: #666; margin-bottom: 4px;"),
                    ui.a(app.url, href=app.url, target="_blank", style="font-size: 12px; margin-bottom: 8px; display: block;"),
                    ui.tags.img(src=_load_qr(app.qr_file), style="height: 80px; width: 80px;", alt=app.name) if _load_qr(app.qr_file) else ui.span("(QR)", style="font-size: 12px; color: #999;"),
                    style="margin-bottom: 12px;",
                )
                for app in _PORTFOLIO_APPS
            ],
        ),
        ui.h5("Services", style="margin-top: 24px; margin-bottom: 12px;"),
        ui.accordion(
            ui.accordion_panel(
                "Sovereign Cloud Compliance Audit — Senior Consultant Rate",
                ui.p("HIPAA-compliant cloud resource audit with OPA policy evaluation and Terraform remediation."),
                ui.tags.ul(ui.tags.li("Policy-as-code review"), ui.tags.li("Violation report"), ui.tags.li("Terraform fix generation")),
                ui.p("Typical engagement: 2–4 weeks", style="margin-top: 8px;"),
            ),
            ui.accordion_panel(
                "Agentic AI System Design — Senior Consultant Rate",
                ui.p("Design and implement agentic workflows (Planner → Worker → Reviewer) for compliance and automation."),
                ui.tags.ul(ui.tags.li("Architecture design"), ui.tags.li("RAG integration"), ui.tags.li("Claude API integration")),
                ui.p("Typical engagement: 4–8 weeks", style="margin-top: 8px;"),
            ),
            ui.accordion_panel(
                "HEDIS/RADV Analytics Consulting — Consulting Rate",
                ui.p("Healthcare quality measure analytics, RADV exposure scoring, and star rating optimization."),
                ui.tags.ul(ui.tags.li("HEDIS measure analysis"), ui.tags.li("RADV scenario modeling"), ui.tags.li("ROI projections")),
                ui.p("Typical engagement: 2–6 weeks", style="margin-top: 8px;"),
            ),
        ),
        ui.div(
            ui.a("Discuss Engagement: reichert.starguardai@email.com", href="mailto:reichert.starguardai@email.com",
                class_="btn btn-warning", style="width: 100%; margin-top: 16px; display: block; text-align: center; text-decoration: none; background: #D4AF37; color: black; font-weight: bold; border: none;"),
        ),
        _footer(),
    )


app_ui = ui.page_fluid(
    ui.tags.head(ui.tags.style(_CSS)),
    ui.panel_title("SovereignShield — Compliance Remediation"),
    ui.navset_card_pill(
        ui.nav_panel(
            "Catalogue",
            ui.input_file(
                "tf_upload",
                "Upload Terraform File (.tf or .tfstate)",
                accept=[".tf", ".tfstate", ".json"],
                placeholder="Drop .tf or .tfstate file here",
            ),
            ui.output_text("upload_status"),
            ui.card(
                ui.card_header("Resources"),
                ui.output_table("catalogue_table"),
            ),
            _footer(),
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
            _footer(),
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
            _footer(),
        ),
        ui.nav_panel(
            "About",
            _about_ui(),
        ),
    ),
)


def server(input: Any, output: Any, session: Any) -> None:
    def _dict_to_cloud_resource(d: dict[str, Any]) -> CloudResource:
        """Convert parsed Terraform dict to CloudResource."""
        return CloudResource(
            resource_id=str(d.get("resource_id", "")),
            resource_type=str(d.get("resource_type", "unknown")),
            region=str(d.get("region", "us-east-1")),
            encryption_enabled=bool(d.get("encryption_enabled", False)),
            cmk_key_id=None,
            is_public=bool(d.get("is_public", False)),
            tags=dict(d.get("tags") or {}),
        )

    @reactive.calc
    def active_resources() -> list[CloudResource]:
        f = input.tf_upload()
        if f is None or len(f) == 0:
            return RESOURCES
        try:
            parsed = parse_terraform(f[0]["datapath"])
            if not parsed:
                return RESOURCES
            return [_dict_to_cloud_resource(d) for d in parsed]
        except Exception:
            return RESOURCES

    @render.text
    def upload_status() -> str:
        f = input.tf_upload()
        if f is None or len(f) == 0:
            return "Using synthetic demo data"
        r = active_resources()
        return f"Loaded {len(r)} resources from {f[0]['name']}"

    @reactive.calc
    def _violations() -> list[dict[str, Any]]:
        v = evaluate(active_resources()) if _USE_REAL_MODULES and evaluate else []
        if not v:
            v = [{"resource_id": "s3-staging-analytics", "violation_type": "data_residency", "severity": "HIGH"}]
        return v

    @reactive.calc
    def _violation_choices() -> dict[str, str]:
        violations = _violations()
        choices = {
            f"{v.get('resource_id', '')}|{v.get('violation_type', '')}": f"{v.get('resource_id', '')} / {v.get('violation_type', '')}"
            for v in violations
        }
        if not choices:
            choices = {"s3-staging-analytics|data_residency": "s3-staging-analytics / data_residency"}
        return choices

    @reactive.effect
    def _update_violation_choices() -> None:
        ui.update_select("violation_select", choices=_violation_choices())

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
        out = _run_agents(rid, vtype, active_resources())
        agent_result.set(out)

    @render.table
    def catalogue_table() -> Any:
        import pandas as pd
        resources = active_resources()
        rows = [
            {
                "resource_id": r.resource_id,
                "resource_type": r.resource_type,
                "region": r.region,
                "encryption_enabled": r.encryption_enabled,
                "is_public": r.is_public,
            }
            for r in resources
        ]
        return pd.DataFrame(rows)

    @render.text
    def trace_output() -> str:
        r = agent_result()
        if r is None:
            return "Click Run to execute the agent loop."
        return cast(str, r.get("trace", ""))

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
