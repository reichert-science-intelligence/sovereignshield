"""
SovereignShield — Shiny for Python sovereign cloud compliance app.
Real agent loop: OPA evaluate → Planner → Worker → Reviewer → RAG/Supabase.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
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
    from project.sovereignshield.core.audit_log import write_run, fetch_history
    AUDIT_LOG_AVAILABLE = True
except Exception:
    AUDIT_LOG_AVAILABLE = False
    write_run = None  # type: ignore[assignment]
    fetch_history = None  # type: ignore[assignment]

try:
    from shiny import App, reactive, render, ui
except ImportError:
    raise ImportError("shiny is required. Run: pip install shiny")

from project.sovereignshield.models import CloudResource

# Full 5-resource catalogue

DEFAULT_OPA_POLICY: str = """
package sovereignshield.compliance

default allow = false

allow {
    input.encryption_enabled == true
    input.is_public == false
    input.region in {"us-east-1", "us-west-2", "us-gov-west-1"}
}

violation[msg] {
    input.encryption_enabled == false
    msg := sprintf("Resource %v: encryption not enabled", [input.resource_id])
}

violation[msg] {
    input.is_public == true
    msg := sprintf("Resource %v: resource is publicly accessible", [input.resource_id])
}

violation[msg] {
    not input.region in {"us-east-1", "us-west-2", "us-gov-west-1"}
    msg := sprintf("Resource %v: region %v not in approved list", 
                   [input.resource_id, input.region])
}
"""


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

# Synthetic history for History tab when fetch_history returns empty or Supabase unavailable
_SYNTHETIC_HISTORY: list[dict[str, Any]] = [
    {"run_at": "2026-03-12 14:22", "total": 5, "compliance_rate": "60.0%", "avg_mttr": "3.8s", "trend": "−"},
    {"run_at": "2026-03-13 09:15", "total": 5, "compliance_rate": "80.0%", "avg_mttr": "2.1s", "trend": "↑"},
    {"run_at": "2026-03-14 11:45", "total": 5, "compliance_rate": "62.0%", "avg_mttr": "4.2s", "trend": "↓"},
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


def _run_agents(resource_id: str, violation_type: str, resources: list[CloudResource], policy: str | None = None) -> dict[str, Any]:
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

    violations = evaluate(resources, policy)
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
            ui.input_action_button(
                "run_all",
                "⚡ Run Batch Remediation — All Resources",
                style="background:#D4AF37; color:#1A1633; font-weight:700; "
                      "border:none; padding:10px 24px; border-radius:8px; "
                      "width:100%; margin-bottom:16px;",
            ),
            ui.output_ui("batch_results_panel"),
            ui.card(
                ui.card_header("Resources"),
                ui.output_ui("catalogue_table"),
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
                ui.div(
                    ui.accordion(
                        ui.accordion_panel(
                            "⚙️ OPA Policy Editor",
                            ui.tags.p(
                                "Edit the active compliance policy below. "
                                "Click Apply Policy to rerun checks.",
                                style="color:#aaa; font-size:0.85rem; margin-bottom:8px;",
                            ),
                            ui.input_text_area(
                                "opa_policy_editor",
                                label=None,
                                value="",
                                rows=12,
                                width="100%",
                                placeholder="Loading policy...",
                            ),
                            ui.input_action_button(
                                "apply_policy",
                                "⚡ Apply Policy",
                                style="background:#4A3E8F; color:white; "
                                      "border:none; padding:8px 20px; "
                                      "border-radius:6px; margin-top:8px;",
                            ),
                            ui.output_text("policy_status"),
                        ),
                        open=False,
                    ),
                    ui.card(
                        ui.card_header("Waterfall trace"),
                        ui.output_text("trace_output"),
                        ui.output_text("verdict_output"),
                    ),
                ),
            ),
            _footer(),
        ),
        ui.nav_panel(
            "Intelligence",
            ui.layout_sidebar(
                ui.sidebar(
                    ui.input_action_button("refresh_btn", "Refresh"),
                    ui.download_button(
                        "export_pdf",
                        "📄 Export Remediation Report",
                        style="background:#4A3E8F; color:white; border:none; "
                              "padding:10px 24px; border-radius:8px; "
                              "margin-top:16px; width:100%;"
                    ),
                    title="System",
                    width=200,
                ),
                ui.row(
                    ui.column(3, ui.output_ui("kpi_mttr")),
                    ui.column(3, ui.output_ui("kpi_rag")),
                    ui.column(3, ui.output_ui("kpi_kb")),
                    ui.column(3, ui.output_ui("kpi_compliance")),
                ),
                ui.card(
                    ui.card_header("Recent events"),
                    ui.output_table("intel_table"),
                ),
                ui.card(ui.card_header("Compliance Heatmap"), ui.output_ui("intel_heatmap")),
                ui.card(ui.card_header("MTTR Trend"), ui.output_ui("intel_mttr_trend")),
                ui.card(ui.card_header("KB Growth"), ui.output_ui("intel_kb_growth")),
                ui.card(ui.card_header("Violation Distribution"), ui.output_ui("violation_chart")),
            ),
            _footer(),
        ),
        ui.nav_panel(
            "History",
            ui.layout_sidebar(
                ui.sidebar(
                    ui.input_action_button("history_refresh_btn", "Refresh"),
                    title="History",
                    width=200,
                ),
                ui.output_ui("history_record_status"),
                ui.card(
                    ui.card_header("Past runs — compliance trending"),
                    ui.output_ui("history_table"),
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
    active_policy: reactive.Value[str] = reactive.Value(DEFAULT_OPA_POLICY)

    @reactive.effect
    def _init_policy() -> None:
        ui.update_text_area("opa_policy_editor", value=DEFAULT_OPA_POLICY)

    @reactive.effect
    @reactive.event(input.apply_policy)
    def _apply_policy() -> None:
        active_policy.set(input.opa_policy_editor())

    @render.text
    def policy_status() -> str:
        if input.apply_policy() > 0:
            return "✅ Policy applied — rerunning checks"
        return ""

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

    @render.ui
    def batch_results_panel() -> Any:
        results = batch_results()
        if not results:
            return ui.div()
        compliant = sum(1 for r in results if r["verdict"] == "COMPLIANT")
        total = len(results)
        avg_mttr = (
            sum(r["mttr_seconds"] for r in results) / total if total else 0
        )
        rows = "".join(
            f"<tr>"
            f"<td style='padding:6px'>{r['resource_id']}</td>"
            f"<td style='padding:6px'>{r['resource_type']}</td>"
            f"<td style='padding:6px; color:{'#10B981' if r['verdict']=='COMPLIANT' else '#EF4444'}'>"
            f"{r['verdict']}</td>"
            f"<td style='padding:6px'>{r['violations']}</td>"
            f"<td style='padding:6px'>{r['mttr_seconds']}s</td>"
            f"</tr>"
            for r in results
        )
        return ui.HTML(
            f"""
            <div style='margin-top:16px; background:#1A1633; '
                      'border-radius:10px; padding:16px;'>
                <div style='display:flex; gap:24px; margin-bottom:12px;'>
                    <span style='color:#D4AF37; font-weight:700'>
                        {compliant}/{total} Compliant</span>
                    <span style='color:#aaa'>
                        Avg MTTR: {avg_mttr:.1f}s</span>
                </div>
                <table style='width:100%; color:#eee; '
                       'border-collapse:collapse; font-size:0.85rem;'>
                    <thead>
                        <tr style='color:#D4AF37; border-bottom:1px solid #4A3E8F'>
                            <th style='padding:6px; text-align:left'>Resource</th>
                            <th style='padding:6px; text-align:left'>Type</th>
                            <th style='padding:6px; text-align:left'>Verdict</th>
                            <th style='padding:6px; text-align:left'>Violations</th>
                            <th style='padding:6px; text-align:left'>MTTR</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
            """
        )

    @reactive.calc
    def _violations() -> list[dict[str, Any]]:
        v = evaluate(active_resources(), active_policy()) if _USE_REAL_MODULES and evaluate else []
        if not v:
            v = [{"resource_id": "s3-staging-analytics", "violation_type": "data_residency", "severity": "HIGH"}]
        return v

    @reactive.calc
    def _violation_choices() -> dict[str, str]:
        try:
            violations = _violations()
            choices = {
                f"{v.get('resource_id', '')}|{v.get('violation_type', '')}": f"{v.get('resource_id', '')} / {v.get('violation_type', '')}"
                for v in violations
            }
            if not choices:
                choices = {"s3-staging-analytics|data_residency": "s3-staging-analytics / data_residency"}
            return choices
        except Exception:
            return {"s3-staging-analytics|data_residency": "s3-staging-analytics / data_residency"}

    @reactive.effect
    def _update_violation_choices() -> None:
        ui.update_select("violation_select", choices=_violation_choices())

    agent_result: reactive.Value[dict[str, Any] | None] = reactive.Value(None)
    batch_results: reactive.Value[list[dict[str, Any]]] = reactive.Value([])
    _run_verdict: reactive.Value[str] = reactive.Value("")
    _run_mttr: reactive.Value[float] = reactive.Value(0.0)

    @reactive.effect
    @reactive.event(input.run_all)
    async def _run_batch() -> None:
        resources = active_resources()
        violations_all = _violations()
        results: list[dict[str, Any]] = []
        for resource in resources:
            res_violations = [
                v for v in violations_all
                if str(v.get("resource_id", "")) == resource.resource_id
            ]
            if not res_violations:
                results.append({
                    "resource_id": resource.resource_id,
                    "resource_type": resource.resource_type,
                    "verdict": "COMPLIANT",
                    "violations": 0,
                    "mttr_seconds": 0,
                })
                continue
            start = time.time()
            try:
                out = await asyncio.to_thread(
                    _run_agents,
                    resource.resource_id,
                    res_violations[0]["violation_type"],
                    resources,
                    active_policy(),
                )
                raw = out.get("verdict", "ERROR")
                verdict = "COMPLIANT" if raw == "APPROVED" else raw
                mttr = round(time.time() - start, 1)
            except Exception:
                verdict = "ERROR"
                mttr = 0.0
            results.append({
                "resource_id": resource.resource_id,
                "resource_type": resource.resource_type,
                "verdict": verdict,
                "violations": len(res_violations),
                "mttr_seconds": mttr,
            })
        batch_results.set(results)
        # Sprint 6: Persist to Supabase audit_runs + audit_results
        if results and write_run is not None:
            tf = input.tf_upload()
            source_filename = tf[0]["name"] if tf and len(tf) > 0 else ""
            write_run(
                batch_results=results,
                source_filename=source_filename,
                policy_text=active_policy(),
            )

    @reactive.effect
    @reactive.event(input.run_btn)
    async def _run_agent() -> None:
        val = input.violation_select()
        if not val:
            return
        parts = str(val).split("|")
        if len(parts) != 2:
            return
        resource_id, violation_type = parts[0], parts[1]
        resources = active_resources()
        resource = None
        for r in resources:
            rid = r.resource_id if hasattr(r, "resource_id") else r.get("resource_id") if isinstance(r, dict) else None
            if rid == resource_id:
                resource = r
                break
        if resource is None:
            return
        # Normalize to dict regardless of type
        if isinstance(resource, dict):
            resource_dict = resource
        else:
            resource_dict = {
                "resource_id": getattr(resource, "resource_id", ""),
                "resource_type": getattr(resource, "resource_type", ""),
                "region": getattr(resource, "region", "us-east-1"),
                "encryption_enabled": getattr(resource, "encryption_enabled", True),
                "is_public": getattr(resource, "is_public", False),
                "tags": getattr(resource, "tags", {}),
            }
        start = time.time()
        try:
            out = await asyncio.to_thread(
                _run_agents, resource_dict.get("resource_id", resource_id), violation_type, resources, active_policy()
            )
            verdict = out.get("verdict", "ERROR")
            agent_result.set(out)
            _run_verdict.set(verdict)
        except Exception as e:
            verdict = "NEEDS_REVISION" if any(x in str(e).lower() for x in ["credit", "400", "billing", "insufficient"]) else f"ERROR: {str(e)[:100]}"
            _run_verdict.set(verdict)
            agent_result.set(None)
        _run_mttr.set(round(time.time() - start, 1))

    @render.ui
    def catalogue_table() -> Any:
        resources = active_resources()
        if not resources:
            return ui.div("No resources loaded.", style="color:#aaa; padding:16px;")
        try:
            violations = _violations()
        except Exception:
            violations = []

        violation_rids: set[str] = {str(v.get("resource_id", "")) for v in violations}

        cards_html = []
        for r in resources:
            has_violation = r.resource_id in violation_rids
            if has_violation:
                color = "#EF4444"
                status = "VIOLATION"
            else:
                color = "#10B981"
                status = "COMPLIANT"

            cards_html.append(
                f'<div style="'
                f'background:#1A1633;'
                f'border-radius:10px;'
                f'border-left:4px solid {color};'
                f'padding:14px 16px;'
                f'margin-bottom:10px;'
                f'display:flex;'
                f'justify-content:space-between;'
                f'align-items:flex-start;'
                f'">'
                f'<div>'
                f'<div style="color:#D4AF37; font-weight:700; font-size:0.95rem;">{r.resource_id}</div>'
                f'<div style="color:#aaa; font-size:0.82rem; margin-top:4px;">'
                f'{r.resource_type} · {r.region}'
                f'</div>'
                f'<div style="color:#aaa; font-size:0.82rem;">'
                f'Encryption: {r.encryption_enabled} · Public: {r.is_public}'
                f'</div>'
                f'</div>'
                f'<span style="'
                f'background:{color};'
                f'color:white;'
                f'font-size:0.75rem;'
                f'font-weight:700;'
                f'padding:3px 10px;'
                f'border-radius:12px;'
                f'white-space:nowrap;'
                f'">{status}</span>'
                f'</div>'
            )
        return ui.HTML("".join(cards_html))

    @render.text
    def trace_output() -> str:
        v = _run_verdict()
        if not v:
            return "Select a resource and click Run."
        return f"Agent completed — verdict: {v}"

    @render.text
    def verdict_output() -> str:
        v = _run_verdict()
        return v if v else "Verdict will appear here after running."

    # KPI tiles — depend on refresh_trigger so they update when Refresh clicked
    refresh_trigger: reactive.Value[int] = reactive.Value(0)

    @reactive.effect
    @reactive.event(input.refresh_btn)
    def _refresh_intel() -> None:
        refresh_trigger.set(refresh_trigger() + 1)

    @reactive.calc
    def _kpi_values() -> tuple[float, float, int, float]:
        refresh_trigger()
        if _USE_REAL_MODULES and db is not None:
            compl = 0.0
            if hasattr(db, "compliance_rate"):
                cr = getattr(db, "compliance_rate")
                compl = cr() if callable(cr) else float(cr) if isinstance(cr, (int, float)) else 0.0
            return (db.avg_mttr(), db.rag_hit_rate(), db.kb_count(), compl)
        return (4.2, 0.87, 24, 0.62)  # Synthetic faux data on load

    @render.ui
    def kpi_mttr() -> Any:
        try:
            avg = _kpi_values()[0]
            return ui.div(
                ui.h5("Avg MTTR"),
                ui.p(f"{avg:.2f}s", class_="mb-0"),
                class_="metric-card",
            )
        except Exception as e:
            return ui.div(f"MTTR: —", class_="metric-card", style="color:#aaa;")

    @render.ui
    def kpi_rag() -> Any:
        try:
            rate = _kpi_values()[1]
            return ui.div(
                ui.h5("RAG hit rate"),
                ui.p(f"{rate:.1%}", class_="mb-0"),
                class_="metric-card",
            )
        except Exception as e:
            return ui.div(f"RAG: —", class_="metric-card", style="color:#aaa;")

    @render.ui
    def kpi_kb() -> Any:
        try:
            cnt = _kpi_values()[2]
            return ui.div(
                ui.h5("KB count"),
                ui.p(str(cnt), class_="mb-0"),
                class_="metric-card",
            )
        except Exception as e:
            return ui.div(f"KB: —", class_="metric-card", style="color:#aaa;")

    @render.ui
    def kpi_compliance() -> Any:
        try:
            rate = _kpi_values()[3]
            return ui.div(
                ui.h5("Compliance Rate"),
                ui.p(f"{rate:.0%}", class_="mb-0"),
                class_="metric-card",
            )
        except Exception as e:
            return ui.div(f"Compliance: —", class_="metric-card", style="color:#aaa;")

    @render.table
    def intel_table() -> Any:
        try:
            import pandas as pd
            refresh_trigger()  # depend on refresh so table updates when Refresh clicked
            rows = _effective_log(10)
            if not rows:
                resources = active_resources()
                rows = [
                    {
                        "task_id": f"syn-{r.resource_id[:12]}",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
                        "resource_id": r.resource_id,
                        "violation_type": "synthetic",
                        "reviewer_verdict": "PENDING",
                    }
                    for r in resources[:5]
                ]
            if not rows:
                return pd.DataFrame(columns=["task_id", "timestamp", "resource_id", "violation_type", "reviewer_verdict"])
            df = pd.DataFrame(rows)
            cols = ["task_id", "timestamp", "resource_id", "violation_type", "reviewer_verdict"]
            for c in cols:
                if c not in df.columns:
                    df[c] = ""
            return df[[c for c in cols if c in df.columns]]
        except Exception:
            return pd.DataFrame(columns=["task_id", "timestamp", "resource_id", "violation_type", "reviewer_verdict"])

    @render.ui
    def intel_heatmap() -> Any:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import io
            import base64
            import numpy as np

            resources = ["s3-phi", "rds-member", "lambda-elig", "s3-staging", "rds-dev"]
            measures = ["Encryption", "Region", "PHI Tag", "Public", "CMK"]
            data = np.array([
                [1, 1, 1, 1, 1],
                [1, 1, 0, 1, 1],
                [1, 1, 1, 1, 0],
                [0, 0, 1, 1, 1],
                [1, 0, 0, 1, 1],
            ])
            fig, ax = plt.subplots(figsize=(6, 4))
            im = ax.imshow(data, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")
            ax.set_xticks(range(len(measures)))
            ax.set_xticklabels(measures, rotation=45, ha="right", color="white", fontsize=8)
            ax.set_yticks(range(len(resources)))
            ax.set_yticklabels(resources, color="white", fontsize=8)
            ax.set_title("Compliance Heatmap", color="white")
            ax.set_facecolor("#1A1633")
            fig.set_facecolor("#1A1633")
            plt.tight_layout()
            buf = io.BytesIO()
            fig.savefig(buf, format="png", facecolor="#1A1633", bbox_inches="tight")
            plt.close(fig)
            buf.seek(0)
            b64 = base64.b64encode(buf.read()).decode()
            return ui.HTML(
                f'<img src="data:image/png;base64,{b64}" '
                f'style="width:100%; border-radius:8px;">'
            )
        except Exception as e:
            return ui.div(
                f"Heatmap error: {str(e)[:80]}",
                style="color:#aaa;padding:8px;",
            )

    @render.ui
    def intel_mttr_trend() -> Any:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import io
            import base64

            days = ["Mar 8", "Mar 9", "Mar 10", "Mar 11", "Mar 12", "Mar 13", "Mar 14"]
            mttr = [8.2, 6.5, 5.1, 4.8, 3.9, 4.2, 3.1]
            x = list(range(len(days)))
            fig, ax = plt.subplots(figsize=(6, 3))
            ax.plot(x, mttr, color="#D4AF37", linewidth=2, marker="o")
            ax.fill_between(x, mttr, alpha=0.2, color="#D4AF37")
            ax.set_xticks(x)
            ax.set_xticklabels(days, rotation=45, ha="right")
            ax.set_ylabel("MTTR (s)", color="white")
            ax.set_title("MTTR Trend", color="white")
            ax.set_facecolor("#1A1633")
            fig.set_facecolor("#1A1633")
            ax.tick_params(colors="white", labelsize=7)
            plt.tight_layout()
            buf = io.BytesIO()
            fig.savefig(buf, format="png", facecolor="#1A1633", bbox_inches="tight")
            plt.close(fig)
            buf.seek(0)
            b64 = base64.b64encode(buf.read()).decode()
            return ui.HTML(
                f'<img src="data:image/png;base64,{b64}" '
                f'style="width:100%; border-radius:8px;">'
            )
        except Exception as e:
            return ui.div(
                f"Trend error: {str(e)[:80]}",
                style="color:#aaa;padding:8px;",
            )

    @render.ui
    def intel_kb_growth() -> Any:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import io
            import base64

            days = ["Mar 8", "Mar 9", "Mar 10", "Mar 11", "Mar 12", "Mar 13", "Mar 14"]
            kb = [4, 8, 12, 15, 18, 22, 24]
            fig, ax = plt.subplots(figsize=(6, 3))
            ax.bar(days, kb, color="#4A3E8F")
            ax.set_ylabel("KB Entries", color="white")
            ax.set_title("Knowledge Base Growth", color="white")
            ax.set_facecolor("#1A1633")
            fig.set_facecolor("#1A1633")
            ax.tick_params(colors="white", labelsize=7)
            plt.xticks(rotation=45)
            plt.tight_layout()
            buf = io.BytesIO()
            fig.savefig(buf, format="png", facecolor="#1A1633", bbox_inches="tight")
            plt.close(fig)
            buf.seek(0)
            b64 = base64.b64encode(buf.read()).decode()
            return ui.HTML(
                f'<img src="data:image/png;base64,{b64}" '
                f'style="width:100%; border-radius:8px;">'
            )
        except Exception as e:
            return ui.div(
                f"KB error: {str(e)[:80]}",
                style="color:#aaa;padding:8px;",
            )

    @render.ui
    def violation_chart() -> Any:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import io
            import base64

            types = ["Encryption", "Public Access", "Region", "PHI Tag", "CMK"]
            counts = [4, 3, 2, 2, 1]
            colors = ["#EF4444", "#F97316", "#F97316", "#EAB308", "#10B981"]

            fig, ax = plt.subplots(figsize=(5, 3))
            ax.barh(types, counts, color=colors)
            ax.set_xlabel("Count")
            ax.set_title("Violation Distribution")
            ax.set_facecolor("#1A1633")
            fig.set_facecolor("#1A1633")
            ax.tick_params(colors="white")
            ax.title.set_color("white")
            ax.xaxis.label.set_color("white")
            plt.tight_layout()

            buf = io.BytesIO()
            fig.savefig(buf, format="png", facecolor="#1A1633", bbox_inches="tight")
            plt.close(fig)
            buf.seek(0)
            b64 = base64.b64encode(buf.read()).decode()
            return ui.HTML(
                f'<img src="data:image/png;base64,{b64}" '
                f'style="width:100%; border-radius:8px;">'
            )
        except Exception as e:
            return ui.div(
                f"Chart error: {str(e)}",
                style="color:#aaa; padding:16px;",
            )

    @render.download(filename=lambda: f"sovereignshield_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf")
    async def export_pdf():  # type: ignore[no-untyped-def]
        from pdf_report import generate_report
        results = batch_results()
        if not results:
            resources = active_resources()
            results = [
                {
                    "resource_id": r.resource_id,
                    "resource_type": r.resource_type,
                    "verdict": "NOT RUN",
                    "violations": 0,
                    "mttr_seconds": 0,
                }
                for r in resources
            ]
        tf = input.tf_upload()
        source_filename = (
            tf[0]["name"] if tf and len(tf) > 0 else "synthetic demo data"
        )
        pdf_bytes = generate_report(
            batch_results=results,
            policy_text=active_policy(),
            source_filename=source_filename,
        )
        yield pdf_bytes

    # ── Sprint 6: Record run & History ───────────────────────────────────
    record_run_status: reactive.Value[str] = reactive.Value("")
    history_refresh_trigger: reactive.Value[int] = reactive.Value(0)

    @reactive.effect
    @reactive.event(input.record_run_btn)
    def _on_record_run() -> None:
        results = batch_results()
        if not results:
            record_run_status.set("No resources to record. Run batch remediation first.")
            return
        tf = input.tf_upload()
        source_filename = tf[0]["name"] if tf and len(tf) > 0 else ""
        run_id = None
        if write_run is not None:
            run_id = write_run(
                batch_results=results,
                source_filename=source_filename,
                policy_text=active_policy(),
            )
        if run_id:
            record_run_status.set(f"Run recorded (id: {run_id[:8]}...)")
            history_refresh_trigger.set(history_refresh_trigger() + 1)
        else:
            record_run_status.set(
                "Supabase unavailable or tables missing. Check env and run audit_runs_schema.sql."
            )

    @reactive.effect
    @reactive.event(input.history_refresh_btn)
    def _on_history_refresh() -> None:
        history_refresh_trigger.set(history_refresh_trigger() + 1)

    @render.ui
    def history_record_status() -> Any:
        msg = record_run_status()
        if not msg:
            return ui.div()
        color = "#10B981" if "recorded" in msg.lower() else "#EF4444"
        return ui.p(msg, style=f"color:{color}; margin-bottom:12px;")

    @reactive.calc
    def _history_runs() -> list[dict[str, Any]]:
        history_refresh_trigger()
        if fetch_history is not None:
            return fetch_history(limit=50)
        return []

    @render.ui
    def history_table() -> Any:
        import pandas as pd
        runs = _history_runs()
        if not runs:
            rows = []
            for r in _SYNTHETIC_HISTORY:
                rows.append(
                    f"<tr>"
                    f"<td style='padding:8px; color:#eee;'>{r['run_at']}</td>"
                    f"<td style='padding:8px; color:#eee;'>{r['total']}</td>"
                    f"<td style='padding:8px; color:#eee;'>{r['compliance_rate']}</td>"
                    f"<td style='padding:8px; color:#eee;'>{r['avg_mttr']}</td>"
                    f"<td style='padding:8px; color:#eee;'>{r['trend']}</td>"
                    f"</tr>"
                )
            tbody = "".join(rows)
            return ui.HTML(
                f"<div style='background:#1A1633; border-radius:10px; padding:16px;'>"
                f"<table style='width:100%; border-collapse:collapse; color:#eee;'>"
                f"<thead><tr style='color:#D4AF37; border-bottom:1px solid #4A3E8F;'>"
                f"<th style='padding:8px; text-align:left'>run_at</th>"
                f"<th style='padding:8px; text-align:left'>total</th>"
                f"<th style='padding:8px; text-align:left'>compliance_rate</th>"
                f"<th style='padding:8px; text-align:left'>avg_mttr</th>"
                f"<th style='padding:8px; text-align:left'>trend</th>"
                f"</tr></thead><tbody>{tbody}</tbody></table>"
                f"<p style='color:#aaa; font-size:12px; margin-top:12px;'>"
                f"* Synthetic demo data — record a real run to see live history</p>"
                f"</div>"
            )
        rows = []
        for r in runs:
            run_at = r.get("run_at", "")
            if run_at:
                try:
                    if hasattr(run_at, "strftime"):
                        run_at = run_at.strftime("%Y-%m-%d %H:%M")
                    else:
                        run_at = str(run_at)[:19]
                except Exception:
                    run_at = str(run_at)[:19]
            rate = r.get("compliance_rate", 0)
            mttr = r.get("avg_mttr_seconds", 0) or 0
            trend = r.get("trending", "stable")
            arrow = "↑" if trend == "up" else "↓" if trend == "down" else "−"
            rows.append({
                "run_at": run_at,
                "total": r.get("total_resources", 0),
                "compliance_rate": f"{rate:.1f}%",
                "avg_mttr": f"{float(mttr):.1f}s",
                "trend": arrow,
            })
        df = pd.DataFrame(rows)
        return ui.HTML(df.to_html(index=False, classes="table", na_rep=""))


app = App(app_ui, server, debug=True)
