"""
SovereignShield — Shiny for Python sovereign cloud compliance app.
Real agent loop: OPA evaluate → Planner → Worker → Reviewer → RAG/Supabase.
"""
from __future__ import annotations

import base64
import io
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, cast

# Brand colors: Purple #4A3E8F, Gold #D4AF37, Green #10b981
_BRAND_PURPLE = "#4A3E8F"
_BRAND_GOLD = "#D4AF37"
_BRAND_GREEN = "#10b981"


def _load_qr_b64(filename: str) -> str:
    """Load base64-encoded image from assets/*.b64.txt. Returns empty string if not found."""
    try:
        base_dir = Path(__file__).resolve().parent
        assets_dir = base_dir / "assets"
        filepath = assets_dir / filename
        if filepath.is_file():
            content = filepath.read_text(encoding="utf-8")
            return "".join(content.split())  # strip whitespace/newlines
        return ""
    except Exception:
        return ""


def _b64_to_data_uri(b64: str) -> str:
    """Return data URI with correct MIME type based on base64 prefix."""
    if not b64:
        return ""
    if b64.startswith("/9j/"):
        return f"data:image/jpeg;base64,{b64}"
    if b64.startswith("iVBORw0KGgo"):
        return f"data:image/png;base64,{b64}"
    return f"data:image/png;base64,{b64}"  # fallback


def _load_avatar() -> str:
    """Load avatar.png from assets as base64 data URI."""
    try:
        assets_dir = Path(__file__).resolve().parent / "assets"
        path = assets_dir / "avatar.png"
        with open(path, "rb") as f:
            data = base64.b64encode(f.read()).decode()
        return f"data:image/png;base64,{data}"
    except Exception:
        return ""


_AVATAR_SRC: str = _load_avatar()

# Graceful import fallback — run with simulated data if any module fails
_USE_REAL_MODULES = True
try:
    from .core.opa_eval import evaluate
    from .core.audit_db import db
    from .core.audit_log import write_run, fetch_history
    from .agents.planner import planner
    from .agents.worker import worker
    from .agents.reviewer import reviewer
    from .rag.retriever import embed_and_store, kb_count, retrieve_similar
except ImportError:
    _USE_REAL_MODULES = False
    evaluate = None  # type: ignore[assignment]
    db = None  # type: ignore[assignment]
    write_run = None  # type: ignore[assignment]
    fetch_history = None  # type: ignore[assignment]
    planner = None  # type: ignore[assignment]
    worker = None  # type: ignore[assignment]
    reviewer = None  # type: ignore[assignment]
    embed_and_store = None  # type: ignore[assignment]
    kb_count = None  # type: ignore[assignment]
    retrieve_similar = None  # type: ignore[assignment]

_CHARTS_AVAILABLE = True
try:
    from .core import charts
except ImportError:
    _CHARTS_AVAILABLE = False
    charts = None  # type: ignore[assignment]

try:
    from shiny import App, reactive, render, ui
except ImportError:
    raise ImportError("shiny is required. Run: pip install shiny")

# Synthetic RESOURCES catalogue — 5 columns for Catalogue tab
RESOURCES: list[dict[str, Any]] = [
    {"resource_id": "s3-staging-analytics", "region": "eu-west-1", "type": "s3", "encryption_enabled": False, "is_public": True},
    {"resource_id": "ec2-prod-api", "region": "us-east-1", "type": "ec2", "encryption_enabled": True, "is_public": False},
]


def parse_terraform(file_path: str) -> list[dict[str, Any]]:
    """
    Parse Terraform .tf or .tfstate file and extract resources.
    Returns list of dicts with keys: resource_id, region, type, encryption_enabled, is_public, tags.
    Falls back to RESOURCES if parsing fails or returns empty.
    """
    result: list[dict[str, Any]] = []
    path = Path(file_path)
    if not path.exists():
        return RESOURCES
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
                    "type": res_type.split("_")[-1] if "_" in res_type else res_type,
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
                    "type": res_type.split("_")[-1] if "_" in res_type else res_type,
                    "encryption_enabled": False,
                    "is_public": False,
                    "tags": {},
                })
    except Exception:
        return RESOURCES
    return result if result else RESOURCES

# Canonical 5 OPA checks for waterfall trace: (policy_id, message)
_OPA_CHECKS: list[tuple[str, str]] = [
    ("approved_regions", "Approved regions: us-east-1, us-gov-east-1"),
    ("cmk_encryption", "CMK encryption (aws:kms) required"),
    ("phi_tag", "DataClass=PHI tag on all resources"),
    ("is_public", "is_public must be False"),
    ("data_residency", "data residency / region constraint"),
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


def _html_esc(s: str) -> str:
    """Escape HTML special characters."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _hcl_synthetic_before(resource_id: str) -> str:
    """Synthetic before (non-compliant) HCL per resource_id."""
    blocks: dict[str, str] = {
        "s3-staging-analytics": '''resource "aws_s3_bucket" "staging_analytics" {
  bucket = "staging-analytics"
  # Missing: server_side_encryption, region constraint
}
''',
        "ec2-prod-api": '''resource "aws_instance" "prod_api" {
  ami           = "ami-12345678"
  instance_type = "t3.medium"
  # Missing: PHI tag, encryption
}
''',
    }
    return blocks.get(resource_id, f'# No synthetic before for {resource_id}\n')


def _hcl_synthetic_after(resource_id: str) -> str:
    """Synthetic after (compliant) HCL per resource_id — used when no work output."""
    blocks: dict[str, str] = {
        "s3-staging-analytics": '''resource "aws_s3_bucket_server_side_encryption_configuration" "fix_staging" {
  bucket = aws_s3_bucket.staging_analytics.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
  }
}
''',
        "ec2-prod-api": '''resource "aws_instance" "prod_api" {
  ami           = "ami-12345678"
  instance_type = "t3.medium"
  tags = {
    DataClass = "PHI"
  }
}
''',
    }
    return blocks.get(resource_id, f'# No synthetic after for {resource_id}\n')


def _build_waterfall_trace(
    checks_passed: list[str],
    checks_failed: list[str],
    violation_severity: str,
) -> str:
    """Build 5-line waterfall trace: ✓/✗ [policy_id] — [message] ([severity])."""
    keywords: list[str] = ["region", "encryption", "phi", "public", "residency"]
    lines: list[str] = []
    for ((pid, msg), kw) in zip(_OPA_CHECKS, keywords, strict=True):
        failed = any(kw in c.lower() for c in checks_failed)
        if failed:
            sym = "✗"
            sev = violation_severity
        else:
            sym = "✓"
            sev = "INFO"
        lines.append(f"  {sym} [{pid}] — {msg} ({sev})")
    return "\n".join(lines) + "\n"


def _highest_severity(violations: list[dict[str, Any]]) -> str:
    """Return highest severity among violations. HIGH > MEDIUM > LOW > INFO."""
    order: dict[str, int] = {"HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    best = "INFO"
    for v in violations:
        s = str(v.get("severity", "INFO")).upper().strip()
        if order.get(s, 0) > order.get(best, 0):
            best = s
    return best


def _effective_log(limit: int = 10) -> list[dict[str, Any]]:
    """Fetch recent events: db.fetch_recent(limit) with local fallback to _SEED_EVENTS."""
    if _USE_REAL_MODULES and db is not None:
        return db.fetch_recent(limit)
    return list(_SEED_EVENTS)[:limit]


def _chart_to_base64_png(
    chart_fn: Callable[..., Any],
    runs: list[dict[str, Any]],
    **kwargs: Any,
) -> str:
    """
    Render a chart (compliance_heatmap, mttr_trend, violation_donut, kb_growth)
    to a base64-encoded PNG for ui.img src.
    """
    if not _CHARTS_AVAILABLE or charts is None:
        return ""
    try:
        import matplotlib.pyplot as mpl_plt

        p = chart_fn(runs, **kwargs)
        fig = p.draw()
        buf: io.BytesIO = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        buf.seek(0)
        enc = base64.b64encode(buf.read()).decode("ascii")
        mpl_plt.close(fig)
        return enc
    except Exception:
        return ""


def _run_agents(resource_id: str, violation_type: str, resources: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Run real agent loop: evaluate → planner → worker → reviewer.
    Returns dict with trace, verdict, checks_passed, checks_failed, etc.
    """
    if not _USE_REAL_MODULES or evaluate is None or planner is None or worker is None or reviewer is None:
        sim_trace = _build_waterfall_trace(
            ["Region check", "CMK check"],
            ["PHI DataClass tag missing"],
            "HIGH",
        )
        return {
            "trace": sim_trace,
            "verdict": "NEEDS_REVISION",
            "checks_passed": ["Region check", "CMK check"],
            "checks_failed": ["PHI DataClass tag missing"],
            "result": None,
            "plan": None,
            "work": None,
            "mttr_seconds": 2.5,
            "hcl_before": _hcl_synthetic_before("s3-staging-analytics"),
            "hcl_after": _hcl_synthetic_after("s3-staging-analytics"),
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
            "trace": _build_waterfall_trace([], ["Violation not found"], "HIGH"),
            "verdict": "REJECTED",
            "checks_passed": [],
            "checks_failed": ["Violation not found"],
            "result": None,
            "plan": None,
            "work": None,
            "mttr_seconds": 0.0,
            "hcl_before": _hcl_synthetic_before(resource_id),
            "hcl_after": _hcl_synthetic_after(resource_id),
        }

    t0 = datetime.now()
    plan = planner.run(dict(selected))  # Violation TypedDict → dict for planner
    work = worker.run(plan)
    result = reviewer.run(plan, work, started_at=t0)

    # Waterfall trace: all 5 OPA checks with ✓/✗ [policy_id] — [message] ([severity])
    resource_violations_pre = [v for v in violations if str(v.get("resource_id", "")) == resource_id]
    sev = _highest_severity(cast(list[dict[str, Any]], resource_violations_pre))
    trace = _build_waterfall_trace(result.checks_passed, result.checks_failed, sev)

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

    # Persist to Supabase via audit_db (severity = highest among resource's violations)
    severity_val = _highest_severity(cast("list[dict[str, Any]]", resource_violations_pre))
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
        "severity": severity_val,
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
        "mttr_seconds": result.mttr_seconds,
        "hcl_before": _hcl_synthetic_before(resource_id),
        "hcl_after": work.hcl_code,
    }


# ── UI ──────────────────────────────────────────────────────────────────────

_CSS = """
:root { --brand-purple: #4A3E8F; --brand-gold: #D4AF37; --brand-green: #10b981; }
.metric-card { padding: 16px; border-radius: 8px; margin-bottom: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); background: #f8f9fa; }
.trace-box { font-family: ui-monospace, monospace; font-size: 13px; white-space: pre-wrap; background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 6px; }
.verdict-approved { color: #28a745; font-weight: bold; }
.verdict-revision { color: #ffc107; font-weight: bold; }
.verdict-rejected { color: #dc3545; font-weight: bold; }
.about-card { border-left: 4px solid var(--brand-purple); background: #f8f9fa; }
.services-card { border-left: 4px solid var(--brand-gold); }
"""

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
                ui.card_header("Resources — click a row to see violation details"),
                ui.div(ui.input_text("catalogue_selected_resource", "", value=""), class_="d-none"),
                ui.output_ui("catalogue_table"),
                ui.output_ui("catalogue_violation_detail"),
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
                    ui.output_ui("mttr_output"),
                    ui.output_ui("hcl_diff_output"),
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
                ui.output_ui("intel_heatmap"),
                ui.output_ui("intel_mttr_trend"),
                ui.output_plot("violation_chart"),
                ui.card(
                    ui.card_header("Recent events"),
                    ui.output_table("intel_table"),
                ),
            ),
        ),
        ui.nav_panel(
            "Analytics",
            ui.layout_sidebar(
                ui.sidebar(
                    ui.input_action_button("analytics_refresh_btn", "Refresh"),
                    ui.input_action_button(
                        "record_run_btn",
                        "📋 Record run",
                        title="Persist current batch to audit history",
                        class_="btn-secondary",
                    ),
                    ui.download_button("analytics_csv_download", "Download Audit Log (CSV)"),
                    title="Analytics",
                    width=220,
                ),
                ui.row(
                    ui.column(3, ui.output_ui("analytics_kpi_total")),
                    ui.column(3, ui.output_ui("analytics_kpi_mttr")),
                    ui.column(3, ui.output_ui("analytics_kpi_compliance")),
                    ui.column(3, ui.output_ui("analytics_kpi_rag")),
                ),
                ui.download_button(
                    "export_pdf",
                    "📄 Export Remediation Report",
                    style="background:#4A3E8F; color:white; border:none; "
                          "padding:10px 24px; border-radius:8px; "
                          "margin-top:16px; width:100%;"
                ),
                ui.row(
                    ui.column(6, ui.output_ui("analytics_chart_heatmap")),
                    ui.column(6, ui.output_ui("analytics_chart_mttr")),
                ),
                ui.row(
                    ui.column(6, ui.output_ui("analytics_chart_donut")),
                    ui.column(6, ui.output_ui("analytics_chart_kb")),
                ),
            ),
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
                    ui.output_table("history_table"),
                ),
            ),
        ),
        ui.nav_panel(
            "About",
            ui.output_ui("about_panel"),
        ),
        ui.nav_panel(
            "Services",
            ui.output_ui("services_panel"),
        ),
    ),
)


def server(input: Any, output: Any, session: Any) -> None:
    @reactive.calc
    def active_resources() -> list[dict[str, Any]]:
        f = input.tf_upload()
        if f is None or len(f) == 0:
            return RESOURCES
        try:
            parsed = parse_terraform(f[0]["datapath"])
            return parsed if parsed else RESOURCES
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
        v = (
            evaluate(active_resources()) if _USE_REAL_MODULES and evaluate is not None else []
        )
        if not v:
            v = [
                {
                    "resource_id": "s3-staging-analytics",
                    "violation_type": "data_residency",
                    "severity": "HIGH",
                    "regulation_cited": "",
                    "detail": "",
                }
            ]
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

    @render.ui
    def catalogue_table() -> Any:
        import pandas as pd
        resources = active_resources()
        violations = _violations()
        df = pd.DataFrame(resources)
        cols = ["resource_id", "region", "type", "encryption_enabled", "is_public"]
        for c in cols:
            if c not in df.columns:
                df[c] = ""
        df = df[[c for c in cols if c in df.columns]]
        # Build HTML table with color-coded rows and click handlers
        rows_html: list[str] = []
        for _, row in df.iterrows():
            rid = str(row.get("resource_id", ""))
            has_viol = any(str(v.get("resource_id", "")) == rid for v in violations)
            bg = "#d4edda" if not has_viol else "#f8d7da"
            cells = "".join(f"<td>{_html_esc(str(row.get(c, '')))}</td>" for c in cols)
            rows_html.append(
                f'<tr style="background-color:{bg};cursor:pointer" '
                f'data-resource-id="{_html_esc(rid)}" '
                f'onclick="Shiny.setInputValue(\'catalogue_selected_resource\', '
                f'\'{_html_esc(rid)}\', {{priority: \'event\'}});">'
                f"{cells}</tr>"
            )
        header = "<thead><tr>" + "".join(f"<th>{c}</th>" for c in cols) + "</tr></thead>"
        body = "<tbody>" + "".join(rows_html) + "</tbody>"
        return ui.HTML(f'<table class="table table-bordered">{header}{body}</table>')

    @render.ui
    def catalogue_violation_detail() -> Any:
        sel = input.catalogue_selected_resource()
        if not sel or not str(sel).strip():
            return ui.div()
        violations = _violations()
        resource_viols = [
            v for v in violations if str(v.get("resource_id", "")) == str(sel)
        ]
        if not resource_viols:
            return ui.div(ui.p("No violations for this resource."), class_="mt-3 p-3 border")
        items = []
        for v in resource_viols:
            pid = str(v.get("violation_type", ""))  # policy_id from violation_type
            sev = str(v.get("severity", ""))
            msg = str(v.get("detail", ""))
            items.append(ui.tags.li(f"policy: {pid} — {msg} (severity: {sev})"))
        return ui.div(
            ui.h6("Violation details"),
            ui.tags.ul(*items, class_="list-unstyled"),
            class_="mt-3 p-3 border rounded",
        )

    @render.text
    def trace_output() -> str:
        r = agent_result()
        if r is None:
            return "Click Run to execute the agent loop."
        return str(r.get("trace", ""))

    @render.text
    def verdict_output() -> str:
        r = agent_result()
        if r is None:
            return ""
        v = r.get("verdict", "")
        return f"Verdict: {v}"

    @render.ui
    def mttr_output() -> Any:
        r = agent_result()
        if r is None:
            return ui.div()
        mttr = r.get("mttr_seconds")
        if mttr is None:
            return ui.div()
        return ui.p(f"MTTR: {float(mttr):.1f}s", class_="mb-0 mt-2")

    @render.ui
    def hcl_diff_output() -> Any:
        r = agent_result()
        if r is None:
            return ui.div()
        before = r.get("hcl_before", "")
        after = r.get("hcl_after", "")
        if not before and not after:
            return ui.div()
        return ui.div(
            ui.h6("HCL diff"),
            ui.div(
                ui.div(
                    ui.strong("Before"),
                    ui.pre(before, class_="bg-light p-2 rounded overflow-auto"),
                    class_="col-6",
                ),
                ui.div(
                    ui.strong("After"),
                    ui.pre(after, class_="bg-light p-2 rounded overflow-auto"),
                    class_="col-6",
                ),
                class_="row",
            ),
            class_="mt-3",
        )

    # KPI tiles — depend on refresh_trigger so they update when Refresh clicked
    refresh_trigger: reactive.Value[int] = reactive.Value(0)

    @reactive.effect
    @reactive.event(input.refresh_btn)
    def _refresh_intel() -> None:
        refresh_trigger.set(refresh_trigger() + 1)

    @reactive.calc
    def _kpi_values() -> tuple[float, float, int]:
        """Live KPIs: Avg MTTR, RAG hit rate, KB count. Fallback to seed when db unavailable."""
        refresh_trigger()
        if _USE_REAL_MODULES and db is not None:
            return (db.avg_mttr(), db.rag_hit_rate(), db.kb_count())
        # Graceful fallback: compute from seed events
        runs = _effective_log(100)
        mttr_vals = [
            float(e["mttr_seconds"])
            for e in runs
            if e.get("mttr_seconds") is not None
        ]
        avg_mttr = sum(mttr_vals) / len(mttr_vals) if mttr_vals else 0.0
        rag_rate = (
            sum(1 for e in runs if e.get("rag_hit") is True) / len(runs)
            if runs
            else 0.0
        )
        kb_cnt = kb_count() if kb_count is not None else 0
        return (avg_mttr, rag_rate, kb_cnt)

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

    @reactive.calc
    def _intel_runs() -> list[dict[str, Any]]:
        refresh_trigger()
        if _USE_REAL_MODULES and db is not None:
            return db.fetch_recent(50)
        return _effective_log(50)

    @render.ui
    def intel_heatmap() -> Any:
        if not _CHARTS_AVAILABLE or charts is None:
            return ui.div(ui.p("Chart unavailable"), class_="metric-card")
        runs = _intel_runs()
        enc = _chart_to_base64_png(charts.compliance_heatmap, runs)
        if not enc:
            return ui.div(ui.p("Chart unavailable"), class_="metric-card")
        return ui.div(
            ui.h5("Compliance heatmap"),
            ui.tags.img(
                src=f"data:image/png;base64,{enc}",
                alt="Compliance heatmap",
                style="max-width:100%; height:auto;",
            ),
            class_="metric-card",
        )

    @render.ui
    def intel_mttr_trend() -> Any:
        if not _CHARTS_AVAILABLE or charts is None:
            return ui.div(ui.p("Chart unavailable"), class_="metric-card")
        runs = _intel_runs()
        enc = _chart_to_base64_png(charts.mttr_trend, runs)
        if not enc:
            return ui.div(ui.p("Chart unavailable"), class_="metric-card")
        return ui.div(
            ui.h5("MTTR trend"),
            ui.tags.img(
                src=f"data:image/png;base64,{enc}",
                alt="MTTR trend",
                style="max-width:100%; height:auto;",
            ),
            class_="metric-card",
        )

    @render.plot
    def violation_chart() -> Any:
        import pandas as pd
        from plotnine import aes, coord_flip, geom_col, ggplot, labs, scale_fill_manual, theme_minimal

        refresh_trigger()
        runs = _intel_runs()
        synthetic_violations = pd.DataFrame({
            "type": ["Encryption", "Public Access", "Region", "PHI Tag", "CMK"],
            "count": [4, 3, 2, 2, 1],
            "severity": ["CRITICAL", "HIGH", "HIGH", "MEDIUM", "LOW"],
        })
        try:
            if not runs:
                chart = (
                    ggplot(synthetic_violations, aes(x="type", y="count", fill="severity"))
                    + geom_col()
                    + coord_flip()
                    + scale_fill_manual(values={
                        "CRITICAL": "#EF4444",
                        "HIGH": "#F97316",
                        "MEDIUM": "#EAB308",
                        "LOW": "#10B981",
                    })
                    + theme_minimal()
                    + labs(title="Violation Distribution", x="", y="Count")
                )
            else:
                chart = (
                    ggplot(synthetic_violations, aes(x="type", y="count", fill="severity"))
                    + geom_col()
                    + coord_flip()
                    + scale_fill_manual(values={
                        "CRITICAL": "#EF4444",
                        "HIGH": "#F97316",
                        "MEDIUM": "#EAB308",
                        "LOW": "#10B981",
                    })
                    + theme_minimal()
                    + labs(title="Violation Distribution", x="", y="Count")
                )
            return chart.draw()
        except Exception:
            import matplotlib.pyplot as plt
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.text(0.5, 0.5, "Chart loading...", ha="center", va="center", fontsize=12)
            ax.axis("off")
            return fig

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

    # ── Analytics tab ─────────────────────────────────────────────────────────
    analytics_refresh_trigger: reactive.Value[int] = reactive.Value(0)

    @reactive.effect
    @reactive.event(input.analytics_refresh_btn)
    def _analytics_refresh() -> None:
        analytics_refresh_trigger.set(analytics_refresh_trigger() + 1)

    @reactive.calc
    def _analytics_runs() -> list[dict[str, Any]]:
        analytics_refresh_trigger()
        if _USE_REAL_MODULES and db is not None:
            return db.fetch_recent(50)
        return _effective_log(50)

    @reactive.calc
    def _analytics_kpi_values() -> tuple[int, float, float, float]:
        """Total runs, avg MTTR, compliance rate %, RAG hit rate %."""
        runs = _analytics_runs()
        if not runs:
            return (0, 0.0, 0.0, 0.0)
        total = len(runs)
        mttr_vals = [
            float(e["mttr_seconds"])
            for e in runs
            if e.get("mttr_seconds") is not None
        ]
        avg_mttr = sum(mttr_vals) / len(mttr_vals) if mttr_vals else 0.0
        approved = sum(1 for e in runs if str(e.get("reviewer_verdict", "")).strip().upper() == "APPROVED")
        compliance_pct = (approved / total) * 100.0 if total else 0.0
        rag_hits = sum(1 for e in runs if e.get("rag_hit") is True)
        rag_pct = (rag_hits / total) * 100.0 if total else 0.0
        return (total, avg_mttr, compliance_pct, rag_pct)

    @render.ui
    def analytics_kpi_total() -> Any:
        total = _analytics_kpi_values()[0]
        return ui.div(
            ui.h5("Total runs"),
            ui.p(str(total), class_="mb-0"),
            class_="metric-card",
        )

    @render.ui
    def analytics_kpi_mttr() -> Any:
        avg = _analytics_kpi_values()[1]
        return ui.div(
            ui.h5("Avg MTTR"),
            ui.p(f"{avg:.2f}s", class_="mb-0"),
            class_="metric-card",
        )

    @render.ui
    def analytics_kpi_compliance() -> Any:
        pct = _analytics_kpi_values()[2]
        return ui.div(
            ui.h5("Compliance rate"),
            ui.p(f"{pct:.1f}%", class_="mb-0"),
            class_="metric-card",
        )

    @render.ui
    def analytics_kpi_rag() -> Any:
        pct = _analytics_kpi_values()[3]
        return ui.div(
            ui.h5("RAG hit rate"),
            ui.p(f"{pct:.1f}%", class_="mb-0"),
            class_="metric-card",
        )

    @render.ui
    def analytics_chart_heatmap() -> Any:
        if not _CHARTS_AVAILABLE or charts is None:
            return ui.div(ui.p("Chart unavailable"), class_="metric-card")
        runs = _analytics_runs()
        enc = _chart_to_base64_png(charts.compliance_heatmap, runs)
        if not enc:
            return ui.div(ui.p("Chart unavailable"), class_="metric-card")
        return ui.div(
            ui.h6("Compliance heatmap"),
            ui.tags.img(
                src=f"data:image/png;base64,{enc}",
                alt="Compliance heatmap",
                style="max-width:100%; height:auto;",
            ),
            class_="metric-card",
        )

    @render.ui
    def analytics_chart_mttr() -> Any:
        if not _CHARTS_AVAILABLE or charts is None:
            return ui.div(ui.p("Chart unavailable"), class_="metric-card")
        runs = _analytics_runs()
        enc = _chart_to_base64_png(charts.mttr_trend, runs)
        if not enc:
            return ui.div(ui.p("Chart unavailable"), class_="metric-card")
        return ui.div(
            ui.h6("MTTR trend"),
            ui.tags.img(
                src=f"data:image/png;base64,{enc}",
                alt="MTTR trend",
                style="max-width:100%; height:auto;",
            ),
            class_="metric-card",
        )

    @render.ui
    def analytics_chart_donut() -> Any:
        if not _CHARTS_AVAILABLE or charts is None:
            return ui.div(ui.p("Chart unavailable"), class_="metric-card")
        runs = _analytics_runs()
        enc = _chart_to_base64_png(charts.violation_donut, runs)
        if not enc:
            return ui.div(ui.p("Chart unavailable"), class_="metric-card")
        return ui.div(
            ui.h6("Violation donut"),
            ui.tags.img(
                src=f"data:image/png;base64,{enc}",
                alt="Violation donut",
                style="max-width:100%; height:auto;",
            ),
            class_="metric-card",
        )

    @render.ui
    def analytics_chart_kb() -> Any:
        if not _CHARTS_AVAILABLE or charts is None:
            return ui.div(ui.p("Chart unavailable"), class_="metric-card")
        runs = _analytics_runs()
        enc = _chart_to_base64_png(charts.kb_growth, runs)
        if not enc:
            return ui.div(ui.p("Chart unavailable"), class_="metric-card")
        return ui.div(
            ui.h6("KB growth"),
            ui.tags.img(
                src=f"data:image/png;base64,{enc}",
                alt="KB growth",
                style="max-width:100%; height:auto;",
            ),
            class_="metric-card",
        )

    @render.download(filename="audit_log.csv")
    def analytics_csv_download() -> Any:
        import pandas as pd

        if _USE_REAL_MODULES and db is not None:
            rows = db.fetch_recent(10000)
        else:
            rows = _effective_log(10000)
        if not rows:
            yield "task_id,timestamp,violation_type,resource_id,reviewer_verdict,is_compliant,mttr_seconds,rag_hit\n"
            return
        df = pd.DataFrame(rows)
        yield df.to_csv(index=False)

    @reactive.calc
    def batch_results() -> list[dict[str, Any]]:
        """Build remediation report rows: resource_id, resource_type, verdict, violations, mttr_seconds."""
        resources = active_resources()
        runs = _analytics_runs()
        violations = _violations()
        # Violation count per resource
        viol_counts: dict[str, int] = {}
        for v in violations:
            rid = str(v.get("resource_id", ""))
            viol_counts[rid] = viol_counts.get(rid, 0) + 1
        # Latest run per resource (by timestamp)
        latest: dict[str, dict[str, Any]] = {}
        for r in runs:
            rid = str(r.get("resource_id", ""))
            ts = r.get("timestamp", "")
            if rid not in latest or (ts and str(ts) > str(latest[rid].get("timestamp", ""))):
                latest[rid] = r
        out: list[dict[str, Any]] = []
        for r in resources:
            rid = str(r.get("resource_id", ""))
            run = latest.get(rid)
            vcount = viol_counts.get(rid, 0)
            verdict = "NOT RUN"
            mttr = 0
            if run:
                rv = str(run.get("reviewer_verdict", "")).strip().upper()
                verdict = "COMPLIANT" if rv == "APPROVED" else rv or "NOT RUN"
                mttr = float(run.get("mttr_seconds", 0) or 0)
            out.append({
                "resource_id": rid,
                "resource_type": str(r.get("resource_type") or r.get("type", "")),
                "verdict": verdict,
                "violations": vcount,
                "mttr_seconds": mttr,
            })
        return out

    @reactive.calc
    def active_policy() -> str:
        """Return active OPA policy text for report."""
        return """package sovereignshield.policy
# Approved regions: us-east-1, us-gov-east-1
default approved_regions = false
approved_regions { input.region == "us-east-1" }
approved_regions { input.region == "us-gov-east-1" }

# CMK encryption (aws:kms) required
default cmk_encryption = false
cmk_encryption { input.encryption_enabled == true }

# DataClass=PHI tag on all resources
default phi_tag = false
phi_tag { "DataClass" in input.tags && input.tags["DataClass"] == "PHI" }

# is_public must be False
default is_public = false
is_public { input.is_public == false }

# data residency / region constraint
default data_residency = false
data_residency { input.region != "" }
"""

    @render.download(filename=lambda: f"sovereignshield_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf")
    async def export_pdf():
        from pdf_report import generate_report
        results = batch_results()
        if not results:
            results = [
                {
                    "resource_id": r["resource_id"],
                    "resource_type": r.get("resource_type", r.get("type", "")),
                    "verdict": "NOT RUN",
                    "violations": 0,
                    "mttr_seconds": 0,
                }
                for r in active_resources()
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

    # ── Record run & History (Sprint 6) ───────────────────────────────────────
    record_run_status: reactive.Value[str] = reactive.Value("")
    history_refresh_trigger: reactive.Value[int] = reactive.Value(0)

    @reactive.effect
    @reactive.event(input.record_run_btn)
    def _on_record_run() -> None:
        results = batch_results()
        if not results:
            record_run_status.set("No resources to record.")
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
            record_run_status.set("Supabase unavailable or tables missing. Check env and run audit_runs_schema.sql.")

    @reactive.effect
    @reactive.event(input.history_refresh_btn)
    def _on_history_refresh() -> None:
        history_refresh_trigger.set(history_refresh_trigger() + 1)

    @render.ui
    def history_record_status() -> Any:
        msg = record_run_status()
        if not msg:
            return ui.div()
        color = "#28a745" if "recorded" in msg.lower() else "#dc3545"
        return ui.p(msg, style=f"color:{color}; margin-bottom:12px;")

    @reactive.calc
    def _history_runs() -> list[dict[str, Any]]:
        history_refresh_trigger()
        if fetch_history is not None:
            return fetch_history(limit=50)
        return []

    _SYNTHETIC_HISTORY: list[dict[str, Any]] = [
        {"run_at": "2026-03-12 14:22", "total": 5, "compliance_rate": "60.0%", "avg_mttr": "3.8s", "trend": "−"},
        {"run_at": "2026-03-13 09:15", "total": 5, "compliance_rate": "80.0%", "avg_mttr": "2.1s", "trend": "↑"},
        {"run_at": "2026-03-14 11:45", "total": 5, "compliance_rate": "62.0%", "avg_mttr": "4.2s", "trend": "↓"},
    ]

    @render.table
    def history_table() -> Any:
        import pandas as pd
        runs = _history_runs()
        if not runs:
            return pd.DataFrame(_SYNTHETIC_HISTORY)
        rows = []
        for r in runs:
            run_at = r.get("run_at", "")
            if run_at:
                try:
                    from datetime import datetime
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
        return pd.DataFrame(rows)

    # ── About tab ─────────────────────────────────────────────────────────────

    @render.ui
    def about_panel() -> Any:
        def _qr_img(filename: str, alt: str) -> Any:
            b64 = _load_qr_b64(filename)
            if b64:
                if b64.startswith("/9j/"):
                    mime = "data:image/jpeg;base64"
                elif b64.startswith("iVBORw0KGgo"):
                    mime = "data:image/png;base64"
                else:
                    mime = "data:image/png;base64"
                return ui.tags.img(
                    src=f"{mime},{b64}",
                    alt=alt,
                    style="width:80px; height:80px; object-fit:contain;",
                )
            return ui.span("QR", class_="text-muted small")

        return ui.div(
            ui.div(
                ui.div(
                    (
                        ui.tags.div(
                            ui.tags.img(
                                src=_AVATAR_SRC,
                                style="width:96px;height:96px;border-radius:50%;object-fit:cover;"
                                      "object-position:center top;border:3px solid " + _BRAND_PURPLE + ";"
                                      "display:block;margin:0 auto 12px auto;",
                            ),
                            class_="text-center",
                        )
                        if _AVATAR_SRC
                        else ui.tags.div("RR", style=f"width:80px;height:80px;border-radius:50%;background:{_BRAND_PURPLE};color:white;display:flex;align-items:center;justify-content:center;font-weight:bold;font-size:24px;")
                    ),
                    ui.h4("Robert Reichert", style=f"color:{_BRAND_PURPLE}; margin-top:12px;"),
                    ui.p("Healthcare Data Scientist & AI Architect", class_="text-muted mb-1"),
                    ui.p("Sovereign Compliance. Automated. Auditable.", style=f"color:{_BRAND_GREEN}; font-weight:500;"),
                    class_="text-center mb-4",
                ),
                class_="col-12",
            ),
            ui.row(
                ui.column(
                    4,
                    ui.card(
                        ui.card_header("Cloud Compliance Automation"),
                        ui.card_body(
                            "OPA policy enforcement, HIPAA §164.312 controls, "
                            "FedRAMP-ready infrastructure validation",
                        ),
                        class_="about-card mb-3",
                    ),
                ),
                ui.column(
                    4,
                    ui.card(
                        ui.card_header("Agentic AI Systems"),
                        ui.card_body(
                            "Compound AI loops: Planner → Worker → Reviewer with "
                            "RAG-enhanced self-correction and Supabase audit trail",
                        ),
                        class_="about-card mb-3",
                    ),
                ),
                ui.column(
                    4,
                    ui.card(
                        ui.card_header("Healthcare Data Science"),
                        ui.card_body(
                            "22+ years Medicare Advantage analytics, $148M+ documented "
                            "savings, HEDIS/RADV/Star Ratings expertise",
                        ),
                        class_="about-card mb-3",
                    ),
                ),
            ),
            ui.div(
                ui.h6("Contact"),
                ui.p("Email: reichert.starguardai@email.com"),
                ui.p("LinkedIn: linkedin.com/in/robertreichert"),
                ui.p("Phone: +1 (480) 767-1337"),
                ui.p("Available March 2026 | Contract | Remote", style=f"color:{_BRAND_GREEN};"),
                class_="mb-4 p-3 rounded", style=f"background:#f8f9fa; border-left:4px solid {_BRAND_PURPLE};",
            ),
            ui.h6("Portfolio Apps"),
            ui.row(
                ui.column(
                    6,
                    ui.card(
                        ui.card_header("AuditShield Live"),
                        ui.card_body(
                            ui.p("HEDIS/RADV Chart Audit — Agentic RAG + Claude"),
                            ui.a("https://rreichert-auditshield-live.hf.space", href="https://rreichert-auditshield-live.hf.space", target="_blank"),
                            ui.div(_qr_img("QR_AuditShield_Live.b64.txt", "AuditShield QR"), class_="mt-2"),
                        ),
                        class_="services-card mb-3",
                    ),
                ),
                ui.column(
                    6,
                    ui.card(
                        ui.card_header("StarGuard Desktop"),
                        ui.card_body(
                            ui.p("Star Ratings Forecasting — Compound AI"),
                            ui.a("https://rreichert-starguard-desktop.hf.space", href="https://rreichert-starguard-desktop.hf.space", target="_blank"),
                            ui.div(_qr_img("QR_StarGuard_Desktop.b64.txt", "StarGuard Desktop QR"), class_="mt-2"),
                        ),
                        class_="services-card mb-3",
                    ),
                ),
                ui.column(
                    6,
                    ui.card(
                        ui.card_header("StarGuard Mobile"),
                        ui.card_body(
                            ui.p("Mobile Analytics — Field Operations"),
                            ui.a("https://rreichert-starguardai.hf.space", href="https://rreichert-starguardai.hf.space", target="_blank"),
                            ui.div(_qr_img("QR_Mobile_Tiny_Sized.b64.txt", "StarGuard Mobile QR"), class_="mt-2"),
                        ),
                        class_="services-card mb-3",
                    ),
                ),
                ui.column(
                    6,
                    ui.card(
                        ui.card_header("SovereignShield Desktop"),
                        ui.card_body(
                            ui.p("OPA policy enforcement — Agentic compliance"),
                            ui.a("https://rreichert-sovereignshield.hf.space", href="https://rreichert-sovereignshield.hf.space", target="_blank"),
                            ui.div(_qr_img("QR_SovereignShield_Desktop.b64.txt", "SovereignShield Desktop QR"), class_="mt-2"),
                        ),
                        class_="services-card mb-3",
                    ),
                ),
                ui.column(
                    6,
                    ui.card(
                        ui.card_header("SovereignShield Mobile"),
                        ui.card_body(
                            ui.p("Compliance Remediation — Mobile"),
                            ui.a("https://rreichert-sovereignshield-mobile.hf.space", href="https://rreichert-sovereignshield-mobile.hf.space", target="_blank"),
                            ui.div(_qr_img("QR_SovereignShield_Mobile.b64.txt", "SovereignShield Mobile QR"), class_="mt-2"),
                        ),
                        class_="services-card mb-3",
                    ),
                ),
            ),
            class_="container py-3",
        )

    # ── Services tab ──────────────────────────────────────────────────────────

    @render.ui
    def services_panel() -> Any:
        return ui.div(
            ui.row(
                ui.column(
                    4,
                    ui.card(
                        ui.card_header("Sovereign Cloud Compliance Audit — Senior Consultant Rate"),
                        ui.card_body(
                        ui.p(
                            "End-to-end OPA policy evaluation of your AWS/Azure "
                            "infrastructure against HIPAA, FedRAMP, and CMS requirements",
                            ),
                            ui.strong("Deliverables:"),
                            ui.tags.ul(
                                ui.tags.li("Terraform state analysis and violation report"),
                                ui.tags.li("Prioritized remediation plan (HIGH/MEDIUM/LOW)"),
                                ui.tags.li("HIPAA §164.312 compliance scorecard"),
                            ),
                            ui.p("Engagement: 2–4 weeks", class_="text-muted mt-2 mb-0"),
                        ),
                        class_="services-card mb-3",
                    ),
                ),
                ui.column(
                    4,
                    ui.card(
                        ui.card_header("Agentic AI System Design — Senior Consultant Rate"),
                        ui.card_body(
                            ui.p(
                                "Architecture and implementation of Compound AI systems with "
                                "Planner/Worker/Reviewer loops, RAG retrieval, and audit-trail persistence",
                            ),
                            ui.strong("Deliverables:"),
                            ui.tags.ul(
                                ui.tags.li("System architecture document"),
                                ui.tags.li("Working prototype with Claude API integration"),
                                ui.tags.li("ChromaDB knowledge base seeded with your domain content"),
                            ),
                            ui.p("Engagement: 4–8 weeks", class_="text-muted mt-2 mb-0"),
                        ),
                        class_="services-card mb-3",
                    ),
                ),
                ui.column(
                    4,
                    ui.card(
                        ui.card_header("HEDIS/RADV Analytics Consulting — Consulting Rate"),
                        ui.card_body(
                            ui.p(
                                "Medicare Advantage analytics from gap closure to RADV audit "
                                "defense, with AI-assisted chart review",
                            ),
                            ui.strong("Deliverables:"),
                            ui.tags.ul(
                                ui.tags.li("HEDIS measure gap analysis"),
                                ui.tags.li("RADV audit defense documentation"),
                                ui.tags.li("Star Ratings forecast model"),
                            ),
                            ui.p("Engagement: Ongoing", class_="text-muted mt-2 mb-0"),
                        ),
                        class_="services-card mb-3",
                    ),
                ),
            ),
            ui.div(
                ui.p("Available March 2026 | Contract | Remote", class_="mb-2"),
                ui.input_action_button(
                    "contact_btn",
                    "Discuss Engagement: reichert.starguardai@email.com",
                    class_="btn",
                    style=f"background-color:{_BRAND_GOLD}; color:#000;",
                ),
                class_="text-center mt-4 p-3",
            ),
            class_="container py-3",
        )


app = App(app_ui, server, debug=True)
