"""
SovereignShield chart generation — plotnine-based visualizations for compliance analytics.
Data helpers and ggplot builders for heatmap, MTTR trend, violation donut, KB growth.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

import pandas as pd

def heatmap_data(runs: list[dict[str, Any]]) -> pd.DataFrame:
    """
    Build resource × policy compliance matrix for heatmap.
    Returns DataFrame with columns: resource_id, violation_type, status, run_count.
    status is one of 'compliant', 'violation', 'mixed'.
    Uses most recent run per (resource_id, violation_type) for status.
    """
    if not runs:
        return pd.DataFrame(columns=["resource_id", "violation_type", "status", "run_count"])

    rows: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], list[bool]] = {}

    for r in runs:
        rid = str(r.get("resource_id", ""))
        vtype = str(r.get("violation_type", ""))
        compliant = bool(r.get("is_compliant", False))
        key = (rid, vtype)
        if key not in seen:
            seen[key] = []
        seen[key].append(compliant)

    for (rid, vtype), compliances in seen.items():
        if all(compliances):
            status = "compliant"
        elif not any(compliances):
            status = "violation"
        else:
            status = "mixed"
        rows.append({
            "resource_id": rid,
            "violation_type": vtype,
            "status": status,
            "run_count": len(compliances),
        })

    return pd.DataFrame(rows)


def mttr_trend_data(runs: list[dict[str, Any]], limit: int = 20) -> pd.DataFrame:
    """
    Build MTTR trend data for line chart.
    Returns DataFrame with columns: run_index, mttr_seconds, timestamp.
    Sorted chronologically (oldest first) for plotting.
    """
    if not runs:
        return pd.DataFrame(columns=["run_index", "mttr_seconds", "timestamp"])

    sorted_runs = sorted(
        runs,
        key=lambda x: str(x.get("timestamp", "")),
        reverse=True,
    )[:limit]
    sorted_runs.reverse()  # chronologically ascending for line plot

    rows = []
    for i, r in enumerate(sorted_runs):
        mttr = r.get("mttr_seconds")
        if mttr is not None:
            rows.append({
                "run_index": i + 1,
                "mttr_seconds": float(mttr),
                "timestamp": r.get("timestamp", ""),
            })

    return pd.DataFrame(rows)


def donut_data(runs: list[dict[str, Any]]) -> pd.DataFrame:
    """
    Build severity counts for violation donut chart.
    Returns DataFrame with columns: severity, count.
    Severity normalized to HIGH, MEDIUM, LOW, INFO; unknown -> INFO.
    """
    if not runs:
        return pd.DataFrame(columns=["severity", "count"])

    valid = {"HIGH", "MEDIUM", "LOW", "INFO"}
    counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for r in runs:
        s = str(r.get("severity", "INFO")).upper().strip()
        if s in valid:
            counts[s] = counts.get(s, 0) + 1
        else:
            counts["INFO"] += 1

    return pd.DataFrame(
        [{"severity": k, "count": v} for k, v in counts.items() if v > 0],
        columns=["severity", "count"],
    )


def kb_growth_data(runs: list[dict[str, Any]]) -> pd.DataFrame:
    """
    Build KB entries added per session for bar chart.
    Session = calendar day (from timestamp).
    KB entries = runs where is_compliant=True (each triggers embed_and_store).
    Returns DataFrame with columns: session, kb_added.
    """
    if not runs:
        return pd.DataFrame(columns=["session", "kb_added"])

    by_session: dict[str, int] = {}
    for r in runs:
        if not r.get("is_compliant", False):
            continue
        ts = r.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            session = dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            session = str(ts)[:10] if ts else "unknown"
        by_session[session] = by_session.get(session, 0) + 1

    rows = [{"session": s, "kb_added": c} for s, c in sorted(by_session.items())]
    return pd.DataFrame(rows, columns=["session", "kb_added"])


def compliance_heatmap(runs: list[dict[str, Any]]) -> Any:
    """
    Plot compliance heatmap: resource × policy matrix, red/amber/green cells.
    Returns plotnine ggplot object.
    """
    data = heatmap_data(runs)
    if data.empty:
        # Empty state
        data = pd.DataFrame({
            "resource_id": ["(no data)"],
            "violation_type": ["(no data)"],
            "status": ["mixed"],
            "run_count": [0],
        })

    from plotnine import aes, geom_tile, ggplot, scale_fill_manual, theme_minimal

    color_map = {"compliant": "#28a745", "violation": "#dc3545", "mixed": "#ffc107"}
    fill_order = ["compliant", "violation", "mixed"]
    data["status"] = pd.Categorical(data["status"], categories=fill_order, ordered=True)

    p = (
        ggplot(data, aes(x="resource_id", y="violation_type", fill="status"))
        + geom_tile(width=0.9, height=0.9)
        + scale_fill_manual(values=color_map, na_value="#e0e0e0")
        + theme_minimal()
    )
    return p


def mttr_trend(runs: list[dict[str, Any]], limit: int = 20) -> Any:
    """
    Plot MTTR trend line chart over last N runs.
    Returns plotnine ggplot object.
    """
    data = mttr_trend_data(runs, limit=limit)
    if data.empty:
        data = pd.DataFrame({"run_index": [1], "mttr_seconds": [0.0], "timestamp": [""]})

    from plotnine import aes, geom_line, geom_point, ggplot, theme_minimal

    p = (
        ggplot(data, aes(x="run_index", y="mttr_seconds"))
        + geom_line()
        + geom_point()
        + theme_minimal()
    )
    return p


def violation_donut(runs: list[dict[str, Any]]) -> Any:
    """
    Plot violation breakdown donut: HIGH/MEDIUM/LOW counts.
    Returns plotnine ggplot object.
    """
    data = donut_data(runs)
    if data.empty:
        data = pd.DataFrame({"severity": ["INFO"], "count": [0]})

    from plotnine import aes, geom_bar, ggplot, scale_fill_manual, theme_void
    from plotnine.coords import coord_polar

    severity_colors = {"HIGH": "#dc3545", "MEDIUM": "#ffc107", "LOW": "#28a745", "INFO": "#6c757d"}
    p = (
        ggplot(data, aes(x="1", y="count", fill="severity"))
        + geom_bar(stat="identity", width=0.6)
        + coord_polar(theta="y")
        + scale_fill_manual(values=severity_colors, na_value="#e0e0e0")
        + theme_void()
    )
    return p


def kb_growth(runs: list[dict[str, Any]]) -> Any:
    """
    Plot KB entries added per session as bar chart.
    Returns plotnine ggplot object.
    """
    data = kb_growth_data(runs)
    if data.empty:
        data = pd.DataFrame({"session": ["(no data)"], "kb_added": [0]})

    from plotnine import aes, geom_col, ggplot, theme_minimal

    p = (
        ggplot(data, aes(x="session", y="kb_added"))
        + geom_col()
        + theme_minimal()
    )
    return p
