"""
Audit log — Supabase-backed audit_runs and audit_results for batch remediation history.
Sprint 6: Persist every batch run and individual resource verdict for compliance trending.
Uses same Sovereign project (SUPABASE_URL, SUPABASE_ANON_KEY) as audit_db.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

_path = Path(__file__).resolve()
_pkg = _path.parents[1]
_env_candidates: list[Path] = [_pkg / ".env"]
if len(_path.parts) >= 6:
    _env_candidates.extend([
        _path.parents[4] / ".env",
        _path.parents[4].parent / "sovereignshield" / ".env",
    ])
for _p in _env_candidates:
    if _p.is_file():
        load_dotenv(dotenv_path=_p)

_SUPABASE_AVAILABLE = False
_client: Any = None

try:
    from supabase import create_client
    url = os.environ.get("SOVEREIGN_SUPABASE_URL")
    key = os.environ.get("SOVEREIGN_SUPABASE_ANON_KEY") or os.environ.get("SUPABASE_SERVICE_KEY")
    if url and key:
        _client = create_client(url, key)
        _SUPABASE_AVAILABLE = True
except Exception:
    pass

_TABLE_RUNS = "audit_runs"
_TABLE_RESULTS = "audit_results"

_APP_VERSION = "1.0.0"


def write_run(
    batch_results: list[dict[str, Any]],
    source_filename: str = "",
    policy_text: str = "",
    app_version: str = _APP_VERSION,
) -> str | None:
    """
    Persist a batch run to audit_runs + audit_results.
    Returns run_id (UUID) if successful, None otherwise.
    """
    if not _SUPABASE_AVAILABLE or _client is None:
        return None
    if not batch_results:
        return None

    total = len(batch_results)
    compliant = sum(
        1 for r in batch_results
        if str(r.get("verdict", "")).strip().upper() in ("COMPLIANT", "APPROVED")
    )
    violation_count = sum(int(r.get("violations", 0) or 0) for r in batch_results)
    mttrs = [
        float(r.get("mttr_seconds", 0))
        for r in batch_results
        if r.get("mttr_seconds") is not None
    ]
    avg_mttr = sum(mttrs) / len(mttrs) if mttrs else 0.0

    try:
        run_row: dict[str, Any] = {
            "source_filename": source_filename or None,
            "total_resources": total,
            "compliant_count": compliant,
            "violation_count": violation_count,
            "avg_mttr_seconds": avg_mttr,
            "policy_text": policy_text or None,
            "app_version": app_version,
        }
        resp = _client.table(_TABLE_RUNS).insert(run_row).execute()
        if not resp.data or not isinstance(resp.data, list) or len(resp.data) == 0:
            return None
        run_id = resp.data[0].get("id")
        if not run_id:
            return None

        result_rows: list[dict[str, Any]] = []
        for r in batch_results:
            verdict = str(r.get("verdict", "NOT RUN")).strip()
            result_rows.append({
                "run_id": run_id,
                "resource_id": str(r.get("resource_id", "")),
                "resource_type": str(r.get("resource_type", "")),
                "verdict": verdict,
                "violations": int(r.get("violations", 0) or 0),
                "mttr_seconds": float(r.get("mttr_seconds", 0) or 0),
            })
        if result_rows:
            _client.table(_TABLE_RESULTS).insert(result_rows).execute()
        return str(run_id)
    except Exception:
        return None


def fetch_history(limit: int = 50) -> list[dict[str, Any]]:
    """
    Fetch past audit runs ordered by run_at descending.
    Returns list of run summary dicts with: id, run_at, source_filename,
    total_resources, compliant_count, violation_count, avg_mttr_seconds,
    compliance_rate, trending (up/down/stable vs previous run).
    """
    if not _SUPABASE_AVAILABLE or _client is None:
        return []

    try:
        resp = (
            _client.table(_TABLE_RUNS)
            .select("*")
            .order("run_at", desc=True)
            .limit(limit)
            .execute()
        )
        if not resp.data or not isinstance(resp.data, list):
            return []
        runs = list(resp.data)

        # Compute compliance_rate and trending
        for i, r in enumerate(runs):
            total = int(r.get("total_resources", 0) or 0)
            compliant = int(r.get("compliant_count", 0) or 0)
            r["compliance_rate"] = (compliant / total * 100.0) if total else 0.0

            # Trending: compare to previous run
            if i + 1 < len(runs):
                prev_total = int(runs[i + 1].get("total_resources", 0) or 0)
                prev_compliant = int(runs[i + 1].get("compliant_count", 0) or 0)
                prev_rate = (prev_compliant / prev_total * 100.0) if prev_total else 0.0
                curr_rate = r["compliance_rate"]
                if curr_rate > prev_rate:
                    r["trending"] = "up"
                elif curr_rate < prev_rate:
                    r["trending"] = "down"
                else:
                    r["trending"] = "stable"
            else:
                r["trending"] = "stable"

        return runs
    except Exception:
        return []
