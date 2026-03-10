"""
Audit database — Supabase-backed agent_interactions with local fallback.
Schema matches: task_id, timestamp, violation_type, resource_id, planner_output,
worker_output, reviewer_verdict, reviewer_notes, is_compliant, mttr_seconds,
tokens_used, rag_hit.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

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

_rag_kb_count: Callable[[], int] | None = None
try:
    from ..rag.retriever import kb_count

    _rag_kb_count = kb_count
except ImportError:
    pass

_SUPABASE_AVAILABLE = False
_client: Any = None

try:
    from supabase import create_client
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_ANON_KEY") or os.environ.get("SUPABASE_SERVICE_KEY")
    if url and key:
        _client = create_client(url, key)
        _SUPABASE_AVAILABLE = True
except Exception:
    pass

_TABLE = "agent_interactions"
_LOCAL_EVENTS: list[dict[str, Any]] = []

# Seed events for local fallback when Supabase unavailable
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


class AuditDB:
    """Supabase-backed audit store with local fallback."""

    @property
    def is_connected(self) -> bool:
        """True if Supabase client is available and configured."""
        return _SUPABASE_AVAILABLE and _client is not None

    def insert(self, event: dict[str, Any]) -> bool:
        """Insert agent interaction event. Returns True if persisted to Supabase."""
        if _SUPABASE_AVAILABLE and _client is not None:
            try:
                row = {
                    "task_id": event.get("task_id"),
                    "timestamp": event.get("timestamp"),
                    "violation_type": event.get("violation_type"),
                    "resource_id": event.get("resource_id"),
                    "planner_output": event.get("planner_output"),
                    "worker_output": event.get("worker_output"),
                    "reviewer_verdict": event.get("reviewer_verdict"),
                    "reviewer_notes": event.get("reviewer_notes"),
                    "is_compliant": event.get("is_compliant", False),
                    "mttr_seconds": event.get("mttr_seconds"),
                    "tokens_used": event.get("tokens_used", 0),
                    "rag_hit": event.get("rag_hit", False),
                    "severity": event.get("severity"),
                }
                _client.table(_TABLE).insert(row).execute()
                return True
            except Exception:
                pass
        _LOCAL_EVENTS.append(event)
        return False

    def fetch_recent(self, limit: int = 10) -> list[dict[str, Any]]:
        """Fetch most recent events. Supabase if available, else local + seed."""
        if _SUPABASE_AVAILABLE and _client is not None:
            try:
                resp = (
                    _client.table(_TABLE)
                    .select("*")
                    .order("timestamp", desc=True)
                    .limit(limit)
                    .execute()
                )
                if resp.data and isinstance(resp.data, list):
                    return list(resp.data)
            except Exception:
                pass
        combined = list(_LOCAL_EVENTS) + list(_SEED_EVENTS)
        combined.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
        return combined[:limit]

    def avg_mttr(self) -> float:
        """Average MTTR in seconds. 0 if no data."""
        events = self.fetch_recent(100)
        vals = [float(e.get("mttr_seconds", 0)) for e in events if e.get("mttr_seconds") is not None]
        return sum(vals) / len(vals) if vals else 0.0

    def rag_hit_rate(self) -> float:
        """Fraction of events with rag_hit=True. 0 if no data."""
        events = self.fetch_recent(100)
        if not events:
            return 0.0
        hits = sum(1 for e in events if e.get("rag_hit") is True)
        return hits / len(events)

    def kb_count(self) -> int:
        """RAG knowledge base document count."""
        if _rag_kb_count is not None:
            return _rag_kb_count()
        return 0


db: AuditDB = AuditDB()
