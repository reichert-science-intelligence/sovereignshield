"""AuditDB — Supabase-backed storage for agent_interactions with graceful fallback."""

from __future__ import annotations

import os
from typing import Any, cast

from dotenv import load_dotenv
from supabase import Client, create_client

load_dotenv()

_TABLE = "agent_interactions"


class AuditDB:
    """Supabase-backed audit store. Graceful fallback when env vars not configured."""

    def __init__(self) -> None:
        load_dotenv()
        url = os.environ.get("SUPABASE_URL", "").strip()
        key = os.environ.get("SUPABASE_ANON_KEY", "").strip()
        self._client: Client | None = None
        if url and key:
            try:
                self._client = create_client(url, key)
            except Exception:
                self._client = None

    @property
    def is_connected(self) -> bool:
        """True if Supabase client is available."""
        return self._client is not None

    def insert(self, event: dict[str, Any]) -> bool:
        """Insert one agent interaction. Returns True on success."""
        if self._client is None:
            return False
        try:
            self._client.table(_TABLE).insert(event).execute()
            return True
        except Exception:
            return False

    def fetch_recent(self, limit: int = 10) -> list[dict[str, Any]]:
        """Fetch most recent interactions, newest first."""
        if self._client is None:
            return []
        try:
            resp = (
                self._client.table(_TABLE)
                .select("*")
                .order("timestamp", desc=True)
                .limit(limit)
                .execute()
            )
            return cast(list[dict[str, Any]], list(resp.data)) if resp.data else []
        except Exception:
            return []

    def kb_count(self) -> int:
        """Total count of records in agent_interactions (knowledge base size)."""
        if self._client is None:
            return 0
        try:
            resp = self._client.table(_TABLE).select("*", count="exact").limit(0).execute()  # type: ignore[arg-type]
            return int(resp.count) if hasattr(resp, "count") and resp.count is not None else 0
        except Exception:
            return 0

    def avg_mttr(self) -> float:
        """Average MTTR (mean time to remediation) in seconds. 0.0 if none."""
        if self._client is None:
            return 0.0
        try:
            resp = self._client.table(_TABLE).select("mttr_seconds").execute()
            rows = cast(list[dict[str, Any]], resp.data or [])
            vals = [float(r["mttr_seconds"]) for r in rows if r.get("mttr_seconds") is not None]
            return sum(vals) / len(vals) if vals else 0.0
        except Exception:
            return 0.0

    def rag_hit_rate(self) -> float:
        """Fraction of interactions where RAG retrieval hit. 0.0 if none."""
        if self._client is None:
            return 0.0
        try:
            resp = self._client.table(_TABLE).select("rag_hit").execute()
            rows = cast(list[dict[str, Any]], resp.data or [])
            if not rows:
                return 0.0
            hits = sum(1 for r in rows if r.get("rag_hit") is True)
            return hits / len(rows)
        except Exception:
            return 0.0


db: AuditDB = AuditDB()
