"""
PlannerAgent — plans remediation for compliance violations via Claude Sonnet.
RAG retrieval (Chat 7) is guarded with try/except; swap in real retriever later with zero changes.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal, Optional

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

# RAG: guard with try/except — rag/retriever.py doesn't exist until Chat 7
retrieve_similar: Optional[Callable[..., tuple[str | None, float]]] = None
try:
    from ..rag.retriever import retrieve_similar as _retrieve_similar
    retrieve_similar = _retrieve_similar
    _RAG_AVAILABLE = True
except ImportError:
    _RAG_AVAILABLE = False


@dataclass
class PlannerResult:
    """Result of planner planning a remediation for a violation."""

    task_id: str
    resource_id: str
    violation_type: str
    regulation_cited: str
    fix_strategy: str
    priority: Literal["HIGH", "MEDIUM", "LOW"]
    rag_hit: bool
    rag_source: str | None
    tokens_used: int


class PlannerAgent:
    """Plans fix strategy for compliance violations using Claude Sonnet and optional RAG."""

    def __init__(self, rag_threshold: float = 0.85) -> None:
        self.rag_threshold = rag_threshold

    def run(self, violation: dict[str, Any]) -> PlannerResult:
        """Plan remediation for a single violation. Returns PlannerResult."""
        # Normalize violation to dict (may be CloudResource-like object)
        if not isinstance(violation, dict):
            violation = {
                "resource_id": getattr(violation, "resource_id", ""),
                "violation_type": getattr(violation, "violation_type", ""),
                "regulation_cited": getattr(violation, "regulation_cited", ""),
                "detail": getattr(violation, "detail", ""),
            }
        task_id = str(uuid.uuid4())
        resource_id = str(violation.get("resource_id", ""))
        violation_type = str(violation.get("violation_type", ""))
        regulation_cited_from_violation = str(violation.get("regulation_cited", ""))

        # RAG retrieval
        rag_hit = False
        rag_source: str | None = None
        if _RAG_AVAILABLE and retrieve_similar is not None:
            try:
                query = f"{violation_type} {resource_id} {regulation_cited_from_violation}"
                result = retrieve_similar(query)
                # Assume (text, score) or similar; adapt based on actual retriever API
                if isinstance(result, tuple) and len(result) >= 2:
                    text, score = result[0], result[1]
                    if score >= self.rag_threshold:
                        rag_hit = True
                        rag_source = str(text)
                elif isinstance(result, dict) and result.get("score", 0) >= self.rag_threshold:
                    rag_hit = True
                    rag_source = str(result.get("text", result.get("content", "")))
                elif hasattr(result, "score") and float(getattr(result, "score", 0)) >= self.rag_threshold:
                    rag_hit = True
                    rag_source = str(getattr(result, "text", getattr(result, "content", "")))
            except Exception:
                rag_hit = False
                rag_source = None

        # Build system prompt
        system_parts = [
            "You are a compliance remediation planner. Given a violation, output JSON with keys: fix_strategy, priority, regulation_cited.",
            f"Violation detail: resource_id={resource_id}, violation_type={violation_type}, regulation_cited={regulation_cited_from_violation}.",
        ]
        if rag_hit and rag_source:
            system_parts.append(f"A prior successful fix for a similar case:\n{rag_source}\nUse this as guidance but adapt to the current violation.")
        system_prompt = "\n".join(system_parts)

        user_prompt = f"Plan remediation for: {resource_id} / {violation_type}. Return JSON only."

        # Claude call
        import os

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return PlannerResult(
                task_id=task_id,
                resource_id=resource_id,
                violation_type=violation_type,
                regulation_cited=regulation_cited_from_violation or "Unknown",
                fix_strategy="[ANTHROPIC_API_KEY not set] Configure .env and retry.",
                priority="HIGH",
                rag_hit=rag_hit,
                rag_source=rag_source,
                tokens_used=0,
            )

        try:
            from anthropic import Anthropic

            client = Anthropic()
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
        except Exception as e:
            err = str(e).lower()
            if "credit" in err or "400" in err or "insufficient" in err:
                fix_msg = "Agent unavailable — API credits required. Showing synthetic verdict for demo."
            else:
                fix_msg = f"[Claude error] {e!s}"
            return PlannerResult(
                task_id=task_id,
                resource_id=resource_id,
                violation_type=violation_type,
                regulation_cited=regulation_cited_from_violation or "Unknown",
                fix_strategy=fix_msg,
                priority="HIGH",
                rag_hit=rag_hit,
                rag_source=rag_source,
                tokens_used=0,
            )

        tokens_used = (
            response.usage.input_tokens + response.usage.output_tokens
            if response.usage
            else 0
        )
        text = ""
        for block in response.content:
            if hasattr(block, "text") and block.text:
                text += block.text

        # Parse JSON — fallback to raw text in fix_strategy if parse fails
        fix_strategy = ""
        priority: Literal["HIGH", "MEDIUM", "LOW"] = "HIGH"
        regulation_cited = regulation_cited_from_violation or "Unknown"

        if text.strip():
            # Try to extract JSON from response (may be wrapped in markdown)
            json_match = re.search(r"\{[^{}]*\}", text, re.DOTALL)
            if json_match:
                try:
                    parsed = json.loads(json_match.group())
                    fix_strategy = str(parsed.get("fix_strategy", text)).strip() or text.strip()
                    p = str(parsed.get("priority", "HIGH")).upper()
                    priority = "HIGH" if p == "HIGH" else "LOW" if p == "LOW" else "MEDIUM"
                    regulation_cited = str(parsed.get("regulation_cited", regulation_cited))
                except json.JSONDecodeError:
                    fix_strategy = text.strip()
            else:
                fix_strategy = text.strip()

        return PlannerResult(
            task_id=task_id,
            resource_id=resource_id,
            violation_type=violation_type,
            regulation_cited=regulation_cited,
            fix_strategy=fix_strategy,
            priority=priority,
            rag_hit=rag_hit,
            rag_source=rag_source,
            tokens_used=tokens_used,
        )


planner = PlannerAgent()
