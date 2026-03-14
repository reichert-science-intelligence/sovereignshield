"""
ReviewerAgent — reviews Worker-generated HCL against OPA policy rules via Claude Sonnet.
Returns verdict, notes, checks_passed, checks_failed for the waterfall trace UI.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv

from .planner import PlannerResult
from .worker import WorkerResult

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


@dataclass
class ReviewerResult:
    """Result of reviewer validating Worker HCL against OPA policy rules."""

    task_id: str
    resource_id: str
    violation_type: str
    verdict: Literal["APPROVED", "NEEDS_REVISION", "REJECTED"]
    notes: str
    is_compliant: bool
    mttr_seconds: float
    tokens_used: int
    iteration: int
    checks_passed: list[str]
    checks_failed: list[str]


def _extract_json(text: str) -> str | None:
    """Extract first JSON object from text (handles nested braces and arrays)."""
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape = False
    quote_char = ""
    i = start
    while i < len(text):
        c = text[i]
        if escape:
            escape = False
            i += 1
            continue
        if c == "\\" and in_string:
            escape = True
            i += 1
            continue
        if in_string:
            if c == quote_char:
                in_string = False
            i += 1
            continue
        if c in ('"', "'"):
            in_string = True
            quote_char = c
            i += 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        i += 1
    return None


_OPA_SYSTEM_RULES = """Approved regions: us-east-1, us-gov-east-1
Required: CMK encryption (aws:kms), not AES256 alone
Required: DataClass=PHI tag on all resources
Required: is_public must be False"""


class ReviewerAgent:
    """Reviews Terraform HCL against OPA policy rules using Claude Sonnet."""

    def __init__(self, max_iterations: int = 3) -> None:
        self.max_iterations = max_iterations

    def run(
        self,
        plan: PlannerResult,
        work: WorkerResult,
        iteration: int = 1,
        started_at: datetime | None = None,
    ) -> ReviewerResult:
        """Review Worker HCL against OPA rules. Returns ReviewerResult."""
        start = started_at if started_at is not None else datetime.now()
        mttr_seconds = (datetime.now() - start).total_seconds()

        task_id = work.task_id
        resource_id = work.resource_id
        violation_type = work.violation_type

        system_prompt = (
            "You are a compliance reviewer validating Terraform HCL against OPA policy rules. "
            "Return JSON only with keys: verdict, notes, checks_passed, checks_failed. "
            "verdict must be one of: APPROVED, NEEDS_REVISION, REJECTED. "
            "checks_passed and checks_failed are lists of short strings describing each check. "
            "\n\nOPA policy rules:\n"
            + _OPA_SYSTEM_RULES
        )

        user_content = (
            f"HCL code to review:\n```hcl\n{work.hcl_code}\n```\n\n"
            f"violation_type: {plan.violation_type}\n"
            f"resource_id: {plan.resource_id}\n"
            f"regulation_cited: {plan.regulation_cited}\n\n"
            "Return JSON with verdict, notes, checks_passed (list of str), checks_failed (list of str)."
        )

        api_key: str | None = None
        try:
            import os

            api_key = os.environ.get("ANTHROPIC_API_KEY")
        except Exception:
            api_key = None

        if not api_key:
            return ReviewerResult(
                task_id=task_id,
                resource_id=resource_id,
                violation_type=violation_type,
                verdict="NEEDS_REVISION",
                notes="ANTHROPIC_API_KEY not set. Configure .env and retry.",
                is_compliant=False,
                mttr_seconds=mttr_seconds,
                tokens_used=0,
                iteration=iteration,
                checks_passed=[],
                checks_failed=["API key not configured"],
            )

        try:
            from anthropic import Anthropic

            client = Anthropic()
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                system=system_prompt,
                messages=[{"role": "user", "content": user_content}],
            )
        except Exception as e:
            err_msg = str(e).lower()
            if any(k in err_msg for k in ("credit", "400", "insufficient", "billing")):
                notes = "Agent unavailable — API credits required. Showing synthetic verdict for demo."
                checks_failed = ["API credits required"]
            else:
                notes = f"Claude call failed: {e!s}"
                checks_failed = [f"Review failed: {e!s}"]
            return ReviewerResult(
                task_id=task_id,
                resource_id=resource_id,
                violation_type=violation_type,
                verdict="NEEDS_REVISION",
                notes=notes,
                is_compliant=False,
                mttr_seconds=mttr_seconds,
                tokens_used=0,
                iteration=iteration,
                checks_passed=[],
                checks_failed=checks_failed,
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

        verdict: Literal["APPROVED", "NEEDS_REVISION", "REJECTED"] = "NEEDS_REVISION"
        notes = ""
        checks_passed: list[str] = []
        checks_failed: list[str] = []

        if text.strip():
            json_str = _extract_json(text)
            if json_str:
                try:
                    parsed = json.loads(json_str)
                    v = str(parsed.get("verdict", "NEEDS_REVISION")).upper()
                    if v == "APPROVED":
                        verdict = "APPROVED"
                    elif v == "REJECTED":
                        verdict = "REJECTED"
                    else:
                        verdict = "NEEDS_REVISION"

                    notes = str(parsed.get("notes", "")).strip()
                    raw_passed = parsed.get("checks_passed", [])
                    checks_passed = [str(x) for x in raw_passed] if isinstance(raw_passed, list) else []
                    raw_failed = parsed.get("checks_failed", [])
                    checks_failed = [str(x) for x in raw_failed] if isinstance(raw_failed, list) else []
                except json.JSONDecodeError:
                    verdict = "NEEDS_REVISION"
                    notes = f"Failed to parse Claude response as JSON. Raw: {text[:200]}..."
                    checks_failed = ["JSON parse failed"]
            else:
                verdict = "NEEDS_REVISION"
                notes = f"No JSON found in response. Raw: {text[:200]}..."
                checks_failed = ["No valid JSON in response"]

        return ReviewerResult(
            task_id=task_id,
            resource_id=resource_id,
            violation_type=violation_type,
            verdict=verdict,
            notes=notes or "No notes provided",
            is_compliant=(verdict == "APPROVED"),
            mttr_seconds=mttr_seconds,
            tokens_used=tokens_used,
            iteration=iteration,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
        )


reviewer: ReviewerAgent = ReviewerAgent()
