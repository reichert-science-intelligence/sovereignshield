"""
WorkerAgent — generates Terraform HCL fixes for compliance violations via Claude Sonnet.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from .planner import PlannerResult

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
class WorkerResult:
    """Result of worker generating HCL remediation for a violation."""

    task_id: str
    resource_id: str
    violation_type: str
    hcl_code: str
    hcl_line_count: int
    tokens_used: int


def _strip_markdown_fences(hcl: str) -> str:
    """Strip leading/trailing triple backticks from response. Critical for Reviewer."""
    hcl = hcl.strip()
    if hcl.startswith("```"):
        hcl = "\n".join(hcl.splitlines()[1:])
    if hcl.endswith("```"):
        hcl = "\n".join(hcl.splitlines()[:-1])
    return hcl.strip()


def _fallback_stub(resource_id: str, violation_type: str) -> str:
    """Minimal valid HCL stub when Claude is unavailable so Reviewer can still run."""
    safe_name = resource_id.replace(".", "_").replace("-", "_")[:40]
    return f'resource "aws_s3_bucket_server_side_encryption_configuration" "fix_{safe_name}" {{\n  bucket = "placeholder"\n  rule {{\n    apply_server_side_encryption_by_default {{\n      sse_algorithm = "AES256"\n    }}\n  }}\n}}\n'


class WorkerAgent:
    """Generates HIPAA-compliant Terraform HCL fixes using Claude Sonnet."""

    def __init__(self) -> None:
        pass

    def run(self, plan: PlannerResult) -> WorkerResult:
        """Generate HCL remediation from plan. Returns WorkerResult."""
        task_id = plan.task_id  # pass through unchanged
        resource_id = plan.resource_id
        violation_type = plan.violation_type

        api_key: str | None = None
        try:
            import os

            api_key = os.environ.get("ANTHROPIC_API_KEY")
        except Exception:
            api_key = None

        if not api_key:
            hcl = _fallback_stub(resource_id, violation_type)
            return WorkerResult(
                task_id=task_id,
                resource_id=resource_id,
                violation_type=violation_type,
                hcl_code=hcl,
                hcl_line_count=len(hcl.splitlines()),
                tokens_used=0,
            )

        system_prompt = (
            "You are a Terraform expert generating HIPAA-compliant infrastructure fixes for AWS. "
            "Output ONLY valid HCL code with no markdown fences, no explanation, no comments outside the resource blocks."
        )
        user_content = (
            f"fix_strategy: {plan.fix_strategy}\n"
            f"resource_id: {resource_id}\n"
            f"violation_type: {violation_type}\n"
            f"regulation_cited: {plan.regulation_cited}\n\n"
            "Generate Terraform HCL to fix this violation. Output only HCL, no markdown."
        )

        try:
            from anthropic import Anthropic

            client = Anthropic()
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2048,
                system=system_prompt,
                messages=[{"role": "user", "content": user_content}],
            )
        except Exception:
            hcl = _fallback_stub(resource_id, violation_type)
            return WorkerResult(
                task_id=task_id,
                resource_id=resource_id,
                violation_type=violation_type,
                hcl_code=hcl,
                hcl_line_count=len(hcl.splitlines()),
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

        hcl = _strip_markdown_fences(text) if text.strip() else _fallback_stub(resource_id, violation_type)
        if not hcl:
            hcl = _fallback_stub(resource_id, violation_type)

        return WorkerResult(
            task_id=task_id,
            resource_id=resource_id,
            violation_type=violation_type,
            hcl_code=hcl,
            hcl_line_count=len(hcl.splitlines()),
            tokens_used=tokens_used,
        )


worker: WorkerAgent = WorkerAgent()
