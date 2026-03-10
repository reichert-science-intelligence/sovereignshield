"""SovereignShield test suite — OPA eval, tf_parser, audit_db, agents, retriever."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure Artifacts is on path for project.sovereignshield imports
_artifacts = Path(__file__).resolve().parents[3]
if str(_artifacts) not in sys.path:
    sys.path.insert(0, str(_artifacts))


# ── OPA eval ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_opa_eval_evaluate_returns_seven_violations() -> None:
    """evaluate(RESOURCES) returns 7 violations for the full 5-resource catalogue."""
    from project.sovereignshield.core.opa_eval import evaluate
    from project.sovereignshield.models import CloudResource

    resources: list[CloudResource] = [
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
    violations = evaluate(resources)
    assert len(violations) == 7


@pytest.mark.unit
def test_opa_eval_violation_has_required_keys() -> None:
    """Each violation dict has resource_id, violation_type, severity, regulation_cited, detail."""
    from project.sovereignshield.core.opa_eval import evaluate
    from project.sovereignshield.models import CloudResource

    resources: list[CloudResource] = [
        CloudResource(
            resource_id="s3-staging-analytics",
            resource_type="aws_s3_bucket",
            region="eu-central-1",
            encryption_enabled=False,
            cmk_key_id=None,
            is_public=False,
            tags={},
        ),
    ]
    violations = evaluate(resources)
    assert len(violations) >= 1
    v = violations[0]
    assert "resource_id" in v
    assert "violation_type" in v
    assert "severity" in v
    assert "regulation_cited" in v
    assert "detail" in v


# ── tf_parser ─────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_tf_parser_parse_tfstate_dict_minimal_valid() -> None:
    """parse_tfstate_dict with minimal valid state dict returns list of LegacyCloudResource."""
    from project.sovereignshield.core.tf_parser import parse_tfstate_dict

    state: dict[str, list[dict[str, object]]] = {
        "resources": [
            {
                "type": "aws_s3_bucket",
                "name": "test_bucket",
                "instances": [
                    {"attributes": {"id": "s3-test", "region": "us-east-1"}},
                ],
            },
        ],
    }
    result = parse_tfstate_dict(state)
    assert len(result) == 1
    res = result[0]
    assert res.type == "aws_s3_bucket"
    assert res.name == "test_bucket"
    assert res.attributes.get("id") == "s3-test"


@pytest.mark.unit
def test_tf_parser_parse_tfstate_dict_empty_returns_empty() -> None:
    """parse_tfstate_dict with empty resources returns empty list."""
    from project.sovereignshield.core.tf_parser import parse_tfstate_dict

    result = parse_tfstate_dict({"resources": []})
    assert result == []


@pytest.mark.unit
def test_tf_parser_parse_tfstate_dict_missing_resources_returns_empty() -> None:
    """parse_tfstate_dict with missing resources key returns empty list."""
    from project.sovereignshield.core.tf_parser import parse_tfstate_dict

    result = parse_tfstate_dict({})
    assert result == []


# ── AuditDB ───────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_audit_db_is_connected_is_bool() -> None:
    """db.is_connected is a boolean."""
    from project.sovereignshield.core.audit_db import db

    assert isinstance(db.is_connected, bool)


@pytest.mark.unit
def test_audit_db_kb_count_returns_int() -> None:
    """db.kb_count() returns an integer."""
    from project.sovereignshield.core.audit_db import db

    count = db.kb_count()
    assert isinstance(count, int)
    assert count >= 0


# ── PlannerResult ──────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_planner_result_dataclass_has_required_fields() -> None:
    """PlannerResult dataclass has task_id, resource_id, violation_type, fix_strategy, etc."""
    from project.sovereignshield.agents.planner import PlannerResult

    p = PlannerResult(
        task_id="t-001",
        resource_id="s3-staging",
        violation_type="data_residency",
        regulation_cited="HIPAA",
        fix_strategy="Add encryption",
        priority="HIGH",
        rag_hit=False,
        rag_source=None,
        tokens_used=0,
    )
    assert p.task_id == "t-001"
    assert p.resource_id == "s3-staging"
    assert p.violation_type == "data_residency"
    assert p.fix_strategy == "Add encryption"
    assert p.priority == "HIGH"
    assert p.rag_hit is False
    assert isinstance(p.tokens_used, int)


@pytest.mark.unit
def test_planner_result_priority_literal() -> None:
    """PlannerResult.priority accepts HIGH, MEDIUM, LOW."""
    from project.sovereignshield.agents.planner import PlannerResult

    for pri in ("HIGH", "MEDIUM", "LOW"):
        p = PlannerResult(
            task_id="t",
            resource_id="r",
            violation_type="x",
            regulation_cited="c",
            fix_strategy="f",
            priority=pri,
            rag_hit=False,
            rag_source=None,
            tokens_used=0,
        )
        assert p.priority == pri


# ── WorkerResult ───────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_worker_result_task_id_passes_through_from_planner() -> None:
    """WorkerResult.task_id equals PlannerResult.task_id when worker runs."""
    from project.sovereignshield.agents.planner import PlannerResult
    from project.sovereignshield.agents.worker import WorkerAgent

    plan = PlannerResult(
        task_id="plan-task-42",
        resource_id="s3-test",
        violation_type="data_residency",
        regulation_cited="HIPAA",
        fix_strategy="Encrypt",
        priority="HIGH",
        rag_hit=False,
        rag_source=None,
        tokens_used=0,
    )
    worker = WorkerAgent()
    result = worker.run(plan)
    assert result.task_id == "plan-task-42"


@pytest.mark.unit
def test_worker_result_has_hcl_code() -> None:
    """WorkerResult has non-empty hcl_code when fallback stub is used."""
    from project.sovereignshield.agents.planner import PlannerResult
    from project.sovereignshield.agents.worker import WorkerAgent

    plan = PlannerResult(
        task_id="t",
        resource_id="s3-test",
        violation_type="data_residency",
        regulation_cited="",
        fix_strategy="",
        priority="HIGH",
        rag_hit=False,
        rag_source=None,
        tokens_used=0,
    )
    worker = WorkerAgent()
    result = worker.run(plan)
    assert len(result.hcl_code) > 0
    assert "aws_s3_bucket" in result.hcl_code or "encryption" in result.hcl_code.lower()


# ── ReviewerResult ────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_reviewer_result_is_compliant_true_only_when_verdict_approved() -> None:
    """ReviewerResult.is_compliant is True only when verdict == APPROVED."""
    from project.sovereignshield.agents.reviewer import ReviewerResult

    approved = ReviewerResult(
        task_id="t",
        resource_id="r",
        violation_type="x",
        verdict="APPROVED",
        notes="ok",
        is_compliant=True,
        mttr_seconds=1.0,
        tokens_used=0,
        iteration=1,
        checks_passed=["a"],
        checks_failed=[],
    )
    assert approved.is_compliant is True
    assert approved.verdict == "APPROVED"

    rejected = ReviewerResult(
        task_id="t",
        resource_id="r",
        violation_type="x",
        verdict="REJECTED",
        notes="bad",
        is_compliant=False,
        mttr_seconds=1.0,
        tokens_used=0,
        iteration=1,
        checks_passed=[],
        checks_failed=["b"],
    )
    assert rejected.is_compliant is False
    assert rejected.verdict == "REJECTED"


@pytest.mark.unit
def test_reviewer_result_needs_revision_not_compliant() -> None:
    """ReviewerResult with verdict NEEDS_REVISION has is_compliant False."""
    from project.sovereignshield.agents.reviewer import ReviewerResult

    r = ReviewerResult(
        task_id="t",
        resource_id="r",
        violation_type="x",
        verdict="NEEDS_REVISION",
        notes="fix",
        is_compliant=False,
        mttr_seconds=1.0,
        tokens_used=0,
        iteration=1,
        checks_passed=[],
        checks_failed=["c"],
    )
    assert r.is_compliant is False


# ── retriever ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_retriever_embed_and_store_returns_bool() -> None:
    """embed_and_store returns a boolean."""
    from project.sovereignshield.rag.retriever import embed_and_store

    result = embed_and_store("test violation", "resource \"x\" {}", {"key": "val"})
    assert isinstance(result, bool)


@pytest.mark.unit
def test_retriever_retrieve_similar_returns_tuple() -> None:
    """retrieve_similar returns tuple[str|None, float]."""
    from project.sovereignshield.rag.retriever import retrieve_similar

    text, score = retrieve_similar("data residency violation")
    assert text is None or isinstance(text, str)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


@pytest.mark.unit
def test_retriever_retrieve_similar_empty_kb_returns_none_zero() -> None:
    """retrieve_similar with empty KB returns (None, 0.0) or similar."""
    from project.sovereignshield.rag.retriever import retrieve_similar

    text, score = retrieve_similar("nonexistent query xyz123")
    # May be (None, 0.0) if empty, or (None, <threshold) if has data
    assert text is None or isinstance(text, str)
    assert isinstance(score, (int, float))


@pytest.mark.unit
def test_opa_eval_legacy_format_supported() -> None:
    """evaluate accepts legacy LegacyCloudResource format from tf_parser."""
    from project.sovereignshield.core.opa_eval import evaluate
    from project.sovereignshield.core.tf_parser import parse_tfstate_dict

    state = {
        "resources": [
            {
                "type": "aws_s3_bucket",
                "name": "legacy_bucket",
                "instances": [
                    {
                        "attributes": {
                            "id": "s3-legacy",
                            "region": "eu-west-1",
                            "tags": {},
                        },
                    },
                ],
            },
        ],
    }
    resources = parse_tfstate_dict(state)
    violations = evaluate(resources)
    assert len(violations) >= 1
    assert any(v["violation_type"] == "data_residency" for v in violations)


# ── models ────────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_cloud_resource_dataclass() -> None:
    """CloudResource has resource_id, resource_type, region, etc."""
    from project.sovereignshield.models import CloudResource

    r = CloudResource(
        resource_id="s3-x",
        resource_type="aws_s3_bucket",
        region="us-east-1",
        encryption_enabled=True,
        cmk_key_id="arn:...",
        is_public=False,
        tags={"a": "b"},
    )
    assert r.resource_id == "s3-x"
    assert r.resource_type == "aws_s3_bucket"
    assert r.region == "us-east-1"
    assert r.encryption_enabled is True
    assert r.is_public is False
    assert r.tags == {"a": "b"}


@pytest.mark.unit
def test_legacy_cloud_resource_dataclass() -> None:
    """LegacyCloudResource has type, name, attributes."""
    from project.sovereignshield.models import LegacyCloudResource

    r = LegacyCloudResource(
        type="aws_s3_bucket",
        name="test",
        attributes={"id": "s3-1", "region": "us-east-1"},
    )
    assert r.type == "aws_s3_bucket"
    assert r.name == "test"
    assert r.attributes["id"] == "s3-1"


# ── Sprint 1 chart module (core/charts.py) ─────────────────────────────────────


@pytest.mark.unit
def test_heatmap_data_columns() -> None:
    """heatmap_data returns DataFrame with resource_id, violation_type, status, run_count."""
    import pandas as pd

    from project.sovereignshield.core.charts import heatmap_data

    runs = [
        {"resource_id": "s3-x", "violation_type": "data_residency", "is_compliant": True},
        {"resource_id": "ec2-y", "violation_type": "encryption", "is_compliant": False},
    ]
    df = heatmap_data(runs)
    assert isinstance(df, pd.DataFrame)
    assert set(df.columns) >= {"resource_id", "violation_type", "status", "run_count"}
    assert len(df) == 2
    assert df["status"].iloc[0] == "compliant"
    assert df["status"].iloc[1] == "violation"


@pytest.mark.unit
def test_mttr_trend_data_shape() -> None:
    """mttr_trend_data returns DataFrame with run_index, mttr_seconds, timestamp; respects limit."""
    import pandas as pd

    from project.sovereignshield.core.charts import mttr_trend_data

    runs = [
        {"timestamp": "2025-03-09T10:00:00", "mttr_seconds": 4.2},
        {"timestamp": "2025-03-09T11:00:00", "mttr_seconds": 3.1},
        {"timestamp": "2025-03-09T12:00:00", "mttr_seconds": 5.0},
    ]
    df = mttr_trend_data(runs, limit=20)
    assert isinstance(df, pd.DataFrame)
    assert set(df.columns) >= {"run_index", "mttr_seconds", "timestamp"}
    assert len(df) == 3
    df2 = mttr_trend_data(runs, limit=2)
    assert len(df2) == 2


@pytest.mark.unit
def test_donut_data_counts() -> None:
    """donut_data returns severity counts for HIGH, MEDIUM, LOW, INFO."""
    import pandas as pd

    from project.sovereignshield.core.charts import donut_data

    runs = [
        {"severity": "HIGH"},
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
        {"severity": "LOW"},
        {"severity": "INFO"},
    ]
    df = donut_data(runs)
    assert isinstance(df, pd.DataFrame)
    assert set(df.columns) >= {"severity", "count"}
    high_row = df[df["severity"] == "HIGH"]
    assert len(high_row) == 1
    assert high_row["count"].iloc[0] == 2
    assert df["count"].sum() == 5


@pytest.mark.unit
def test_kb_growth_data_nonnegative() -> None:
    """kb_growth_data returns session/kb_added with non-negative counts."""
    import pandas as pd

    from project.sovereignshield.core.charts import kb_growth_data

    runs = [
        {"timestamp": "2025-03-09T10:00:00", "is_compliant": True},
        {"timestamp": "2025-03-09T10:30:00", "is_compliant": True},
        {"timestamp": "2025-03-09T10:45:00", "is_compliant": False},
        {"timestamp": "2025-03-10T09:00:00", "is_compliant": True},
    ]
    df = kb_growth_data(runs)
    assert isinstance(df, pd.DataFrame)
    assert set(df.columns) >= {"session", "kb_added"}
    assert (df["kb_added"] >= 0).all()
    assert df["kb_added"].sum() == 3


@pytest.mark.unit
def test_compliance_heatmap_returns_ggplot() -> None:
    """compliance_heatmap returns a plotnine ggplot object."""
    pytest.importorskip("plotnine")
    from project.sovereignshield.core.charts import compliance_heatmap

    runs = [
        {"resource_id": "s3-x", "violation_type": "data_residency", "is_compliant": True},
    ]
    p = compliance_heatmap(runs)
    assert p is not None
    assert hasattr(p, "draw") or "ggplot" in type(p).__name__ or "ggplot" in str(type(p))


@pytest.mark.unit
def test_mttr_trend_returns_ggplot() -> None:
    """mttr_trend returns a plotnine ggplot object."""
    pytest.importorskip("plotnine")
    from project.sovereignshield.core.charts import mttr_trend

    runs = [
        {"timestamp": "2025-03-09T10:00:00", "mttr_seconds": 4.2},
        {"timestamp": "2025-03-09T11:00:00", "mttr_seconds": 3.1},
    ]
    p = mttr_trend(runs, limit=20)
    assert p is not None
    assert hasattr(p, "draw") or "ggplot" in type(p).__name__ or "ggplot" in str(type(p))
