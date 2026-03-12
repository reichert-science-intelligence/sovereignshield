"""
Sprint 5 — OPA eval tests.
Unit: mock subprocess — test parsing logic without OPA binary.
Integration: real OPA binary — compliant/violation inputs (skipped if OPA not installed).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure sovereignshield package is importable
_root = Path(__file__).resolve().parents[2]
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from sovereignshield.core.opa_eval import (
    _normalize_resource,
    _violation_str_to_dict,
    evaluate,
)


# ── Unit tests (mock subprocess) ──────────────────────────────────────────────


def test_normalize_resource_adds_defaults():
    """_normalize_resource adds tags, region, encryption_enabled, is_public if missing."""
    r = {"resource_id": "s3-x"}
    out = _normalize_resource(r)
    assert out["tags"] == {}
    assert out["region"] == ""
    assert out["encryption_enabled"] is False
    assert out["is_public"] is False
    assert out["resource_id"] == "s3-x"


def test_normalize_resource_preserves_existing():
    """_normalize_resource preserves existing fields."""
    r = {
        "resource_id": "ec2-y",
        "region": "us-east-1",
        "encryption_enabled": True,
        "is_public": False,
        "tags": {"DataClass": "PHI"},
    }
    out = _normalize_resource(r)
    assert out["region"] == "us-east-1"
    assert out["encryption_enabled"] is True
    assert out["tags"] == {"DataClass": "PHI"}


def test_violation_str_to_dict():
    """_violation_str_to_dict parses 'violation_type|message' into app dict."""
    d = _violation_str_to_dict("s3-staging", "data_residency|GDPR Art. 44")
    assert d["resource_id"] == "s3-staging"
    assert d["violation_type"] == "data_residency"
    assert d["severity"] == "HIGH"
    assert "GDPR" in d["regulation_cited"]
    assert "data_residency" in d["detail"]


def test_violation_str_to_dict_single_part():
    """_violation_str_to_dict handles string without pipe."""
    d = _violation_str_to_dict("r1", "unknown_violation")
    assert d["violation_type"] == "unknown_violation"
    assert d["detail"]


@patch("sovereignshield.core.opa_eval.subprocess.run")
def test_evaluate_parses_opa_output(mock_run):
    """evaluate parses OPA JSON output into violation dicts."""
    opa_result = {
        "result": [
            {
                "expressions": [
                    {
                        "value": [
                            "data_residency|data residency / region constraint",
                            "cmk_encryption|CMK encryption (aws:kms) required",
                        ],
                    }
                ]
            }
        ]
    }
    mock_run.return_value = type("R", (), {"returncode": 0, "stdout": json.dumps(opa_result), "stderr": ""})()

    resources = [
        {
            "resource_id": "s3-staging-analytics",
            "region": "eu-west-1",
            "encryption_enabled": False,
            "is_public": True,
            "tags": {},
        }
    ]
    violations = evaluate(resources)

    assert len(violations) == 2
    assert all(v["resource_id"] == "s3-staging-analytics" for v in violations)
    vtypes = {v["violation_type"] for v in violations}
    assert "data_residency" in vtypes
    assert "cmk_encryption" in vtypes


@patch("sovereignshield.core.opa_eval.subprocess.run")
def test_evaluate_handles_opa_error(mock_run):
    """evaluate returns opa_error violation when OPA returns non-zero."""
    mock_run.return_value = type("R", (), {"returncode": 1, "stdout": "", "stderr": "policy compile error"})()

    violations = evaluate([{"resource_id": "r1", "region": "us-east-1"}])
    assert len(violations) == 1
    assert violations[0]["violation_type"] == "opa_error"
    assert "OPA error" in violations[0]["detail"]


@patch("sovereignshield.core.opa_eval.subprocess.run")
def test_evaluate_empty_violations(mock_run):
    """evaluate returns empty list when OPA returns no violations."""
    opa_result = {"result": [{"expressions": [{"value": []}]}]}
    mock_run.return_value = type("R", (), {"returncode": 0, "stdout": json.dumps(opa_result), "stderr": ""})()

    resources = [
        {
            "resource_id": "ec2-compliant",
            "region": "us-east-1",
            "encryption_enabled": True,
            "is_public": False,
            "tags": {"DataClass": "PHI"},
        }
    ]
    violations = evaluate(resources)
    assert violations == []


# ── Integration tests (real OPA binary) ────────────────────────────────────────


def _opa_available() -> bool:
    import subprocess
    try:
        subprocess.run(["opa", "version"], capture_output=True, timeout=5, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


@pytest.mark.skipif(not _opa_available(), reason="OPA binary not installed")
def test_evaluate_integration_violation():
    """Integration: real OPA finds violations for non-compliant resource."""
    resources = [
        {
            "resource_id": "s3-staging-analytics",
            "region": "eu-west-1",
            "encryption_enabled": False,
            "is_public": True,
            "tags": {},
        }
    ]
    violations = evaluate(resources)
    assert len(violations) >= 1
    assert any(v["resource_id"] == "s3-staging-analytics" for v in violations)
    assert any(
        v["violation_type"] in ("data_residency", "approved_regions", "cmk_encryption", "phi_tag", "is_public")
        for v in violations
    )


@pytest.mark.skipif(not _opa_available(), reason="OPA binary not installed")
def test_evaluate_integration_compliant():
    """Integration: real OPA returns no violations for fully compliant resource."""
    resources = [
        {
            "resource_id": "ec2-prod",
            "region": "us-east-1",
            "encryption_enabled": True,
            "is_public": False,
            "tags": {"DataClass": "PHI"},
        }
    ]
    violations = evaluate(resources)
    assert violations == []
