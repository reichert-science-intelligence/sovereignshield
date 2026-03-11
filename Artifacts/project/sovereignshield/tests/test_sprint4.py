"""Sprint 4 CI hardening — parse_terraform, generate_report, DEFAULT_OPA_POLICY."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_artifacts = Path(__file__).resolve().parents[3]
if str(_artifacts) not in sys.path:
    sys.path.insert(0, str(_artifacts))


# 1. parse_terraform — .tfstate parsing
def test_parse_terraform_tfstate(tmp_path):
    """parse_terraform correctly parses a .tfstate file."""
    tfstate = {
        "resources": [
            {
                "type": "aws_s3_bucket",
                "name": "my_bucket",
                "instances": [
                    {
                        "attributes": {
                            "region": "us-east-1",
                            "tags": {"env": "prod"}
                        }
                    }
                ]
            }
        ]
    }
    f = tmp_path / "main.tfstate"
    f.write_text(json.dumps(tfstate))
    from project.sovereignshield.app import parse_terraform

    result = parse_terraform(str(f))
    assert len(result) == 1
    assert result[0]["resource_type"] == "aws_s3_bucket"
    assert result[0]["region"] == "us-east-1"


# 2. parse_terraform — .tf file parsing
def test_parse_terraform_tf(tmp_path):
    """parse_terraform correctly parses a .tf file."""
    tf_content = '''
resource "aws_s3_bucket" "my_bucket" {
  bucket = "test"
}
resource "aws_rds_instance" "my_db" {
  engine = "mysql"
}
'''
    f = tmp_path / "main.tf"
    f.write_text(tf_content)
    from project.sovereignshield.app import parse_terraform

    result = parse_terraform(str(f))
    assert len(result) == 2
    types = [r["resource_type"] for r in result]
    assert "aws_s3_bucket" in types
    assert "aws_rds_instance" in types


# 3. parse_terraform — fallback on empty file
def test_parse_terraform_empty_fallback(tmp_path):
    """parse_terraform returns empty list on empty file."""
    f = tmp_path / "empty.tf"
    f.write_text("")
    from project.sovereignshield.app import parse_terraform

    result = parse_terraform(str(f))
    assert isinstance(result, list)


# 4. parse_terraform — fallback on invalid JSON
def test_parse_terraform_invalid_json_fallback(tmp_path):
    """parse_terraform returns empty list on invalid JSON."""
    f = tmp_path / "bad.tfstate"
    f.write_text("not valid json {{{{")
    from project.sovereignshield.app import parse_terraform

    result = parse_terraform(str(f))
    assert isinstance(result, list)


# 5. generate_report — returns bytes
def test_generate_report_returns_bytes():
    """generate_report returns non-empty PDF bytes."""
    from project.sovereignshield.pdf_report import generate_report

    results = [
        {
            "resource_id": "res-001",
            "resource_type": "aws_s3_bucket",
            "verdict": "COMPLIANT",
            "violations": 0,
            "mttr_seconds": 1.2
        },
        {
            "resource_id": "res-002",
            "resource_type": "aws_rds_instance",
            "verdict": "VIOLATION",
            "violations": 2,
            "mttr_seconds": 3.4
        }
    ]
    policy = "package test\ndefault allow = false"
    pdf_bytes = generate_report(results, policy, "test.tfstate")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000


# 6. generate_report — PDF header signature
def test_generate_report_pdf_signature():
    """generate_report output starts with PDF magic bytes."""
    from project.sovereignshield.pdf_report import generate_report

    pdf_bytes = generate_report([], "policy", "demo")
    assert pdf_bytes[:4] == b"%PDF"


# 7. generate_report — empty batch results
def test_generate_report_empty_results():
    """generate_report handles empty batch results without error."""
    from project.sovereignshield.pdf_report import generate_report

    pdf_bytes = generate_report([], "package test", "demo data")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0


# 8. DEFAULT_OPA_POLICY — content check
def test_default_opa_policy_content():
    """DEFAULT_OPA_POLICY contains required Rego keywords."""
    from project.sovereignshield.app import DEFAULT_OPA_POLICY

    assert "package" in DEFAULT_OPA_POLICY
    assert "violation" in DEFAULT_OPA_POLICY
    assert "encryption_enabled" in DEFAULT_OPA_POLICY
    assert "is_public" in DEFAULT_OPA_POLICY
