"""OPA-style policy evaluation — evaluates CloudResource objects against sovereign policies.

Pure Python inline policy rules (no OPA subprocess). Returns typed Violation objects
for downstream agents and audit storage.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from app import CloudResource

_ALLOWED_REGIONS = frozenset({"us-east-1", "us-gov-east-1"})


class Violation(TypedDict):
    """Typed violation record for policy evaluation results."""

    resource_id: str
    violation_type: str
    severity: Literal["HIGH", "MEDIUM", "LOW"]
    regulation_cited: str
    detail: str


def _resource_id(res: CloudResource) -> str:
    """Derive stable resource identifier from attributes or type+name."""
    attrs = res.attributes or {}
    return (
        str(attrs.get("id") or attrs.get("bucket") or attrs.get("identifier") or "")
        or f"{res.type}.{res.name}"
    )


def _get_region(attrs: dict[str, Any]) -> str:
    """Extract region from attributes (region, availability_zone, arn)."""
    r = attrs.get("region") or attrs.get("region_name")
    if r:
        return str(r)
    az = attrs.get("availability_zone")
    if az:
        return str(az)[:-1] if len(str(az)) > 1 else str(az)
    arn = attrs.get("arn") or ""
    if ":" in str(arn):
        parts = str(arn).split(":")
        if len(parts) >= 4:
            return str(parts[3])
    return ""


def _encryption_enabled(attrs: dict[str, Any], res_type: str) -> bool:
    """Check if resource has encryption enabled (S3 or RDS)."""
    if res_type == "aws_db_instance":
        return bool(attrs.get("storage_encrypted"))
    if res_type in ("aws_s3_bucket", "aws_s3_bucket_v2"):
        sse = attrs.get("server_side_encryption_configuration")
        if sse:
            return True
        for k, v in attrs.items():
            if "sse_algorithm" in k.lower() or "encryption" in k.lower():
                if v and str(v).lower() not in ("", "none"):
                    return True
    return False


def _cmk_key_id(attrs: dict[str, Any], res_type: str) -> str:
    """Extract customer-managed key ID if present (S3 or RDS)."""
    if res_type == "aws_db_instance":
        return str(attrs.get("kms_key_id") or "")
    if res_type in ("aws_s3_bucket", "aws_s3_bucket_v2"):
        for k, v in attrs.items():
            if "kms_master_key_id" in k.lower() or "kms_key" in k.lower():
                if v:
                    return str(v)
    return ""


def _is_public(attrs: dict[str, Any], res_type: str) -> bool:
    """Check if resource is publicly exposed."""
    if res_type == "aws_db_instance":
        return bool(attrs.get("publicly_accessible"))
    if res_type in ("aws_s3_bucket", "aws_s3_bucket_v2"):
        acl = attrs.get("acl") or ""
        if "public" in str(acl).lower():
            return True
        for k, v in attrs.items():
            if "block_public" in k.lower() and v is False:
                return True
    return False


def _tags(attrs: dict[str, Any]) -> dict[str, str]:
    """Get tags as flat key->value dict."""
    tags = attrs.get("tags") or attrs.get("tags_all") or {}
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items() if v is not None}
    return {}


def evaluate(resources: list[CloudResource]) -> list[Violation]:
    """Evaluate resources against sovereign policies. Returns list of Violation dicts."""
    violations: list[Violation] = []

    for res in resources:
        attrs = res.attributes or {}
        rid = _resource_id(res)
        res_type = res.type or ""

        region = _get_region(attrs)
        if region and region not in _ALLOWED_REGIONS:
            violations.append(
                Violation(
                    resource_id=rid,
                    violation_type="data_residency",
                    severity="HIGH",
                    regulation_cited="HIPAA §164.312(a)(1)",
                    detail=f"Region '{region}' not in allowed sovereign regions {sorted(_ALLOWED_REGIONS)}",
                )
            )

        enc_enabled = _encryption_enabled(attrs, res_type)
        if not enc_enabled:
            if res_type in ("aws_s3_bucket", "aws_s3_bucket_v2", "aws_db_instance"):
                violations.append(
                    Violation(
                        resource_id=rid,
                        violation_type="hipaa_encryption",
                        severity="HIGH",
                        regulation_cited="HIPAA §164.312(a)(2)(iv)",
                        detail="Encryption at rest is not enabled",
                    )
                )
        else:
            cmk = _cmk_key_id(attrs, res_type)
            if not cmk and res_type in ("aws_s3_bucket", "aws_s3_bucket_v2", "aws_db_instance"):
                violations.append(
                    Violation(
                        resource_id=rid,
                        violation_type="cmk_required",
                        severity="MEDIUM",
                        regulation_cited="HIPAA §164.312(a)(2)(iv)",
                        detail="Encryption enabled but no customer-managed key (CMK); using default key",
                    )
                )

        if _is_public(attrs, res_type):
            violations.append(
                Violation(
                    resource_id=rid,
                    violation_type="public_exposure",
                    severity="HIGH",
                    regulation_cited="HIPAA §164.312(e)(1)",
                    detail="Resource is publicly accessible",
                )
            )

        tags = _tags(attrs)
        if tags.get("DataClass") != "PHI":
            violations.append(
                Violation(
                    resource_id=rid,
                    violation_type="phi_tagging",
                    severity="LOW",
                    regulation_cited="Internal sovereign policy",
                    detail="DataClass tag not set to PHI for data handling classification",
                )
            )

    return violations


if __name__ == "__main__":
    # Sanity check with synthetic data — run: python -m Artifacts.project.sovereignshield.core.opa_eval
    from app import CloudResource

    RESOURCES: list[CloudResource] = [
        CloudResource(
            type="aws_s3_bucket",
            name="staging_analytics",
            attributes={
                "id": "s3-staging-analytics",
                "bucket": "s3-staging-analytics",
                "region": "eu-west-1",
                "server_side_encryption_configuration": [
                    {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]}
                ],
                "tags": {},
            },
        ),
        CloudResource(
            type="aws_db_instance",
            name="dev_sandbox",
            attributes={
                "id": "rds-dev-sandbox",
                "identifier": "rds-dev-sandbox",
                "availability_zone": "eu-west-1a",
                "storage_encrypted": False,
                "publicly_accessible": True,
                "tags": {},
            },
        ),
    ]
    violations = evaluate(RESOURCES)
    for v in violations:
        print(f"{v['resource_id']:30s} {v['violation_type']:20s} {v['severity']:6s} {v['regulation_cited']}")
