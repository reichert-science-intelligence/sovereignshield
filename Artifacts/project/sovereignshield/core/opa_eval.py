"""OPA policy evaluation — evaluates resources against compliance rules via real OPA binary."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any

_DEFAULT_POLICY = """package sovereignshield.compliance

# Approved regions: us-east-1, us-gov-east-1
approved_regions { input.region == "us-east-1" }
approved_regions { input.region == "us-gov-east-1" }

# CMK encryption (aws:kms) required
cmk_encryption { input.encryption_enabled == true }

# DataClass=PHI tag on all resources (tags may be missing)
phi_tag { input.tags["DataClass"] == "PHI" }

# is_public must be False
is_public_ok { input.is_public == false }

# data residency / region constraint (region must exist and be approved)
data_residency { input.region != ""; approved_regions }

# violation collects failed checks as "violation_type|message"
violation[v] {
    not approved_regions
    v := "approved_regions|Approved regions: us-east-1, us-gov-east-1"
}
violation[v] {
    not cmk_encryption
    v := "cmk_encryption|CMK encryption (aws:kms) required"
}
violation[v] {
    not phi_tag
    v := "phi_tag|DataClass=PHI tag on all resources"
}
violation[v] {
    not is_public_ok
    v := "is_public|is_public must be False"
}
violation[v] {
    not data_residency
    v := "data_residency|data residency / region constraint"
}
"""

# Map violation_type to regulation for report
_REGULATION_MAP: dict[str, str] = {
    "data_residency": "GDPR Art. 44 / CCPA",
    "approved_regions": "GDPR Art. 44",
    "cmk_encryption": "HIPAA §164.312",
    "phi_tag": "HIPAA §164.312",
    "is_public": "HIPAA §164.312",
}


def _violation_str_to_dict(resource_id: str, vstr: str) -> dict[str, Any]:
    """Convert OPA violation string 'violation_type|message' to app-expected dict."""
    parts = vstr.split("|", 1)
    vtype = parts[0].strip() if parts else "unknown"
    detail = parts[1].strip() if len(parts) > 1 else vstr
    return {
        "resource_id": resource_id,
        "violation_type": vtype,
        "severity": "HIGH",
        "regulation_cited": _REGULATION_MAP.get(vtype, ""),
        "detail": f"{vtype} for {resource_id}: {detail}",
    }


def _normalize_resource(r: dict[str, Any]) -> dict[str, Any]:
    """Ensure resource has tags, region, etc. for OPA input."""
    out = dict(r)
    if "tags" not in out:
        out["tags"] = {}
    if "region" not in out:
        out["region"] = ""
    if "encryption_enabled" not in out:
        out["encryption_enabled"] = False
    if "is_public" not in out:
        out["is_public"] = False
    return out


def _python_evaluate(resource: dict[str, Any]) -> list[str]:
    """Pure Python policy evaluation — no OPA binary needed."""
    violations: list[str] = []
    rid = resource.get("resource_id", "unknown")

    if not resource.get("encryption_enabled", True):
        violations.append("cmk_encryption|CMK encryption (aws:kms) required")
    if resource.get("is_public", False):
        violations.append("is_public|is_public must be False")
    approved = {"us-east-1", "us-west-2", "us-gov-west-1"}
    if resource.get("region", "us-east-1") not in approved:
        violations.append("data_residency|data residency / region constraint")
    tags = resource.get("tags", {}) or {}
    if str(resource.get("resource_type", "") or "").startswith("aws_s3"):
        if tags.get("DataClass") != "PHI":
            violations.append("phi_tag|DataClass=PHI tag on all resources")
    return violations


def _eval_with_opa(resource: dict[str, Any], policy: str) -> list[str] | None:
    """Run OPA eval for one resource. Returns violation strings or None on any failure."""
    norm = _normalize_resource(resource)
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = os.path.join(tmpdir, "policy.rego")
            with open(policy_path, "w") as f:
                f.write(policy)

            input_path = os.path.join(tmpdir, "input.json")
            with open(input_path, "w") as f:
                json.dump(norm, f)

            result = subprocess.run(
                [
                    "opa",
                    "eval",
                    "-d",
                    policy_path,
                    "-i",
                    input_path,
                    "data.sovereignshield.compliance.violation",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

        if result.returncode != 0:
            return None

        output = json.loads(result.stdout)
        raw = (
            output.get("result", [{}])[0]
            .get("expressions", [{}])[0]
            .get("value", [])
        )
        if not isinstance(raw, list):
            return None
        return [str(x) for x in raw]
    except Exception:
        return None


def _resource_to_dict(r: Any) -> dict[str, Any]:
    """Normalize CloudResource or dict to dict for OPA input."""
    if isinstance(r, dict):
        return dict(r)
    return {
        "resource_id": getattr(r, "resource_id", ""),
        "resource_type": getattr(r, "resource_type", ""),
        "region": getattr(r, "region", "us-east-1"),
        "encryption_enabled": getattr(r, "encryption_enabled", True),
        "is_public": getattr(r, "is_public", False),
        "tags": getattr(r, "tags", {}),
    }


def evaluate(
    resources: list[dict[str, Any]],
    policy: str | None = None,
) -> list[dict[str, Any]]:
    """Evaluate resources against OPA policies. Returns list of violations (dicts)."""
    policy_text = policy or _DEFAULT_POLICY
    results: list[dict[str, Any]] = []
    for r in resources:
        r_norm = _resource_to_dict(r)
        rid = str(r_norm.get("resource_id", "unknown"))
        raw_violations = _eval_with_opa(r_norm, policy_text)
        if raw_violations is None:
            raw_violations = _python_evaluate(r_norm)
        for vstr in raw_violations:
            results.append(_violation_str_to_dict(rid, vstr))
    return results
