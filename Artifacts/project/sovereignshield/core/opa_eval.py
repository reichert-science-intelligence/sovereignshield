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


def _normalize_resource(r: Any) -> dict[str, Any]:
    """Normalize CloudResource or dict to a plain dict for OPA input."""
    if isinstance(r, dict):
        out = dict(r)
    else:
        # CloudResource dataclass — convert to dict
        out = {
            "resource_id": getattr(r, "resource_id", "unknown"),
            "resource_type": getattr(r, "resource_type", "unknown"),
            "region": getattr(r, "region", "us-east-1"),
            "encryption_enabled": getattr(r, "encryption_enabled", True),
            "is_public": getattr(r, "is_public", False),
            "tags": getattr(r, "tags", {}) or {},
        }
    if "tags" not in out:
        out["tags"] = {}
    if "region" not in out:
        out["region"] = ""
    if "encryption_enabled" not in out:
        out["encryption_enabled"] = False
    if "is_public" not in out:
        out["is_public"] = False
    return out


def _eval_single_resource(resource: dict[str, Any], policy: str) -> list[str]:
    """Run OPA eval for one resource. Returns list of violation strings."""
    norm = _normalize_resource(resource)
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
            return [f"OPA error: {result.stderr.strip()}"]

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            return [f"OPA parse error: {result.stdout[:200]}"]

        raw = (
            output.get("result", [{}])[0]
            .get("expressions", [{}])[0]
            .get("value", [])
        )
        if not isinstance(raw, list):
            return []
        return [str(x) for x in raw]


def evaluate(
    resources: list[dict[str, Any]],
    policy: str | None = None,
) -> list[dict[str, Any]]:
    """Evaluate resources against OPA policies. Returns list of violations (dicts)."""
    policy_text = policy or _DEFAULT_POLICY
    violations: list[dict[str, Any]] = []
    for r in resources:
        resource_dict = _normalize_resource(r)
        rid = str(resource_dict.get("resource_id", "unknown"))
        raw_violations = _eval_single_resource(resource_dict, policy_text)
        for vstr in raw_violations:
            if vstr.startswith("OPA error:") or vstr.startswith("OPA parse error:"):
                violations.append(
                    {
                        "resource_id": rid,
                        "violation_type": "opa_error",
                        "severity": "HIGH",
                        "regulation_cited": "",
                        "detail": vstr,
                    }
                )
            else:
                violations.append(_violation_str_to_dict(rid, vstr))
    return violations
