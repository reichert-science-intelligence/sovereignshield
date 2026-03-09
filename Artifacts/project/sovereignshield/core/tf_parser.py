"""Terraform state parser — ingests .tfstate JSON and returns typed CloudResource objects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app import CloudResource


def parse_tfstate(path: str) -> list[CloudResource]:
    """Load .tfstate from file path and parse into CloudResource list."""
    content = Path(path).read_text(encoding="utf-8")
    state: dict[str, Any] = json.loads(content)
    return parse_tfstate_dict(state)


def parse_tfstate_dict(state: dict[str, Any]) -> list[CloudResource]:
    """Parse a Terraform state dict into a list of CloudResource objects.

    Handles Terraform state v3/v4 format. Iterates resources[], then instances[]
    within each resource. Missing keys use sensible defaults.
    """
    result: list[CloudResource] = []
    resources: list[dict[str, Any]] = state.get("resources") or []

    for resource in resources:
        res_type: str = resource.get("type") or "unknown"
        res_name: str = resource.get("name") or "unnamed"
        provider: str = resource.get("provider") or ""
        module: str = resource.get("module") or ""

        instances: list[dict[str, Any]] = resource.get("instances") or []

        for idx, instance in enumerate(instances):
            attributes: dict[str, Any] = instance.get("attributes") or {}
            instance_name = res_name
            if len(instances) > 1:
                index_key = instance.get("index_key")
                if index_key is not None:
                    instance_name = f"{res_name}[{index_key}]"
                else:
                    instance_name = f"{res_name}[{idx}]"

            result.append(
                CloudResource(
                    type=res_type,
                    name=instance_name,
                    attributes=attributes,
                    provider=provider,
                    module=module,
                )
            )

    return result
