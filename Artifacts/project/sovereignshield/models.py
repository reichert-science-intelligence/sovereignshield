"""Shared data models for SovereignShield."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class LegacyCloudResource:
    """Legacy: Terraform state format (type, name, attributes) for tf_parser."""

    type: str
    name: str
    attributes: dict[str, Any]
    provider: str = ""
    module: str = ""


@dataclass
class CloudResource:
    """Typed representation of a cloud resource for policy evaluation."""

    resource_id: str
    resource_type: str
    region: str
    encryption_enabled: bool
    cmk_key_id: str | None
    is_public: bool
    tags: dict[str, str]
