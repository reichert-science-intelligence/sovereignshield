"""SovereignShield — Shiny for Python sovereign cloud compliance app."""

from dataclasses import dataclass
from typing import Any


@dataclass
class CloudResource:
    """Typed representation of a cloud resource parsed from Terraform state."""

    type: str
    name: str
    attributes: dict[str, Any]
    provider: str = ""
    module: str = ""


# Shiny app placeholder — will be built out
def server(input: object, output: object, session: object) -> None:
    pass
