"""Panel module registry.

Adding a module = one entry here + a router in app/modules/<id>/router.py.
The frontend reads /api/modules and builds its navigation from it, so the menu
never needs editing on the UI side.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter

from .modules.suricata.router import router as suricata_router
from .modules.system.router import router as system_router


@dataclass(frozen=True)
class Module:
    id: str
    name: str
    description: str
    icon: str          # icon name resolved by the UI
    route: str         # Angular route path
    router: APIRouter
    enabled: bool = True
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "icon": self.icon,
            "route": self.route,
            "enabled": self.enabled,
            "tags": self.tags,
            "api_prefix": f"/api{self.router.prefix}",
        }


MODULES: list[Module] = [
    Module(
        id="ids",
        name="IDS / IPS",
        description="Intrusion detection and blocking: protection, alerts, traffic",
        icon="shield",
        route="/ids",
        router=suricata_router,
        tags=["security", "network"],
    ),
    Module(
        id="system",
        name="System",
        description="Device health: CPU, memory, temperature, interfaces",
        icon="cpu",
        route="/system",
        router=system_router,
        tags=["hardware"],
    ),
]


def enabled_modules() -> list[Module]:
    return [m for m in MODULES if m.enabled]
