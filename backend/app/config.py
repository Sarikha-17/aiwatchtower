"""Paths and static configuration. Model IDs are never hardcoded: read env vars only."""
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

# backend/app/config.py -> parents[2] is the repository root
REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
POLICY_DIR = REPO_ROOT / "policies"


@dataclass(frozen=True)
class DomainConfig:
    internal_domains: frozenset = field(default_factory=frozenset)
    allowlisted_external_domains: frozenset = field(default_factory=frozenset)
    demo_user: str = "security_admin@company.example"


def load_domain_config(path: Path | None = None) -> DomainConfig:
    path = path or (DATA_DIR / "config.json")
    raw = json.loads(path.read_text(encoding="utf-8"))
    return DomainConfig(
        internal_domains=frozenset(d.lower() for d in raw["internal_domains"]),
        allowlisted_external_domains=frozenset(
            d.lower() for d in raw["allowlisted_external_domains"]
        ),
        demo_user=raw.get("demo_user", "security_admin@company.example"),
    )


# Used from Level 3 onward (Nebius Token Factory, OpenAI-compatible)
NEBIUS_API_KEY = os.getenv("NEBIUS_API_KEY", "")
NEBIUS_BASE_URL = os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/")
NEMOTRON_NANO_MODEL = os.getenv("NEMOTRON_NANO_MODEL", "")
NEMOTRON_SUPER_MODEL = os.getenv("NEMOTRON_SUPER_MODEL", "")
NEMOTRON_ULTRA_MODEL = os.getenv("NEMOTRON_ULTRA_MODEL", "")
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"
