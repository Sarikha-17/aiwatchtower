"""Paths, domain config and settings. Model IDs are never hardcoded: they come from the environment."""
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

# backend/app/config.py -> parents[2] is the repository root
REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
POLICY_DIR = REPO_ROOT / "policies"


def load_dotenv(path: Path | None = None) -> None:
    """Minimal .env loader (no extra dependency). Existing environment variables win."""
    path = path or (REPO_ROOT / ".env")
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass(frozen=True)
class Settings:
    api_key: str
    base_url: str
    nano_model: str
    super_model: str
    ultra_model: str
    demo_mode: bool
    price_in_per_1m: float | None
    price_out_per_1m: float | None
    nano_intent_mode: str  # off | annotate | escalate
    max_tokens: int = 4000  # reasoning models spend tokens thinking before they answer


def _float_or_none(name: str):
    raw = os.getenv(name, "").strip()
    try:
        return float(raw) if raw else None
    except ValueError:
        return None


def _int_or_default(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, "").strip() or default)
    except ValueError:
        return default
    return value if value > 0 else default


def get_settings() -> Settings:
    """Read the environment on every call so tests and .env changes take effect."""
    return Settings(
        api_key=os.getenv("NEBIUS_API_KEY", "").strip(),
        base_url=os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/").strip(),
        nano_model=os.getenv("NEMOTRON_NANO_MODEL", "").strip(),
        super_model=os.getenv("NEMOTRON_SUPER_MODEL", "").strip(),
        ultra_model=os.getenv("NEMOTRON_ULTRA_MODEL", "").strip(),
        demo_mode=os.getenv("DEMO_MODE", "false").strip().lower() == "true",
        price_in_per_1m=_float_or_none("MODEL_PRICE_INPUT_PER_1M_USD"),
        price_out_per_1m=_float_or_none("MODEL_PRICE_OUTPUT_PER_1M_USD"),
        nano_intent_mode=os.getenv("NANO_INTENT_CHECK", "off").strip().lower()
        if os.getenv("NANO_INTENT_CHECK", "off").strip().lower() in ("off", "annotate", "escalate") else "off",
        max_tokens=_int_or_default("NEMOTRON_MAX_TOKENS", 4000),
    )


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
        allowlisted_external_domains=frozenset(d.lower() for d in raw["allowlisted_external_domains"]),
        demo_user=raw.get("demo_user", "security_admin@company.example"),
    )
