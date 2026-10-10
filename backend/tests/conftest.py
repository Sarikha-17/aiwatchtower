import pytest

from app.config import load_domain_config
from app.services.data_store import DataStore
from app.services.tools import ToolRunner


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """Every test gets its own database and NEVER calls the real model API, even if a .env exists."""
    monkeypatch.setenv("AIWATCHTOWER_DB", str(tmp_path / "test.db"))
    for name in ("NEBIUS_API_KEY", "NEMOTRON_NANO_MODEL", "NEMOTRON_SUPER_MODEL", "NEMOTRON_ULTRA_MODEL"):
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("DEMO_MODE", "true")


@pytest.fixture
def cfg():
    return load_domain_config()


@pytest.fixture
def store():
    return DataStore.from_files()


@pytest.fixture
def runner(store):
    return ToolRunner(store)
