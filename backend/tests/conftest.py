import pytest

from app.config import load_domain_config
from app.services.data_store import DataStore
from app.services.tools import ToolRunner


@pytest.fixture
def cfg():
    return load_domain_config()


@pytest.fixture
def store():
    return DataStore.from_files()


@pytest.fixture
def runner(store):
    return ToolRunner(store)
