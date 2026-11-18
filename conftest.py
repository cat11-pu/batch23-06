import pytest
@pytest.fixture(autouse=True)
def clean():
    yield
