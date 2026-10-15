import pytest


@pytest.fixture(autouse=True)
def default_to_stub_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_MODE", "stub")
