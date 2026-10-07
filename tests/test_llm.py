import pytest

import llm
from config import Settings


def use_settings(monkeypatch, **values):
    # _env_file=None: build settings from these values only, never from the real .env.
    settings = Settings(_env_file=None, **values)
    monkeypatch.setattr(llm, "get_settings", lambda: settings)


@pytest.fixture
def calls(monkeypatch):
    # Replace init_chat_model so no test ever contacts a real provider.
    recorded = []

    def fake_init_chat_model(model, **options):
        recorded.append((model, options))
        return "model"

    monkeypatch.setattr(llm, "init_chat_model", fake_init_chat_model)
    return recorded


def test_missing_model_gives_a_clear_error(monkeypatch, calls):
    use_settings(monkeypatch)
    with pytest.raises(llm.ModelNotConfiguredError):
        llm.get_model()
    assert calls == []


def test_model_and_key_are_passed_to_langchain(monkeypatch, calls):
    use_settings(monkeypatch, llm_model="openai:gpt-4.1-mini", llm_api_key="sk-test")
    assert llm.get_model() == "model"
    assert calls == [("openai:gpt-4.1-mini", {"api_key": "sk-test"})]


def test_no_key_is_sent_when_none_is_set(monkeypatch, calls):
    use_settings(monkeypatch, llm_model="ollama:llama3.1")
    llm.get_model()
    assert calls == [("ollama:llama3.1", {})]


def test_the_key_is_hidden_when_settings_are_printed():
    settings = Settings(_env_file=None, llm_api_key="sk-test")
    assert "sk-test" not in str(settings)
    assert "sk-test" not in repr(settings)
