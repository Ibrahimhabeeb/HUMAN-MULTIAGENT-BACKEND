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


def test_missing_certificate_override_uses_verified_defaults(monkeypatch, tmp_path, caplog):
    use_settings(monkeypatch, llm_model="openai:gpt-4.1-mini", llm_api_key="sk-test")
    missing = str(tmp_path / "missing-conda-cacert.pem")
    monkeypatch.setenv("SSL_CERT_FILE", missing)

    def initialise(model, **options):
        assert "SSL_CERT_FILE" not in os.environ
        assert options == {"api_key": "sk-test"}
        context = ssl.create_default_context()
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        return "model"

    monkeypatch.setattr(llm, "init_chat_model", initialise)
    assert llm.get_model() == "model"
    assert "missing-conda-cacert.pem" in caplog.text
    assert "TLS verification remains enabled" in caplog.text
    assert "sk-test" not in caplog.text


def test_existing_certificate_override_is_preserved(monkeypatch, tmp_path, calls, caplog):
    use_settings(monkeypatch, llm_model="openai:gpt-4.1-mini")
    certificate = tmp_path / "custom-ca.pem"
    certificate.touch()
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate))
    llm.get_model()
    assert os.environ["SSL_CERT_FILE"] == str(certificate)
    assert caplog.records == []


def test_no_certificate_override_is_added_when_unset(monkeypatch, calls, caplog):
    use_settings(monkeypatch, llm_model="openai:gpt-4.1-mini")
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    llm.get_model()
    assert "SSL_CERT_FILE" not in os.environ
    assert caplog.records == []
import os
import ssl
