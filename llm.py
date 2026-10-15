import logging
import os
from pathlib import Path

from langchain.chat_models import init_chat_model
from langchain_core.language_models import BaseChatModel

from config import get_settings


class ModelNotConfiguredError(RuntimeError):
    pass


class ModelCallError(RuntimeError):
    pass


def get_model() -> BaseChatModel:
    settings = get_settings()
    if not settings.llm_model:
        raise ModelNotConfiguredError('Set LLM_MODEL in .env, e.g. "openai:gpt-4.1-mini"')

    certificate = os.environ.get("SSL_CERT_FILE")
    if certificate and not Path(certificate).is_file():
        # Conda can leave a stale override. Let the SDK use its default trusted CAs, never disable verification.
        logging.getLogger(__name__).warning(
            "SSL_CERT_FILE points to a missing file (%s); using the AI client's default trusted certificates. "
            "TLS verification remains enabled.",
            certificate,
        )
        os.environ.pop("SSL_CERT_FILE", None)

    options = {}
    if settings.llm_api_key:
        options["api_key"] = settings.llm_api_key.get_secret_value()
    return init_chat_model(settings.llm_model, **options)
