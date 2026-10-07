from langchain.chat_models import init_chat_model
from langchain_core.language_models import BaseChatModel

from config import get_settings


class ModelNotConfiguredError(RuntimeError):
    pass


def get_model() -> BaseChatModel:
    settings = get_settings()
    if not settings.llm_model:
        raise ModelNotConfiguredError('Set LLM_MODEL in .env, e.g. "openai:gpt-4.1-mini"')

    options = {}
    if settings.llm_api_key:
        options["api_key"] = settings.llm_api_key.get_secret_value()
    return init_chat_model(settings.llm_model, **options)
