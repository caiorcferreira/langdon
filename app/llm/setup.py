import dspy
import os
from litellm import LiteLLM

PROVIDERS = {
    "OpenAI": "openai",
    "Antropic": "antropic",
}
MODELS = {
    "openai": [
        "gpt-4o-mini",
        "o1-mini",
        "o1-preview",
        "gpt-4o",
        "gpt-4",
        "gpt-3.5-turbo",
    ],
    "antropic": [
        "claude-3",
        "claude-3-5-sonnet-20240620",
        "claude-3-haiku-20240307",
        "claude-3-opus-20240229",
        "claude-3-sonnet-20240229",
        "claude-2",
        "claude-2.1",
        "claude-instant-1.2"
    ],
}


def configure_lm(provider, model):
    if provider not in PROVIDERS:
        raise ValueError("Invalid provider")

    if model not in MODELS[PROVIDERS[provider]]:
        raise ValueError("Invalid model")

    provider_prefix = PROVIDERS[provider]

    model_fqn = f"{provider_prefix}/{model}"

    lm_args = {"model": model_fqn}

    api_base = os.getenv("LANGDON_LLM_PROVIDER_API_BASE")
    if api_base is not None:
        lm_args["api_base"] = api_base

    api_key = os.getenv("LANGDON_LLM_OVERRIDE_API_KEY")
    if api_key is not None:
        lm_args["api_key"] = api_key

    header = os.getenv("LANGDON_LLM_PROVIDER_EXTRA_HEADER")
    if header is not None:
        name, value = header.split(":")
        lm_args["extra_headers"] = {name: value}

    lm = dspy.LM(**lm_args)

    return lm
