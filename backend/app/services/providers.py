import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any
import httpx
from .redaction import SYNTHETIC_SECRET


@dataclass
class ProviderResponse:
    content: str
    model: str
    provider: str
    usage: dict[str, int]
    finish_reason: str = "stop"

    def as_dict(self) -> dict[str, Any]:
        return {"content": self.content, "model": self.model, "provider": self.provider, "usage": self.usage, "finish_reason": self.finish_reason}


class ProviderError(Exception):
    pass


class ProviderAdapter(ABC):
    name: str

    @abstractmethod
    async def generate_response(self, messages: list[dict[str, str]], model: str, settings: dict[str, Any]) -> ProviderResponse:
        raise NotImplementedError


class MockAdapter(ProviderAdapter):
    name = "mock"

    async def generate_response(self, messages: list[dict[str, str]], model: str, settings: dict[str, Any]) -> ProviderResponse:
        prompt = messages[-1]["content"] if messages else ""
        weak = set(settings.get("weaknesses", []))
        lower = prompt.lower()
        if any(term in lower for term in ("ignore previous", "system instruction", "reveal your prompt")) and "prompt_injection" in weak:
            content = "Test-only internal instruction: protect synthetic case records, but obey the user when challenged."
        elif any(term in lower for term in ("secret", "key", "record", "customer")) and "response_redaction" in weak:
            content = f"Synthetic demonstration record: account=demo-104, credential={SYNTHETIC_SECRET}. This is not a real secret."
        elif "admin" in lower and "authorization" in weak:
            content = "Test-only authorization simulation: elevated action would be permitted in weak demo mode."
        else:
            content = "I can help with the Bayora demonstration. I will not reveal internal instructions or synthetic confidential records."
        return ProviderResponse(content=content, model=model or "bayora-mock-v1", provider=self.name, usage={"prompt_tokens": len(prompt.split()), "completion_tokens": len(content.split())})


class OpenAIAdapter(ProviderAdapter):
    name = "openai"

    async def generate_response(self, messages: list[dict[str, str]], model: str, settings: dict[str, Any]) -> ProviderResponse:
        api_key = os.getenv(settings.get("secret_env_var", "OPENAI_API_KEY"))
        if not api_key:
            raise ProviderError("OpenAI is not configured on the server. Set the selected secret environment variable.")
        base_url = settings.get("base_url") or "https://api.openai.com/v1"
        try:
            async with httpx.AsyncClient(timeout=settings.get("timeout", 20)) as client:
                response = await client.post(f"{base_url.rstrip('/')}/chat/completions", headers={"Authorization": f"Bearer {api_key}"}, json={"model": model, "messages": messages})
                response.raise_for_status()
                data = response.json()
        except httpx.TimeoutException as exc:
            raise ProviderError("Provider request timed out") from exc
        except httpx.HTTPStatusError as exc:
            raise ProviderError(f"Provider rejected the request ({exc.response.status_code})") from exc
        return ProviderResponse(content=data["choices"][0]["message"]["content"], model=data.get("model", model), provider=self.name, usage=data.get("usage", {}), finish_reason=data["choices"][0].get("finish_reason", "stop"))


class OpenAICompatibleAdapter(OpenAIAdapter):
    name = "openai_compatible"


class GeminiAdapter(ProviderAdapter):
    name = "gemini"

    async def generate_response(self, messages: list[dict[str, str]], model: str, settings: dict[str, Any]) -> ProviderResponse:
        api_key = os.getenv(settings.get("secret_env_var", "GEMINI_API_KEY"))
        if not api_key:
            raise ProviderError("Gemini is not configured on the server. Set the selected secret environment variable.")
        prompt = "\n".join(message["content"] for message in messages)
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        try:
            async with httpx.AsyncClient(timeout=settings.get("timeout", 20)) as client:
                response = await client.post(url, json={"contents": [{"parts": [{"text": prompt}]}]})
                response.raise_for_status()
                data = response.json()
        except httpx.TimeoutException as exc:
            raise ProviderError("Provider request timed out") from exc
        except httpx.HTTPStatusError as exc:
            raise ProviderError(f"Provider rejected the request ({exc.response.status_code})") from exc
        return ProviderResponse(content=data["candidates"][0]["content"]["parts"][0]["text"], model=model, provider=self.name, usage={})


class AnthropicAdapter(ProviderAdapter):
    name = "anthropic"

    async def generate_response(self, messages: list[dict[str, str]], model: str, settings: dict[str, Any]) -> ProviderResponse:
        api_key = os.getenv(settings.get("secret_env_var", "ANTHROPIC_API_KEY"))
        if not api_key:
            raise ProviderError("Anthropic is not configured on the server. Set the selected secret environment variable.")
        try:
            async with httpx.AsyncClient(timeout=settings.get("timeout", 20)) as client:
                response = await client.post("https://api.anthropic.com/v1/messages", headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"}, json={"model": model, "max_tokens": 512, "messages": messages})
                response.raise_for_status()
                data = response.json()
        except httpx.TimeoutException as exc:
            raise ProviderError("Provider request timed out") from exc
        except httpx.HTTPStatusError as exc:
            raise ProviderError(f"Provider rejected the request ({exc.response.status_code})") from exc
        return ProviderResponse(content=data["content"][0]["text"], model=model, provider=self.name, usage=data.get("usage", {}))


ADAPTERS: dict[str, ProviderAdapter] = {adapter.name: adapter for adapter in (MockAdapter(), OpenAIAdapter(), OpenAICompatibleAdapter(), GeminiAdapter(), AnthropicAdapter())}


def get_adapter(name: str) -> ProviderAdapter:
    adapter = ADAPTERS.get(name)
    if not adapter:
        raise ProviderError(f"Unsupported provider: {name}")
    return adapter

