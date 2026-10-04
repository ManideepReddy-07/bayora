from typing import Literal
from pydantic import BaseModel, Field, HttpUrl, field_validator


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=12000)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=200)


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=40)
    session_id: str | None = Field(default=None, max_length=80)
    defense_enabled: bool = True
    provider_id: str | None = None
    weaknesses: list[Literal["prompt_injection", "response_redaction", "authorization"]] = []


class ProviderCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    provider: Literal["mock", "openai", "gemini", "anthropic", "openai_compatible"]
    model: str = Field(min_length=1, max_length=120)
    base_url: str | None = Field(default=None, max_length=500)
    secret_env_var: str | None = Field(default=None, max_length=100, pattern=r"^[A-Z][A-Z0-9_]*$")
    active: bool = False


class ProviderUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    model: str | None = Field(default=None, min_length=1, max_length=120)
    base_url: str | None = Field(default=None, max_length=500)
    secret_env_var: str | None = Field(default=None, max_length=100, pattern=r"^[A-Z][A-Z0-9_]*$")
    active: bool | None = None


class TargetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    target_type: Literal["demo_chatbot", "authorized_api"] = "demo_chatbot"
    base_url: str | None = Field(default=None, max_length=500)
    authorized: bool


class RunCreate(BaseModel):
    target_id: str
    suite_id: str
    defenses_enabled: bool = False
    authorization_confirmed: bool
    categories: list[str] = []


class PolicyUpdate(BaseModel):
    enabled: bool


class PatchCreate(BaseModel):
    finding_id: str | None = None
    title: str = Field(min_length=3, max_length=240)
    diff: str = Field(min_length=10, max_length=30000)


class PatchApproval(BaseModel):
    approval_note: str = Field(default="", max_length=1000)
