import threading
import time
from collections import deque
from dataclasses import dataclass
from sqlalchemy.orm import Session
from .redaction import contains_sensitive, redact
from ..models import Alert, DefenseEvent, DefensePolicy
from ..config import get_settings

_rate_limit_lock = threading.Lock()
_request_windows: dict[str, deque[float]] = {}


@dataclass
class DefenseDecision:
    blocked: bool
    reason: str | None = None
    policy_key: str | None = None


def enabled_policies(db: Session) -> set[str]:
    return {policy.key for policy in db.query(DefensePolicy).filter(DefensePolicy.enabled.is_(True)).all()}


def inspect_request(db: Session, prompt: str, session_id: str | None = None, force_enabled: bool = True) -> DefenseDecision:
    policies = enabled_policies(db) if force_enabled else set()
    normalized = prompt.lower()
    suspicious = any(marker in normalized for marker in ("ignore previous", "reveal your prompt", "system instruction", "bypass safety"))
    extraction = any(marker in normalized for marker in ("show secret", "api key", "credential", "confidential record"))
    if "rate_limit" in policies and _is_rate_limited(session_id or "anonymous"):
        _event(db, "rate_limit", "rate-limit", "medium", session_id, "Request rate exceeded the configured gateway window", "blocked")
        _alert(db, "medium", "rate-limit", "The gateway limited a request burst from one synthetic session.")
        return DefenseDecision(True, "Request rate limit reached. Wait briefly before retrying.", "rate_limit")
    if "prompt_injection" in policies and suspicious:
        _event(db, "prompt_injection", "prompt-injection", "high", session_id, "Prompt pattern matched instruction-override heuristic", "blocked")
        _alert(db, "high", "prompt-injection", "A request attempted to override test-only system instructions.")
        return DefenseDecision(True, "Prompt-injection attempt blocked by configured policy.", "prompt_injection")
    if "sensitive_input" in policies and extraction:
        _event(db, "sensitive_input", "data-extraction", "high", session_id, "Prompt pattern matched synthetic-data extraction heuristic", "blocked")
        _alert(db, "high", "sensitive-data", "A request attempted to extract protected synthetic data.")
        return DefenseDecision(True, "Sensitive-data extraction request blocked by configured policy.", "sensitive_input")
    return DefenseDecision(False)


def _is_rate_limited(session_key: str) -> bool:
    settings = get_settings()
    now = time.monotonic()
    with _rate_limit_lock:
        window = _request_windows.setdefault(session_key[:80], deque())
        cutoff = now - settings.rate_limit_window_seconds
        while window and window[0] <= cutoff:
            window.popleft()
        if len(window) >= settings.rate_limit_requests:
            return True
        window.append(now)
        return False


def inspect_response(db: Session, response: str, session_id: str | None = None, force_enabled: bool = True) -> tuple[str, bool]:
    policies = enabled_policies(db) if force_enabled else set()
    if "response_redaction" in policies and contains_sensitive(response):
        _event(db, "response_redaction", "response-redaction", "critical", session_id, "Synthetic credential was redacted before client delivery", "redacted")
        _alert(db, "critical", "response-redaction", "The gateway redacted synthetic sensitive material from a model response.")
        return redact(response), True
    return response, False


def _event(db: Session, policy_key: str, event_type: str, severity: str, session_id: str | None, detail: str, action: str) -> None:
    db.add(DefenseEvent(policy_key=policy_key, event_type=event_type, severity=severity, session_id=session_id, detail=detail, action=action))


def _alert(db: Session, severity: str, category: str, explanation: str) -> None:
    db.add(Alert(severity=severity, category=category, explanation=explanation, detection_method="deterministic gateway policy", recommended_response="Review the request context and retain the defense policy enabled."))
