import re

SYNTHETIC_SECRET = "BAYORA_SYNTHETIC_KEY_9f48a8"
SECRET_PATTERNS = [
    re.compile(r"BAYORA_SYNTHETIC_KEY_[A-Za-z0-9_-]+"),
    re.compile(r"(?i)(api[_ -]?key|password|secret|token)\s*[:=]\s*['\"]?[^\s'\"]+"),
]


def redact(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def contains_sensitive(value: str) -> bool:
    return any(pattern.search(value) for pattern in SECRET_PATTERNS)
