"""Best-effort PII redaction for the bounded service."""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
PHONE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})(?!\d)")
CARD = re.compile(r"(?<!\d)(?:\d[ -]*){13,19}(?!\d)")

IBAN = re.compile(r"(?<![A-Z0-9])[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}(?![A-Z0-9])")
SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}\b")
PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    re.S,
)
DB_URL = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://"
    r"[^\s/@]+:[^\s/@]+@[^\s]+\b",
    re.I,
)
API_KEY = re.compile(
    r"(?i)\b(?:sk|pk|rk|ghp|github_pat|abb)[-_][A-Za-z0-9_-]{12,}\b"
)


def luhn_valid(digits: str) -> bool:
    numbers = [int(char) for char in digits if char.isdigit()]
    if not 13 <= len(numbers) <= 19:
        return False
    checksum = 0
    reverse = numbers[::-1]
    for index, digit in enumerate(reverse):
        if index % 2:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def iban_valid(value: str) -> bool:
    compact = re.sub(r"[^A-Z0-9]", "", value.upper())
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(ord(char) - 55) if char.isalpha() else char for char in rearranged)
    remainder = 0
    for char in numeric:
        remainder = (remainder * 10 + int(char)) % 97
    return remainder == 1


def stable_token(category: str, value: str, pepper: str = "") -> str:
    digest = hmac.new(
        (pepper or "agentblackbox-redaction").encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:12]
    return f"[REDACTED_{category.upper()}:{digest}]"


def redact_text(value: str) -> str:
    value = EMAIL.sub("[REDACTED_EMAIL]", value)
    value = PHONE.sub("[REDACTED_PHONE]", value)
    value = CARD.sub(
        lambda match: "[REDACTED_CARD]" if luhn_valid(match.group(0)) else match.group(0),
        value,
    )
    value = IBAN.sub(
        lambda match: "[REDACTED_IBAN]" if iban_valid(match.group(0)) else match.group(0),
        value,
    )
    value = SSN.sub("[REDACTED_SSN]", value)
    value = JWT.sub("[REDACTED_JWT]", value)
    value = PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", value)
    value = DB_URL.sub("[REDACTED_DB_URL]", value)
    value = API_KEY.sub("[REDACTED_API_KEY]", value)
    return value


def redact_text_stable(value: str, pepper: str = "") -> str:
    patterns = (
        ("card", CARD, lambda item: luhn_valid(item)),
        ("iban", IBAN, iban_valid),
        ("ssn", SSN, lambda item: True),
        ("jwt", JWT, lambda item: True),
        ("private_key", PRIVATE_KEY, lambda item: True),
        ("db_url", DB_URL, lambda item: True),
        ("api_key", API_KEY, lambda item: True),
    )
    value = EMAIL.sub("[REDACTED_EMAIL]", value)
    value = PHONE.sub("[REDACTED_PHONE]", value)
    for category, pattern, predicate in patterns:
        value = pattern.sub(
            lambda match, cat=category, pred=predicate: (
                (
                    f"[REDACTED_{cat.upper()}]"
                    if cat in ("card", "iban", "ssn")
                    else stable_token(cat, match.group(0), pepper)
                )
                if pred(match.group(0))
                else match.group(0)
            ),
            value,
        )
    return value


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        return {str(key): redact(item) for key, item in value.items()}
    return value


def redact_stable(value: Any, pepper: str = "") -> Any:
    if isinstance(value, str):
        return redact_text_stable(value, pepper)
    if isinstance(value, list):
        return [redact_stable(item, pepper) for item in value]
    if isinstance(value, dict):
        return {str(key): redact_stable(item, pepper) for key, item in value.items()}
    return value


def safe_log_context(context: dict[str, Any]) -> dict[str, Any]:
    """Create a canary-safe log context; never include authorization or secret fields."""
    blocked = {
        "authorization",
        "x-api-key",
        "cookie",
        "set-cookie",
        "password",
        "secret",
        "token",
        "raw_key",
        "api_key",
        "private_key",
        "webhook_secret",
        "payload_key",
    }
    safe: dict[str, Any] = {}
    for key, value in context.items():
        normalized = str(key).lower().replace("-", "_")
        if normalized in blocked or any(
            marker in normalized for marker in ("secret", "password", "token")
        ):
            safe[str(key)] = "[REDACTED]"
        else:
            safe[str(key)] = redact_stable(value)
    return safe
