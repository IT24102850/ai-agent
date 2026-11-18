"""Canonical JSON primitives."""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from typing import Any

MAX_SAFE_INTEGER = 2**53


def canonical_json(value: Any) -> bytes:
    """Serialize JSON using sorted keys, NFC strings, and stable numbers.

    Integers outside JavaScript's safe range are represented as JSON strings.
    Floats use Python's shortest round-trippable representation and must be
    finite. This deliberately rejects lone UTF-16 surrogates.
    """
    normalized = _normalize(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_text(value: Any) -> str:
    return canonical_json(value).decode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def validate_json(value: Any, depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("JSON nesting exceeds maximum depth of 64")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ValueError("JSON strings must not contain lone surrogates")
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON values must not contain NaN or infinity")
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            validate_json(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON object keys must be strings")
            validate_json(item, depth + 1)
        return
    raise TypeError(f"unsupported JSON value type: {type(value).__name__}")


def _normalize(value: Any, depth: int = 0) -> Any:
    validate_json(value, depth)
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > MAX_SAFE_INTEGER:
        return str(value)
    if isinstance(value, tuple):
        return [_normalize(item, depth + 1) for item in value]
    if isinstance(value, list):
        return [_normalize(item, depth + 1) for item in value]
    if isinstance(value, dict):
        return {_normalize(key): _normalize(item, depth + 1) for key, item in value.items()}
    return value
