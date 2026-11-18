"""Signed webhook delivery and replay-window verification."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import socket
import time
from urllib.parse import urlparse

import httpx


class WebhookValidationError(ValueError):
    pass


def _is_blocked_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
        or ip.is_multicast
        or getattr(ip, "is_global", True) is False
    )


def validate_webhook_url(url: str) -> str:
    """Validate an HTTPS webhook endpoint and resolve every address before use."""
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise WebhookValidationError("webhook URL must use https")
    if not parsed.hostname or parsed.username or parsed.password:
        raise WebhookValidationError("webhook URL must contain a safe hostname")
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise WebhookValidationError("invalid webhook port")
    if parsed.fragment:
        raise WebhookValidationError("webhook URL must not contain a fragment")

    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise WebhookValidationError("webhook hostname could not be resolved") from exc
    if not addresses:
        raise WebhookValidationError("webhook hostname resolved to no addresses")
    for address in {item[4][0] for item in addresses}:
        if _is_blocked_ip(address):
            raise WebhookValidationError("webhook URL resolves to a private or unsafe address")
    return url


def sign_payload(secret: str, timestamp: int, body: bytes) -> str:
    if not secret:
        raise ValueError("webhook signing secret must not be empty")
    signed = f"{timestamp}.".encode("ascii") + body
    digest = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_signature(
    secret: str,
    timestamp: str,
    body: bytes,
    signature: str,
    *,
    replay_window_seconds: int = 300,
    now: int | None = None,
) -> bool:
    try:
        timestamp_int = int(timestamp)
    except (TypeError, ValueError):
        return False
    now = int(time.time()) if now is None else now
    if abs(now - timestamp_int) > replay_window_seconds:
        return False
    expected = sign_payload(secret, timestamp_int, body)
    return hmac.compare_digest(expected, signature)


class SignedWebhookSender:
    def __init__(
        self,
        secret: str,
        *,
        timeout_seconds: float = 10.0,
        replay_window_seconds: int = 300,
    ) -> None:
        if not secret:
            raise ValueError("webhook signing secret must not be empty")
        self.secret = secret
        self.timeout_seconds = timeout_seconds
        self.replay_window_seconds = replay_window_seconds

    async def send_async(self, url: str, body: bytes) -> httpx.Response:
        validate_webhook_url(url)
        timestamp = int(time.time())
        signature = sign_payload(self.secret, timestamp, body)
        headers = {
            "Content-Type": "application/json",
            "X-AgentBlackbox-Timestamp": str(timestamp),
            "X-AgentBlackbox-Signature": signature,
            "X-AgentBlackbox-Replay-Window": str(self.replay_window_seconds),
        }
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds,
            follow_redirects=False,
        ) as client:
            response = await client.post(url, content=body, headers=headers)
        if 300 <= response.status_code < 400:
            raise WebhookValidationError("webhook redirects are forbidden")
        return response
