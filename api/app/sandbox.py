"""Explicit replay and candidate execution sandbox."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


class SandboxDeniedError(RuntimeError):
    pass


@dataclass(frozen=True)
class SandboxPolicy:
    network_allowed: bool = False
    credentials_allowed: bool = False
    process_allowed: bool = False


class Sandbox:
    def __init__(self, policy: SandboxPolicy | None = None) -> None:
        self.policy = policy or SandboxPolicy()

    def execute(self, tool: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        raise SandboxDeniedError("Candidate and replay execution denies real tools")

    def open_network(self, *args: Any, **kwargs: Any) -> Any:
        raise SandboxDeniedError("Sandbox denies network access")

    def get_credentials(self, *args: Any, **kwargs: Any) -> Any:
        raise SandboxDeniedError("Sandbox denies credentials")

    def execute_process(self, *args: Any, **kwargs: Any) -> Any:
        raise SandboxDeniedError("Sandbox denies process execution")


# A descriptive alias for code that needs to be explicit about replay behavior.
ReplaySandbox = Sandbox
