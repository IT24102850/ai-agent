"""Fail-safe recording queue and replay guard."""

from __future__ import annotations

import functools
import inspect
import json
import queue
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from contextlib import suppress
from typing import Any


class ReplayGuardError(RuntimeError):
    pass


class ReplayDivergence(ReplayGuardError):
    """Raised or collected when replay cannot faithfully serve a tool call."""


class ReplaySandbox:
    """Replay-only sandbox: it has no network, credential, or process capability."""

    def __init__(self) -> None:
        self.network_allowed = False
        self.credentials_allowed = False
        self.process_allowed = False

    def execute(self, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        raise ReplayGuardError("Replay sandbox denies real tool execution")


class Recorder:
    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str = "local-dev-key",
        *,
        session_name: str | None = None,
        metadata: dict[str, Any] | None = None,
        replay: bool = False,
        recorded_events: list[dict[str, Any]] | None = None,
        collect_replay_divergences: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session_name = session_name
        self.metadata = metadata or {}
        self.session_id: str | None = None
        self.replay = replay
        self.recorded_events = recorded_events or []
        self.collect_replay_divergences = collect_replay_divergences
        self.replay_divergences: list[dict[str, Any]] = []
        self._tool_results: dict[str, Any] = {}
        self._tool_recordings: dict[str, list[dict[str, Any]]] = {}
        self._tool_call_counts: dict[str, int] = {}
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._worker = threading.Thread(target=self._drain, daemon=True)
        self._worker.start()

        if replay:
            for event in self.recorded_events:
                payload = event.get("payload", {})
                data = payload.get("data", payload)
                name = data.get("tool_name") if isinstance(data, dict) else None
                if name:
                    self._tool_results[name] = data.get("result")
                    self._tool_recordings.setdefault(name, []).append(
                        {
                            "args": data.get("args", []),
                            "kwargs": data.get("kwargs", {}),
                            "result": data.get("result"),
                        }
                    )

    def __enter__(self) -> Recorder:
        if not self.replay:
            body = {"name": self.session_name, "metadata": self.metadata}
            response = self._request("POST", "/v1/sessions", body)
            if response and isinstance(response, dict) and response.get("id"):
                self.session_id = response["id"]
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if self.session_id:
            self.log("session.end", {"ended": True})
            self._queue.put(
                {
                    "method": "POST",
                    "path": f"/v1/sessions/{self.session_id}/end",
                    "body": {},
                    "idempotency": None,
                }
            )
        self.close()
        return False

    def close(self) -> None:
        self._queue.put(None)
        self._worker.join(timeout=2)

    def _drain(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            with suppress(Exception):
                self._request(item["method"], item["path"], item["body"], item["idempotency"])

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None,
        idempotency: str | None = None,
    ) -> dict[str, Any] | None:
        try:
            data = json.dumps(body or {}, default=str).encode("utf-8")
            request = urllib.request.Request(
                self.base_url + path,
                data=data,
                method=method,
                headers={"Content-Type": "application/json", "X-API-Key": self.api_key},
            )
            if idempotency:
                request.add_header("Idempotency-Key", idempotency)
            with urllib.request.urlopen(request, timeout=3) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
            return None

    def _enqueue(
        self, event_type: str, payload: dict[str, Any], idempotency: str | None = None
    ) -> None:
        if not self.session_id or self.replay:
            return
        import uuid

        idempotency = idempotency or str(uuid.uuid4())
        self._queue.put(
            {
                "method": "POST",
                "path": f"/v1/sessions/{self.session_id}/events",
                "body": {"event_type": event_type, "payload": payload},
                "idempotency": idempotency,
            }
        )

    def log_llm_call(
        self, model: str, request: dict[str, Any], response: Any, **metadata: Any
    ) -> None:
        self._enqueue(
            "llm.call",
            {"model": model, "request": request, "response": response, "metadata": metadata},
        )

    def log_decision(self, decision: str, rationale: str = "", **metadata: Any) -> None:
        self._enqueue("decision", {"decision": decision, "rationale": rationale, **metadata})

    def log_human_approval(self, approver: str, approved: bool, **metadata: Any) -> None:
        self._enqueue("human.approval", {"approver": approver, "approved": approved, **metadata})

    def log(self, event_type: str, payload: dict[str, Any], **metadata: Any) -> None:
        self._enqueue(event_type, {**payload, **metadata})

    def call_tool(
        self, name: str, function: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> Any:
        if self.replay:
            recordings = self._tool_recordings.get(name)
            index = self._tool_call_counts.get(name, 0)
            self._tool_call_counts[name] = index + 1
            if not recordings:
                return self._record_or_raise(
                    name,
                    "missing_recording",
                    f"Recorded tool result unavailable for '{name}'; real tool was not executed",
                )
            recording = recordings[min(index, len(recordings) - 1)]
            if list(args) != list(recording["args"]) or dict(kwargs) != dict(recording["kwargs"]):
                return self._record_or_raise(
                    name,
                    "arguments_mismatch",
                    f"Replay arguments differ for '{name}'",
                    expected={"args": recording["args"], "kwargs": recording["kwargs"]},
                    actual={"args": list(args), "kwargs": kwargs},
                )
            return recording["result"]
        try:
            result = function(*args, **kwargs)
            self._enqueue(
                "tool.call", {"tool_name": name, "args": args, "kwargs": kwargs, "result": result}
            )
            return result
        except Exception as exc:
            self._enqueue("tool.error", {"tool_name": name, "error": repr(exc)})
            raise

    def _record_or_raise(
        self,
        name: str,
        kind: str,
        message: str,
        **details: Any,
    ) -> Any:
        divergence = {"tool": name, "kind": kind, "message": message, **details}
        if self.collect_replay_divergences:
            self.replay_divergences.append(divergence)
            return None
        raise ReplayDivergence(message)


def tool(*args: Any, recorder: Recorder | None = None, name: str | None = None) -> Any:
    """Decorator for sync or async tools."""
    function: Callable[..., Any] | None = args[0] if len(args) == 1 and callable(args[0]) else None

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = name or fn.__name__

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*fn_args: Any, **fn_kwargs: Any) -> Any:
                rec = recorder
                if rec is None:
                    rec = getattr(fn_args[0], "_agentblackbox_recorder", None) if fn_args else None
                if rec is None:
                    return await fn(*fn_args, **fn_kwargs)
                if rec.replay:
                    return rec.call_tool(tool_name, fn, fn_args, fn_kwargs)
                try:
                    result = await fn(*fn_args, **fn_kwargs)
                    rec._enqueue(
                        "tool.call",
                        {
                            "tool_name": tool_name,
                            "args": fn_args,
                            "kwargs": fn_kwargs,
                            "result": result,
                        },
                    )
                    return result
                except Exception as exc:
                    rec._enqueue("tool.error", {"tool_name": tool_name, "error": repr(exc)})
                    raise

            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*fn_args: Any, **fn_kwargs: Any) -> Any:
            rec = recorder
            if rec is None:
                rec = getattr(fn_args[0], "_agentblackbox_recorder", None) if fn_args else None
            if rec is None:
                return fn(*fn_args, **fn_kwargs)
            return rec.call_tool(tool_name, fn, fn_args, fn_kwargs)

        return sync_wrapper

    return decorate if function is None else decorate(function)
