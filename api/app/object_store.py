"""Large-payload object-storage interface and local adapters."""

from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path
from typing import Protocol


class ObjectStoreError(RuntimeError):
    pass


class ObjectStore(Protocol):
    def put(self, key: str, content: bytes) -> dict[str, str]: ...
    def get(self, key: str) -> bytes: ...
    def delete(self, key: str) -> None: ...


class LocalFilesystemObjectStore:
    """Safe, content-addressed local adapter for development and tests."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def put(self, key: str, content: bytes) -> dict[str, str]:
        digest = hashlib.sha256(content).hexdigest()
        with self._lock:
            directory = self.root / digest[:2] / digest
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / "payload"
            if not path.exists():
                tmp = directory / ".payload.tmp"
                tmp.write_bytes(content)
                os.replace(tmp, path)
            elif path.read_bytes() != content:
                raise ObjectStoreError("Content-address collision")
        return {"adapter": "filesystem", "sha256": digest, "key": digest}

    def get(self, key: str) -> bytes:
        if len(key) != 64:
            raise ObjectStoreError("Invalid object key")
        try:
            int(key, 16)
        except ValueError as exc:
            raise ObjectStoreError("Invalid object key") from exc
        path = self.root / key[:2] / key / "payload"
        if not path.is_file():
            raise ObjectStoreError("Object not found")
        return path.read_bytes()

    def delete(self, key: str) -> None:
        path = self.root / key[:2] / key
        if path.is_dir():
            for child in path.iterdir():
                child.unlink()
            path.rmdir()


class MinioCompatibleObjectStore(LocalFilesystemObjectStore):
    """Filesystem-compatible placeholder interface for MinIO-style object APIs.

    This adapter is intentionally local and does not claim S3/MinIO network
    compatibility unless endpoint operations are implemented by the caller.
    """


MinIOObjectStore = MinioCompatibleObjectStore
S3CompatibleObjectStore = MinioCompatibleObjectStore

