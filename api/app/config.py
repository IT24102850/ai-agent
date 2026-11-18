"""Environment-backed service configuration."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    api_key: str = "local-dev-key"
    database_url: str = "sqlite:///./agentblackbox.db"
    environment: str = "development"
    api_key_pepper: str = "local-dev-pepper-change-me"
    payload_key: str | None = None
    kms_key_id: str | None = None
    large_payload_threshold: int = 1024 * 1024
    object_store_root: str = "./agentblackbox-objects"
    candidate_sandbox_enabled: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            api_key=os.getenv("AGENTBLACKBOX_API_KEY", "local-dev-key"),
            database_url=os.getenv("AGENTBLACKBOX_DATABASE_URL", "sqlite:///./agentblackbox.db"),
            environment=os.getenv("ENV", "development"),
            api_key_pepper=os.getenv("AGENTBLACKBOX_API_KEY_PEPPER", "local-dev-pepper-change-me"),
            payload_key=os.getenv("AGENTBLACKBOX_PAYLOAD_KEY"),
            kms_key_id=os.getenv("AGENTBLACKBOX_KMS_KEY_ID"),
            large_payload_threshold=int(
                os.getenv("AGENTBLACKBOX_LARGE_PAYLOAD_THRESHOLD", str(1024 * 1024))
            ),
            object_store_root=os.getenv(
                "AGENTBLACKBOX_OBJECT_STORE_ROOT", "./agentblackbox-objects"
            ),
            candidate_sandbox_enabled=(
                os.getenv("AGENTBLACKBOX_CANDIDATE_SANDBOX", "true").lower() == "true"
            ),
        )

    def validate(self) -> None:
        if self.environment.lower() == "production" and self.api_key == "local-dev-key":
            raise ValueError("AGENTBLACKBOX_API_KEY must be configured in production")
        if self.environment.lower() == "production" and self.api_key_pepper.startswith("local-dev"):
            raise ValueError("AGENTBLACKBOX_API_KEY_PEPPER must be configured in production")
        if self.environment.lower() == "production" and not self.kms_key_id:
            raise ValueError("AGENTBLACKBOX_KMS_KEY_ID must be configured in production")
