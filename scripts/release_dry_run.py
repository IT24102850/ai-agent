"""Validate release inputs locally; never authenticates to or deploys to AWS."""

from __future__ import annotations

import shutil
import subprocess
import sys


def run(command: list[str]) -> bool:
    print("+", " ".join(command))
    return subprocess.run(command).returncode == 0


def main() -> int:
    checks: list[bool] = []
    if shutil.which("docker") is None:
        print("ERROR: Docker is required for release dry run")
        return 1
    checks.append(run(["docker", "compose", "config", "--quiet"]))
    checks.append(run(["docker", "build", "-f", "Dockerfile.api", "-t", "agentblackbox-api:local", "."]))
    checks.append(run(["docker", "build", "-f", "web/Dockerfile", "-t", "agentblackbox-web:local", "./web"]))
    if shutil.which("terraform"):
        checks.append(run(["terraform", "-chdir=infra", "fmt", "-check", "-recursive"]))
    print("DRY RUN COMPLETE: no AWS credentials were used and no resources were changed.")
    return 0 if all(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
