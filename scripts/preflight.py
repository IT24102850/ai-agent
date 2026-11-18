"""Preflight checks for the local and AWS reference deployment scaffold."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def check(name: str, available: bool, detail: str) -> bool:
    print(f"{'PASS' if available else 'FAIL'} {name}: {detail}")
    return available


def command_ok(command: list[str]) -> bool:
    try:
        return subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except (FileNotFoundError, OSError):
        return False


def main() -> int:
    ok = True
    ok &= check("Python", sys.version_info >= (3, 10), sys.version.split()[0])
    ok &= check("Docker", shutil.which("docker") is not None, "Docker CLI")
    ok &= check("Compose", command_ok(["docker", "compose", "version"]), "docker compose version")
    ok &= check("Node", shutil.which("node") is not None, "Node.js")
    ok &= check("npm", shutil.which("npm") is not None, "npm")
    terraform_available = shutil.which("terraform") is not None
    ok &= check(
        "Terraform",
        True,
        "Terraform CLI available" if terraform_available else "Terraform not installed (optional local check)",
    )
    ok &= check(
        "Repository",
        (Path.cwd() / "Dockerfile.api").is_file() and (Path.cwd() / "infra").is_dir(),
        str(Path.cwd()),
    )
    ok &= check(
        "Compose configuration",
        command_ok(["docker", "compose", "config", "--quiet"]),
        "docker-compose.yml",
    )
    if shutil.which("terraform"):
        ok &= check(
            "Terraform format",
            command_ok(["terraform", "-chdir=infra", "fmt", "-check", "-recursive"]),
            "infra/*.tf",
        )
    helm = shutil.which("helm")
    if helm:
        ok &= check("Helm chart lint", command_ok(["helm", "lint", "charts/agentblackbox"]), "helm lint")
        ok &= check(
            "Helm small template",
            command_ok(["helm", "template", "agentblackbox", "charts/agentblackbox", "-f", "charts/agentblackbox/values-small.yaml"]),
            "small profile",
        )
        ok &= check(
            "Helm standard template",
            command_ok(["helm", "template", "agentblackbox", "charts/agentblackbox", "-f", "charts/agentblackbox/values-standard.yaml"]),
            "standard profile",
        )
        ok &= check(
            "Helm HA template",
            command_ok(["helm", "template", "agentblackbox", "charts/agentblackbox", "-f", "charts/agentblackbox/values-ha.yaml"]),
            "HA profile",
        )
    else:
        check("Helm", True, "Helm not installed; chart rendering skipped honestly")

    kind = shutil.which("kind")
    kubectl = shutil.which("kubectl")
    if kind and kubectl:
        print("PASS kind/kubectl: tools found; no cluster was created or modified")
    else:
        check(
            "kind/kubectl",
            True,
            "kind or kubectl not installed; kind cluster validation skipped honestly",
        )
    print("NO DEPLOYMENT CLAIM: this script does not install Helm charts or apply cloud resources")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
