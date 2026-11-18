"""Check whether local AgentBlackbox prerequisites are available."""

from __future__ import annotations

import shutil
import sys
import subprocess


def check(name: str, available: bool, detail: str) -> bool:
    print(f"{'PASS' if available else 'FAIL'} {name}: {detail}")
    return available


def main() -> int:
    ok = True
    ok &= check("Python", sys.version_info >= (3, 10), sys.version.split()[0])
    ok &= check("docker", shutil.which("docker") is not None, "Docker CLI")
    ok &= check("compose", shutil.which("docker") is not None, "docker compose is checked separately")
    ok &= check("node", shutil.which("node") is not None, "Node.js")
    ok &= check("npm", shutil.which("npm") is not None, "npm")
    ok &= check(
        "terraform",
        True,
        "Terraform CLI available"
        if shutil.which("terraform") is not None
        else "Terraform not installed (optional for local-only work)",
    )
    ok &= check(
        "compose config",
        shutil.which("docker") is not None
        and subprocess.run(
            ["docker", "compose", "config", "--quiet"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0,
        "docker-compose.yml",
    )
    helm = shutil.which("helm")
    kind = shutil.which("kind")
    kubectl = shutil.which("kubectl")
    ok &= check("helm", True, "Helm CLI available" if helm else "Helm not installed (optional; chart checks skipped)")
    if helm:
        ok &= check(
            "Helm chart",
            subprocess.run(["helm", "lint", "charts/agentblackbox"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0,
            "charts/agentblackbox",
        )
    ok &= check("kind", True, "kind CLI available" if kind else "kind not installed (optional; cluster skipped)")
    ok &= check("kubectl", True, "kubectl CLI available" if kubectl else "kubectl not installed (optional; cluster skipped)")
    if kind and kubectl:
        print("INFO: kind/cluster apply is not automatic; use scripts/preflight.py for local validation")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
