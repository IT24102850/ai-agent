"""Small stdlib-only local load test for the AgentBlackbox API."""

from __future__ import annotations

import argparse
import statistics
import time
import urllib.error
import urllib.request


def probe(url: str, timeout: float) -> float:
    started = time.monotonic()
    with urllib.request.urlopen(url, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"{url} returned HTTP {response.status}")
    return (time.monotonic() - started) * 1000


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()

    latencies: list[float] = []
    failures = 0
    started = time.monotonic()
    for _ in range(args.requests):
        try:
            latencies.append(probe(f"{args.base_url.rstrip('/')}/health", args.timeout))
        except (urllib.error.URLError, TimeoutError, RuntimeError):
            failures += 1
    elapsed = time.monotonic() - started

    print(f"requests={args.requests} failures={failures} duration_s={elapsed:.3f}")
    if latencies:
        print(
            "latency_ms "
            f"min={min(latencies):.1f} "
            f"mean={statistics.fmean(latencies):.1f} "
            f"p95={sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)]:.1f} "
            f"max={max(latencies):.1f}"
        )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
