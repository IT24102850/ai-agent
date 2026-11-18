import argparse
import json
import sys
from pathlib import Path

from . import (
    create_chain,
    load_policy_yaml,
    merkle_root,
    verify_export_bundle,
)
from .reports import write_json_audit_report
from .signing import verify_bundle_signature
from .suites import execute_suite, load_suite, suite_json, suite_junit


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m agentblackbox")
    subparsers = parser.add_subparsers(dest="command")

    verify = subparsers.add_parser("verify", help="Verify an exported JSON bundle")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--public-key", default=None, help="Hex or PEM Ed25519 public key")
    verify.add_argument("--report", type=Path, default=None, help="Write a JSON audit report")

    suite = subparsers.add_parser("suite", help="Run an editable regression suite")
    suite.add_argument("action", choices=["run"])
    suite.add_argument("file", type=Path)
    suite.add_argument("--format", choices=["json", "junit"], default="json")
    suite.add_argument("--output", type=Path, default=None)

    subparsers.add_parser("demo", help="Run the existing bounded demo")
    parser.add_argument("--list-policies", action="store_true")
    parser.add_argument("--policy-pack", default=None)
    args = parser.parse_args()

    if args.command == "verify":
        try:
            bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read bundle: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
        integrity = verify_export_bundle(bundle)
        signature = verify_bundle_signature(bundle, args.public_key)
        valid = integrity["valid"] and (not signature["signed"] or signature["valid"] is True)
        result = {"valid": valid, "integrity": integrity, "signature": signature}
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        if args.report:
            write_json_audit_report(bundle, args.report, args.public_key)
        raise SystemExit(0 if valid else 1)

    if args.command == "suite":
        try:
            report = execute_suite(load_suite(args.file))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read suite: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
        output = suite_json(report) if args.format == "json" else suite_junit(report)
        if args.output:
            suffix = "\n" if args.format == "junit" else ""
            args.output.write_text(output + suffix, encoding="utf-8")
        print(output)
        raise SystemExit(0 if report["status"] in ("passed", "changed") else 1)

    if args.list_policies:
        default_pack = Path(__file__).parent / "policy_packs" / "customer_support_refunds.yaml"
        rules = load_policy_yaml(args.policy_pack or default_pack)
        print(json.dumps(rules, indent=2))
        return

    chain = create_chain([{"event": "started"}, {"event": "completed"}])
    print(f"chain_head={chain[-1].hash}")
    print(f"merkle_root={merkle_root([chain[0].to_dict(), chain[1].to_dict()])}")


if __name__ == "__main__":
    main()
