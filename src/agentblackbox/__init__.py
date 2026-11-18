"""AgentBlackbox core integrity primitives."""

from .canonical import canonical_json, canonical_text, sha256_json
from .diff import structured_diff
from .export import EXPORT_FORMAT, EXPORT_VERSION, export_session_bundle, verify_export_bundle
from .hashchain import (
    GENESIS_HASH,
    ChainEntry,
    ChainVerification,
    create_chain,
    entry_hash,
    verify_chain,
    verify_chain_result,
)
from .merkle import (
    MerkleProof,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    verify_inclusion,
)
from .policy import (
    PolicyError,
    evaluate_expression,
    evaluate_policies,
    evaluate_policy,
    load_policy_yaml,
    validate_policy_pack,
)
from .reports import (
    PdfUnavailableError,
    deterministic_audit_report,
    pdf_report_bytes,
    report_html,
    write_json_audit_report,
    write_pdf_report,
)
from .signing import (
    CRYPTOGRAPHY_AVAILABLE,
    generate_ed25519_keypair,
    sign_bundle,
    sign_payload,
    verify_bundle_signature,
    verify_payload,
)
from .suites import execute_suite, load_suite, suite_json, suite_junit

__all__ = [
    "GENESIS_HASH",
    "ChainEntry",
    "ChainVerification",
    "MerkleProof",
    "PolicyError",
    "canonical_json",
    "canonical_text",
    "create_chain",
    "entry_hash",
    "evaluate_expression",
    "evaluate_policies",
    "evaluate_policy",
    "inclusion_proof",
    "leaf_hash",
    "merkle_root",
    "sha256_json",
    "structured_diff",
    "verify_chain",
    "verify_chain_result",
    "verify_inclusion",
    "load_policy_yaml",
    "validate_policy_pack",
    "EXPORT_FORMAT",
    "EXPORT_VERSION",
    "export_session_bundle",
    "verify_export_bundle",
    "CRYPTOGRAPHY_AVAILABLE",
    "generate_ed25519_keypair",
    "sign_bundle",
    "sign_payload",
    "verify_bundle_signature",
    "verify_payload",
    "PdfUnavailableError",
    "deterministic_audit_report",
    "pdf_report_bytes",
    "report_html",
    "write_json_audit_report",
    "write_pdf_report",
    "execute_suite",
    "load_suite",
    "suite_json",
    "suite_junit",
]
