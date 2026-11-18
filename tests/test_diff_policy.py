from pathlib import Path

import pytest

from agentblackbox import (
    PolicyError,
    evaluate_expression,
    evaluate_policy,
    load_policy_yaml,
    structured_diff,
)


def test_structured_diff():
    before = {"name": "a", "nested": {"x": 1}, "items": [1, 2]}
    after = {"name": "b", "nested": {"x": 2, "y": 3}, "items": [1, 2, 3]}
    assert structured_diff(before, after) == [
        {"op": "add", "path": "$.items[2]", "value": 3},
        {"op": "replace", "path": "$.name", "before": "a", "after": "b"},
        {"op": "replace", "path": "$.nested.x", "before": 1, "after": 2},
        {"op": "add", "path": "$.nested.y", "value": 3},
    ]


def test_safe_policy_evaluation():
    context = {"risk": 87, "environment": {"name": "production"}, "roles": ["admin"]}
    assert evaluate_expression("risk >= 80 and environment.name in ['prod', 'production']", context)
    assert evaluate_expression("'admin' in roles", context)
    assert (
        evaluate_policy(
            [
                {"when": "risk >= 80", "decision": "deny"},
                {"when": "True", "decision": "allow"},
            ],
            context,
        )
        == "deny"
    )


@pytest.mark.parametrize(
    "expression",
    ["__import__('os').system('echo unsafe')", "open('/tmp/x')", "risk.__class__", "[1][0]"],
)
def test_policy_rejects_unsafe_syntax(expression):
    with pytest.raises(PolicyError):
        evaluate_expression(expression, {"risk": 5})


def test_customer_support_policy_pack_has_six_safe_policies():
    pack = (
        Path(__file__).parents[1]
        / "src"
        / "agentblackbox"
        / "policy_packs"
        / "customer_support_refunds.yaml"
    )
    rules = load_policy_yaml(pack)
    assert len(rules) == 6
    assert evaluate_policy(rules, {"action": "refund", "amount": 600}) == "deny"


@pytest.mark.parametrize(
    "expression",
    [
        "().__class__.__mro__",
        "globals()['x']",
        "lambda: 1",
        "1 if (__import__('os')) else 0",
        "[x for x in (1,2)]",
        "context.__dict__",
    ],
)
def test_policy_sandbox_escape_attempts(expression):
    with pytest.raises(PolicyError):
        evaluate_expression(expression, {"context": {}})
