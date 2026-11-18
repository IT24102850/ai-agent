"""Restricted policy-expression evaluation.

Expressions are parsed into Python's AST and evaluated with an allow-list.
There is deliberately no Python ``eval`` call and no attribute/function execution.
"""

from __future__ import annotations

import ast
import operator
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - fail clearly when optional runtime is missing
    yaml = None


class PolicyError(ValueError):
    pass


REQUIRED_POLICY_FIELDS = {"id", "when", "decision"}


def validate_policy_pack(value: Any) -> list[dict[str, Any]]:
    """Validate and return a policy-pack mapping/list."""
    if isinstance(value, dict):
        value = value.get("policies")
    if not isinstance(value, list):
        raise PolicyError("policy pack must contain a 'policies' list")
    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    for index, rule in enumerate(value):
        if not isinstance(rule, dict):
            raise PolicyError(f"policy at index {index} must be an object")
        missing = REQUIRED_POLICY_FIELDS - set(rule)
        if missing:
            raise PolicyError(
                f"policy at index {index} missing required fields: " + ", ".join(sorted(missing))
            )
        policy_id = rule["id"]
        when = rule["when"]
        if not isinstance(policy_id, str) or not policy_id:
            raise PolicyError(f"policy at index {index} needs a non-empty string id")
        if policy_id in seen:
            raise PolicyError(f"duplicate policy id: {policy_id}")
        if not isinstance(when, str):
            raise PolicyError(f"policy {policy_id} needs a string 'when' expression")
        evaluate_expression(when, {})
        severity = rule.get("severity", "medium")
        if not isinstance(severity, str):
            raise PolicyError(f"policy {policy_id} severity must be a string")
        seen.add(policy_id)
        validated.append(rule)
    return validated


def load_policy_yaml(source: str | Path) -> list[dict[str, Any]]:
    """Load a policy pack from YAML using only PyYAML's safe loader."""
    if yaml is None:
        raise PolicyError("PyYAML is required to load policy YAML")
    path = Path(source)
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = yaml.safe_load(stream)
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"unable to load policy pack: {exc}") from exc
    return validate_policy_pack(value)


def evaluate_policies(
    rules: list[dict[str, Any]],
    context: dict[str, Any],
) -> list[dict[str, Any]]:
    """Evaluate all matching policies and return violation-style records."""
    violations: list[dict[str, Any]] = []
    for rule in validate_policy_pack({"policies": rules}):
        if evaluate_expression(rule["when"], context):
            violations.append(
                {
                    "policy_id": rule["id"],
                    "decision": rule["decision"],
                    "severity": rule.get("severity", "medium"),
                    "description": rule.get("description", ""),
                }
            )
    return violations


_BINARY = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Mod: operator.mod,
}
_COMPARISON = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda left, right: left in right,
    ast.NotIn: lambda left, right: left not in right,
}
_UNARY = {ast.Not: operator.not_, ast.USub: operator.neg, ast.UAdd: operator.pos}
_MISSING = object()


def _resolve(node: ast.AST, context: dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (dict, list, set)):
            raise PolicyError("only scalar and tuple/list literals are allowed")
        return node.value
    if isinstance(node, ast.Name):
        return context.get(node.id, _MISSING)
    if isinstance(node, ast.Attribute):
        if node.attr.startswith("_"):
            raise PolicyError("private and dunder attributes are forbidden")
        current = _resolve(node.value, context)
        if current is _MISSING or not isinstance(current, dict):
            return _MISSING
        return current.get(node.attr, _MISSING)
    if isinstance(node, ast.List):
        return [_resolve(item, context) for item in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_resolve(item, context) for item in node.elts)
    if isinstance(node, ast.Set):
        return {_resolve(item, context) for item in node.elts}
    raise PolicyError(f"unsupported expression element: {type(node).__name__}")


def evaluate_expression(expression: str, context: dict[str, Any]) -> Any:
    if not isinstance(expression, str) or len(expression) > 4000:
        raise PolicyError("expression must be a string of at most 4000 characters")
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise PolicyError("invalid policy expression") from exc
    return _evaluate(tree.body, context, depth=0)


def _evaluate(node: ast.AST, context: dict[str, Any], depth: int) -> Any:
    if depth > 32:
        raise PolicyError("expression nesting exceeds maximum depth")
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            result = True
            for value in node.values:
                result = bool(_evaluate(value, context, depth + 1))
                if not result:
                    break
            return result
        if isinstance(node.op, ast.Or):
            result = False
            for value in node.values:
                result = bool(_evaluate(value, context, depth + 1))
                if result:
                    break
            return result
        raise PolicyError("unsupported boolean operator")
    if isinstance(node, ast.UnaryOp):
        operation = _UNARY.get(type(node.op))
        if operation is None:
            raise PolicyError("unsupported unary operator")
        value = _evaluate(node.operand, context, depth + 1)
        if value is _MISSING:
            return False
        return operation(value)
    if isinstance(node, ast.BinOp):
        operation = _BINARY.get(type(node.op))
        if operation is None:
            raise PolicyError("unsupported binary operator")
        left = _evaluate(node.left, context, depth + 1)
        right = _evaluate(node.right, context, depth + 1)
        if left is _MISSING or right is _MISSING:
            return _MISSING
        return operation(left, right)
    if isinstance(node, ast.Compare):
        left = _evaluate(node.left, context, depth + 1)
        if left is _MISSING:
            return False
        for operation_node, comparator in zip(node.ops, node.comparators, strict=False):
            operation = _COMPARISON.get(type(operation_node))
            if operation is None:
                raise PolicyError("unsupported comparison operator")
            right = _evaluate(comparator, context, depth + 1)
            if right is _MISSING:
                return False
            try:
                if not operation(left, right):
                    return False
            except (TypeError, ValueError):
                return False
            left = right
        return True
    if isinstance(node, ast.IfExp):
        branch = node.body if _evaluate(node.test, context, depth + 1) else node.orelse
        return _evaluate(branch, context, depth + 1)
    if isinstance(node, (ast.Name, ast.Attribute)):
        value = _resolve(node, context)
        return False if value is _MISSING else value
    if isinstance(node, (ast.Constant, ast.List, ast.Tuple, ast.Set)):
        return _resolve(node, context)
    raise PolicyError(f"unsupported expression element: {type(node).__name__}")


def evaluate_policy(
    rules: list[dict[str, Any]],
    context: dict[str, Any],
    default: Any = None,
) -> Any:
    """Return the first matching rule's decision, or default."""
    for rule in rules:
        if not isinstance(rule, dict):
            raise PolicyError("each rule must be an object")
        expression = rule.get("when")
        if not isinstance(expression, str):
            raise PolicyError("each rule needs a string 'when' expression")
        if evaluate_expression(expression, context):
            if "decision" not in rule:
                raise PolicyError("matching rule needs a 'decision'")
            return rule["decision"]
    return default
